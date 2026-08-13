package commands

// `vey ssh-cert` — provision or refresh the operator's SSH credential
// (specs/005-ssh-gateway/contracts/cli-commands.md `vey ssh-cert`,
// contracts/rest-api.md GET /api/ssh/host-key + POST /api/ssh/certificates,
// data-model.md "Stored SSH material").
//
// The command is deliberately small and ordered:
//
//	refuse api_token mode → reuse-or-generate the keypair → fetch the host key
//	→ post the public key → persist everything → report the expiry
//
// The refusal comes first, before any network call: SSH access to fleet
// servers is an interactive-operator capability, and a script holding an API
// token must not even be able to ask (FR-002/SC-004). The hub enforces the
// same rule with `interactiveOnly`, so this is the client half of a
// two-sided guarantee, not the guarantee itself.
//
// The private key never leaves this process except into the credential store.
// It is not printed, not logged, and not quoted in any error — errors from
// key parsing and marshaling are replaced with fixed text for exactly that
// reason.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/wyiu/veyport/cli/internal/api"
	"github.com/wyiu/veyport/cli/internal/auth"
	"github.com/wyiu/veyport/cli/internal/cmdutil"
	"golang.org/x/crypto/ssh"
)

const (
	// sshHostKeyPath is the gateway's identity, fetched so the fingerprint
	// can be cached for host pinning (FR-013).
	sshHostKeyPath = "/api/ssh/host-key"
	// sshCertPath is the interactive-only issuance endpoint.
	sshCertPath = "/api/ssh/certificates"
)

// sshHostKeyResponse is GET /api/ssh/host-key's body.
type sshHostKeyResponse struct {
	Fingerprint string `json:"fingerprint"`
	PublicKey   string `json:"public_key"`
	Port        int    `json:"port"`
}

// sshCertRequest is POST /api/ssh/certificates' body. The principal is not
// negotiable and is therefore not sent: the hub derives it from the
// authenticated session.
type sshCertRequest struct {
	PublicKey string `json:"public_key"`
}

// sshCertResponse is POST /api/ssh/certificates' body.
type sshCertResponse struct {
	Certificate        string `json:"certificate"`
	Principal          string `json:"principal"`
	ExpiresAt          string `json:"expires_at"`
	HostKeyFingerprint string `json:"host_key_fingerprint"`
	GatewayPort        int    `json:"gateway_port"`
}

// sshCertPayload is the --json shape for `vey ssh-cert`
// (contracts/cli-commands.md: "{principal, expires_at,
// host_key_fingerprint, gateway_port}"). It carries no key material: the
// certificate itself is public but useless without the key, and the key is
// never rendered.
type sshCertPayload struct {
	Principal          string `json:"principal"`
	ExpiresAt          string `json:"expires_at"`
	HostKeyFingerprint string `json:"host_key_fingerprint"`
	GatewayPort        int    `json:"gateway_port"`
}

// sshKeypair is one ed25519 client key in the two forms this command needs:
// the openssh-form private key to persist, and the authorized_keys-form
// public key to send.
type sshKeypair struct {
	// privatePEM is secret material. It is only ever handed to the store.
	privatePEM string
	// authorized is the public half, safe to send and to print.
	authorized string
}

// RunSSHCert implements `vey ssh-cert`.
func RunSSHCert(ctx *Context) int {
	fail := func(err error) int {
		ctx.Printer.Error(err)
		return cmdutil.Code(err)
	}

	if err := parseNoArgs(ctx.Args); err != nil {
		return fail(err)
	}

	hubURL, err := ctx.RequireHub()
	if err != nil {
		return fail(err)
	}
	store, actx, err := newAuthContext(ctx, hubURL)
	if err != nil {
		return fail(err)
	}
	// Before anything reaches the network: SSH certificates are issued to
	// interactive sessions only.
	if actx.Mode() == auth.ModeAPIToken {
		return fail(cmdutil.NewAuthError(fmt.Errorf(
			"vey ssh-cert requires an interactive session, but the active credential for %s is an API token; run: vey login --hub %s",
			hubURL, hubURL)))
	}

	key, err := loadOrGenerateSSHKey(ctx, store, hubURL)
	if err != nil {
		return fail(err)
	}

	bg := context.Background()
	host, err := fetchSSHHostKey(bg, actx)
	if err != nil {
		return fail(err)
	}
	cert, err := issueSSHCertificate(bg, actx, hubURL, key.authorized)
	if err != nil {
		return fail(err)
	}

	expiry, err := time.Parse(time.RFC3339, strings.TrimSpace(cert.ExpiresAt))
	if err != nil {
		// Nothing is persisted: a certificate whose lifetime vey cannot check
		// would defeat `vey ssh`'s up-front expiry check (FR-013).
		return fail(cmdutil.NewCodedError(cmdutil.ExitError, fmt.Errorf(
			"hub %s returned an unparseable certificate expiry %q", hubURL, cert.ExpiresAt)))
	}

	payload := sshCertPayload{
		Principal:          cert.Principal,
		ExpiresAt:          expiry.Format(time.RFC3339),
		HostKeyFingerprint: pickFingerprint(host, cert),
		GatewayPort:        pickGatewayPort(host, cert),
	}

	if err := store.SaveSSH(hubURL, auth.StoredSSH{
		PrivateKey:      key.privatePEM,
		Certificate:     strings.TrimSpace(cert.Certificate),
		CertExpiresAt:   expiry,
		HostFingerprint: payload.HostKeyFingerprint,
	}); err != nil {
		// The store's own errors never quote what they failed to write (see
		// internal/auth/store.go), so this is safe to surface as-is.
		return fail(cmdutil.NewCodedError(cmdutil.ExitError, err))
	}

	printSSHCert(ctx, payload)
	return cmdutil.ExitOK
}

// parseNoArgs enforces the "no arguments, no flags" surface of `vey
// ssh-cert`, so a mistyped invocation fails as a usage error instead of being
// silently ignored.
func parseNoArgs(args []string) error {
	fs := flag.NewFlagSet("ssh-cert", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		return cmdutil.NewUsageError(err)
	}
	if fs.NArg() > 0 {
		return cmdutil.NewUsageError(errors.New("usage: vey ssh-cert (takes no arguments)"))
	}
	return nil
}

// fetchSSHHostKey caches the gateway's identity for host pinning. It runs
// before issuance on purpose: a hub with no usable gateway host key cannot
// give the operator anything they could safely connect with, so there is no
// point spending an issuance against the rate limiter first.
func fetchSSHHostKey(bg context.Context, actx *auth.AuthContext) (sshHostKeyResponse, error) {
	var host sshHostKeyResponse
	err := actx.Do(bg, func(c *api.Client) error {
		return c.Get(bg, sshHostKeyPath, nil, &host)
	})
	return host, err
}

// issueSSHCertificate posts the public key and maps the one refusal the
// contract singles out.
//
// A 403 from this endpoint means exactly one thing (contracts/rest-api.md:
// "interactive login required"), and the fix is to log in — so it is reported
// as exit 3 carrying the hub's own message, rather than as the generic exit 4
// "permission denied" that api.Client assigns to every 403.
func issueSSHCertificate(bg context.Context, actx *auth.AuthContext, hubURL, publicKey string) (sshCertResponse, error) {
	var cert sshCertResponse
	err := actx.Do(bg, func(c *api.Client) error {
		return c.Post(bg, sshCertPath, sshCertRequest{PublicKey: publicKey}, &cert)
	})
	if err != nil && cmdutil.Code(err) == cmdutil.ExitForbidden {
		return sshCertResponse{}, cmdutil.NewAuthError(fmt.Errorf(
			"%s; run: vey login --hub %s", err, hubURL))
	}
	return cert, err
}

// loadOrGenerateSSHKey returns the keypair to certify: the stored one when
// this hub already has a usable key (FR-004 — re-issuance keeps the keypair),
// a freshly generated one otherwise.
func loadOrGenerateSSHKey(ctx *Context, store auth.Store, hubURL string) (sshKeypair, error) {
	stored, ok, err := store.LoadSSH(hubURL)
	if err != nil {
		return sshKeypair{}, cmdutil.NewCodedError(cmdutil.ExitError, err)
	}
	if ok {
		key, parseErr := keypairFromPEM(stored.PrivateKey)
		if parseErr == nil {
			return key, nil
		}
		// A stored key vey cannot read is unusable, and so is the certificate
		// signed for it — dead-ending here would leave the operator with no
		// way forward, so it is replaced instead. The parse error itself is
		// deliberately not shown: it can quote the key.
		ctx.Printer.Errorf("warning: the stored SSH key for %s could not be read; generating a new one\n", hubURL)
	}
	return generateSSHKeypair()
}

// keypairFromPEM re-derives both forms from a stored private key. Its error
// is never surfaced to the user (see loadOrGenerateSSHKey).
func keypairFromPEM(privatePEM string) (sshKeypair, error) {
	signer, err := ssh.ParsePrivateKey([]byte(privatePEM))
	if err != nil {
		return sshKeypair{}, err
	}
	return sshKeypair{
		privatePEM: privatePEM,
		authorized: authorizedKeyLine(signer.PublicKey()),
	}, nil
}

// generateSSHKeypair mints a new ed25519 client key. ed25519 is the only
// algorithm in play across this feature (the user CA and the gateway host key
// are ed25519 too), so there is nothing to negotiate.
func generateSSHKeypair() (sshKeypair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return sshKeypair{}, cmdutil.NewCodedError(cmdutil.ExitError,
			fmt.Errorf("generating an ed25519 SSH key: %w", err))
	}

	// Fixed messages, no %w: an encoder error must not become a channel for
	// key material to reach stderr.
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return sshKeypair{}, cmdutil.NewCodedError(cmdutil.ExitError,
			errors.New("encoding the generated SSH private key failed"))
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return sshKeypair{}, cmdutil.NewCodedError(cmdutil.ExitError,
			errors.New("encoding the generated SSH public key failed"))
	}

	return sshKeypair{
		privatePEM: string(pem.EncodeToMemory(block)),
		authorized: authorizedKeyLine(sshPub),
	}, nil
}

// authorizedKeyLine renders a public key as a single authorized_keys line,
// which is the form contracts/rest-api.md specifies for `public_key`.
func authorizedKeyLine(pub ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
}

// pickFingerprint and pickGatewayPort resolve the two values that both
// endpoints report. GET /api/ssh/host-key is the dedicated pinning source and
// wins; the issuance response is the fallback for a hub that leaves the
// host-key fields empty. The two are asserted equal hub-side (T020), so this
// is a robustness rule, not a reconciliation.
func pickFingerprint(host sshHostKeyResponse, cert sshCertResponse) string {
	if fp := strings.TrimSpace(host.Fingerprint); fp != "" {
		return fp
	}
	return strings.TrimSpace(cert.HostKeyFingerprint)
}

func pickGatewayPort(host sshHostKeyResponse, cert sshCertResponse) int {
	if host.Port != 0 {
		return host.Port
	}
	return cert.GatewayPort
}

// printSSHCert renders the result: one JSON document in --json mode,
// otherwise the contract's human line plus the two values `vey ssh` will use
// to reach and verify the gateway.
func printSSHCert(ctx *Context, p sshCertPayload) {
	_ = ctx.Printer.Payload(p, func(w io.Writer, v any) error {
		c := v.(sshCertPayload)
		fmt.Fprintf(w, "Signed cert for %s, valid until %s\n", c.Principal, c.ExpiresAt)
		fmt.Fprintf(w, "Gateway port: %d\n", c.GatewayPort)
		fmt.Fprintf(w, "Host key fingerprint: %s\n", c.HostKeyFingerprint)
		return nil
	})
}
