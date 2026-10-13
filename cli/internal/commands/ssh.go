package commands

// `vey ssh <server> [-- '<command>']` — connect to a fleet server via
// the gateway (specs/005-ssh-gateway/contracts/cli-commands.md `vey ssh`,
// contracts/ssh-gateway.md "Addressing the target server", data-model.md
// "Stored SSH material").
//
// The command is deliberately structured so the parts that decide *what* to
// run are pure and independently testable, and the parts that actually *do*
// something (network calls, temp files, process exec) are thin and
// injectable:
//
//	preflight the stored cert (local)  → resolve the server (one or two GETs,
//	same algorithm as `vey servers get`) → fetch the gateway host key (one
//	GET, for pinning) → write cert+key+known_hosts to a private temp dir →
//	buildSSHArgs (pure) → execSSH (the one injectable seam) → propagate its
//	exit code
//
// buildSSHArgs takes no filesystem/network arguments — only the
// already-resolved sshInvocation value — so the exact argv vey would hand to
// ssh is assertable in a test without a temp directory or a real hub.
// execSSH is a package-level var precisely so a test can replace the actual
// process exec with a recorder: this command must never spawn a real ssh
// connection during `go test`.

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/wyiu/veyport/cli/internal/api"
	"github.com/wyiu/veyport/cli/internal/auth"
	"github.com/wyiu/veyport/cli/internal/cmdutil"
	"golang.org/x/crypto/ssh"
)

// sshClientBinary is the native ssh client vey execs. Resolved via PATH at
// run time (see runSSHClient) — vey never ships or pins its own copy.
const sshClientBinary = "ssh"

// sshRunner executes the ssh client directly with the destination followed by
// an optional command string and independently wired stdin/stdout/stderr.
// exitCode is the ssh client's own exit status, propagated verbatim. err
// reports local start or I/O failures and cancellation before an exit status
// is available, distinct from anything ssh itself reported.
type sshRunner func(ctx context.Context, binary string, argv []string, stdin io.Reader, stdout, stderr io.Writer) (exitCode int, err error)

// execSSH is the one seam this command uses to reach the outside world for
// the actual connection. Production wires it to runSSHClient; tests replace
// it with a recorder so argv can be asserted without ever spawning ssh.
var execSSH sshRunner = runSSHClient

// sshStdinIsTTY reports whether stdin is an interactive terminal. Interactive
// shells require a TTY; command mode gives terminal stdin EOF and passes
// redirected input through. Tests can force either branch.
var sshStdinIsTTY = func() bool { return cmdutil.IsTTY(os.Stdin) }

// RunSSH implements `vey ssh <server> [-- '<command>']`.
func RunSSH(ctx *Context) int {
	fail := func(err error) int {
		ctx.Printer.Error(err)
		return cmdutil.Code(err)
	}

	request, err := parseSSHArgs(ctx.Args)
	if err != nil {
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

	// Preflight before any network call other than what resolution/host-key
	// fetch itself needs: an absent or expired certificate makes everything
	// downstream pointless, and the contract wants the operator pointed at
	// `vey ssh-cert` immediately (exit 3), not after a round trip.
	material, err := loadSSHCredential(store, hubURL)
	if err != nil {
		return fail(err)
	}
	username, err := certPrincipal(material.Certificate)
	if err != nil {
		return fail(cmdutil.NewAuthError(fmt.Errorf(
			"the stored SSH certificate for %s is unusable (%s); run: vey ssh-cert", hubURL, err)))
	}

	bg := context.Background()
	if request.command != "" {
		// Register before any temporary material is written. On cancellation,
		// the native runner waits for its child before this function returns
		// through the credential cleanup defer. Interactive behavior is unchanged.
		var stop context.CancelFunc
		bg, stop = signal.NotifyContext(bg, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
		defer stop()
	}
	server, err := resolveSSHServer(bg, actx, request.server)
	if err != nil {
		return fail(err)
	}

	host, err := fetchSSHHostKey(bg, actx)
	if err != nil {
		return fail(err)
	}
	warnIfHostFingerprintChanged(ctx, material.HostFingerprint, host)

	gatewayHost, err := gatewayHostFromHub(hubURL)
	if err != nil {
		return fail(err)
	}
	if host.Port <= 0 {
		return fail(cmdutil.NewCodedError(cmdutil.ExitError, fmt.Errorf(
			"hub %s did not report a usable SSH gateway port", hubURL)))
	}
	hostsLine, err := knownHostsLine(gatewayHost, host.Port, host.PublicKey)
	if err != nil {
		return fail(cmdutil.NewCodedError(cmdutil.ExitError, err))
	}

	files, err := writeSSHCredentialFiles(material, hostsLine)
	if err != nil {
		return fail(err)
	}
	defer files.cleanup()

	argv, err := buildSSHArgs(sshInvocation{
		identityFile:   files.identityFile,
		knownHostsFile: files.knownHostsFile,
		port:           host.Port,
		username:       username,
		server:         server.Name,
		gatewayHost:    gatewayHost,
		command:        request.command,
	})
	if err != nil {
		return fail(cmdutil.NewCodedError(cmdutil.ExitError, err))
	}

	// Keep preflight errors available to scripts probing the interactive mode.
	// Command mode must never wait for input from the operator's terminal.
	var stdin io.Reader = os.Stdin
	if sshStdinIsTTY() {
		if request.command != "" {
			stdin = nil // os/exec supplies the null device: immediate EOF.
		}
	} else if request.command == "" {
		return fail(cmdutil.NewCodedError(cmdutil.ExitError, errors.New(
			"vey ssh requires an interactive terminal (stdin is not a TTY); use: vey ssh <server> -- '<command>'")))
	}

	code, err := execSSH(bg, sshClientBinary, argv, stdin, os.Stdout, os.Stderr)
	if err != nil {
		// A local failure to even start the client (missing binary, exec
		// failure) is a vey-side environment problem, not a hub connectivity
		// failure (ExitConn is reserved for dial/TLS/timeout to the hub
		// itself — see api.mapTransportErr) and not ssh's own exit status, so
		// it gets the generic ExitError rather than either of those.
		return fail(cmdutil.NewCodedError(cmdutil.ExitError, err))
	}
	return code
}

const maxSSHCommandBytes = 32 * 1024

type sshArguments struct {
	server  string
	command string // Empty only for an interactive shell.
}

// parseSSHArgs accepts a node and, optionally, exactly one opaque command
// argument after --. Neither splitting nor trimming changes the remote program.
func parseSSHArgs(args []string) (sshArguments, error) {
	usageError := func() (sshArguments, error) {
		return sshArguments{}, cmdutil.NewUsageError(errors.New("usage: vey ssh <server> [-- '<command>']"))
	}
	if len(args) > 0 && args[0] == "--" {
		return usageError() // The command delimiter must follow a node.
	}
	fs := flag.NewFlagSet("ssh", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		return sshArguments{}, cmdutil.NewUsageError(err)
	}
	if fs.NArg() == 0 || strings.TrimSpace(fs.Arg(0)) == "" {
		return usageError()
	}
	request := sshArguments{server: fs.Arg(0)}
	if fs.NArg() == 1 {
		return request, nil
	}
	if fs.NArg() != 3 || fs.Arg(1) != "--" {
		return usageError()
	}
	request.command = fs.Arg(2)
	if err := validateSSHCommand(request.command); err != nil {
		return sshArguments{}, cmdutil.NewUsageError(err)
	}
	return request, nil
}

func validateSSHCommand(command string) error {
	if strings.TrimSpace(command) == "" {
		return errors.New("ssh command must not be empty")
	}
	if len(command) > maxSSHCommandBytes {
		return errors.New("ssh command exceeds the 32 KiB limit")
	}
	if !utf8.ValidString(command) || strings.ContainsRune(command, '\x00') {
		return errors.New("ssh command must be valid UTF-8 without NUL bytes")
	}
	return nil
}

// loadSSHCredential returns the stored SSH material for hubURL, or a
// cmdutil-coded error naming `vey ssh-cert` as the remedy when there is
// nothing usable to connect with: no material at all, or a certificate whose
// stored expiry has already passed. Checking the *stored* expiry (rather
// than parsing the certificate itself) is what lets `vey ssh` refuse
// up front without ever touching x/crypto/ssh for this step (FR-013 —
// `vey ssh-cert` is the one place that timestamp is trusted from).
func loadSSHCredential(store auth.Store, hubURL string) (auth.StoredSSH, error) {
	material, ok, err := store.LoadSSH(hubURL)
	if err != nil {
		return auth.StoredSSH{}, cmdutil.NewCodedError(cmdutil.ExitError, err)
	}
	if !ok {
		return auth.StoredSSH{}, cmdutil.NewAuthError(fmt.Errorf(
			"no SSH certificate found for %s; run: vey ssh-cert", hubURL))
	}
	if !material.CertExpiresAt.After(time.Now()) {
		return auth.StoredSSH{}, cmdutil.NewAuthError(fmt.Errorf(
			"the SSH certificate for %s expired at %s; run: vey ssh-cert", hubURL, material.CertExpiresAt.Format(time.RFC3339)))
	}
	return material, nil
}

// certPrincipal recovers the connecting veyport username from the stored
// certificate itself, rather than from whatever auth mode happens to be
// active right now: the cert's baked-in principal is what the gateway will
// actually check (contracts/ssh-gateway.md "cert principal == left part"),
// and a cert issued under a past session must keep working even if the
// active credential has since changed to an API token.
func certPrincipal(certLine string) (string, error) {
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(certLine))
	if err != nil {
		return "", errors.New("stored certificate is not readable")
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		return "", errors.New("stored certificate is not an SSH user certificate")
	}
	if len(cert.ValidPrincipals) == 0 || strings.TrimSpace(cert.ValidPrincipals[0]) == "" {
		return "", errors.New("stored certificate carries no principal")
	}
	return cert.ValidPrincipals[0], nil
}

// resolveSSHServer uses the same caller-visible resolution as servers get.
func resolveSSHServer(bg context.Context, actx *auth.AuthContext, ref string) (api.Server, error) {
	server, _, err := resolveServer(bg, actx, ref)
	return server, err
}

// warnIfHostFingerprintChanged tells the operator when the gateway's live
// host-key fingerprint no longer matches the one cached by the last `vey
// ssh-cert` (cached, from material.HostFingerprint). Not fatal: the live
// fetch is authoritative for the connection about to happen. But a
// fingerprint that moved since the last `vey ssh-cert` is exactly what
// FR-013/SC-007 (host-key stability) exists to catch, so the operator is
// told.
func warnIfHostFingerprintChanged(ctx *Context, cached string, host sshHostKeyResponse) {
	fp := strings.TrimSpace(cached)
	if fp != "" && fp != strings.TrimSpace(host.Fingerprint) {
		ctx.Printer.Errorf("warning: gateway host key fingerprint changed since the last vey ssh-cert (%s -> %s)\n", fp, host.Fingerprint)
	}
}

// gatewayHostFromHub derives the SSH gateway's host from the hub's own base
// URL: the gateway is the same box the hub API is served from, on a
// different port (contracts/cli-commands.md `vey ssh`: "the gateway
// host/port"), so there is no separate configuration surface for it.
func gatewayHostFromHub(hubURL string) (string, error) {
	u, err := url.Parse(hubURL)
	if err != nil || strings.TrimSpace(u.Hostname()) == "" {
		return "", cmdutil.NewCodedError(cmdutil.ExitError, fmt.Errorf(
			"could not determine the SSH gateway host from hub URL %q", hubURL))
	}
	return u.Hostname(), nil
}

// knownHostsLine renders a pinned known_hosts entry for host:port from the
// gateway's authorized_keys-form public key (contracts/rest-api.md GET
// /api/ssh/host-key "public_key"). Pinning via a purpose-built known_hosts
// file (rather than blind TOFU or the user's real ~/.ssh/known_hosts) is
// FR-013's "no blind TOFU" guarantee: ssh verifies against exactly the key
// the hub itself reported, nothing else.
func knownHostsLine(host string, port int, hostPublicKey string) (string, error) {
	fields := strings.Fields(hostPublicKey)
	if len(fields) < 2 {
		return "", fmt.Errorf("gateway reported a malformed host public key %q", hostPublicKey)
	}
	return fmt.Sprintf("%s %s %s\n", knownHostsPattern(host, port), fields[0], fields[1]), nil
}

// knownHostsPattern is the host part of a known_hosts line: bare hostname
// for the default port 22 (never expected here, since the gateway listens on
// its own configured port, but handled for completeness), bracketed
// "[host]:port" for anything else — the form ssh itself requires for a
// non-default port.
func knownHostsPattern(host string, port int) string {
	if port == 22 {
		return host
	}
	return fmt.Sprintf("[%s]:%d", host, port)
}

// sshInvocation bundles buildSSHArgs's inputs. It is deliberately the only
// thing buildSSHArgs looks at: no *Context, no filesystem, no network — so
// the exact argv vey constructs for a given resolved state is assertable
// directly.
type sshInvocation struct {
	// identityFile is the private key path handed to `ssh -i`; ssh's own
	// fixed convention loads the paired certificate from
	// identityFile+"-cert.pub" automatically, so the cert is never named on
	// the command line.
	identityFile string
	// knownHostsFile is the pinned, purpose-built known_hosts file (see
	// knownHostsLine) — never the operator's real ~/.ssh/known_hosts.
	knownHostsFile string
	// port is the gateway's listening port.
	port int
	// username is the connecting veyport principal, taken from the
	// certificate itself (certPrincipal).
	username string
	// server is the resolved target server's name (contracts/ssh-gateway.md
	// "Addressing the target server" — the gateway re-resolves this
	// independently; vey's own resolution just catches ambiguity/unknown
	// early with a clean CLI-side error).
	server string
	// gatewayHost is the SSH destination host (gatewayHostFromHub).
	gatewayHost string
	// command is an opaque remote shell program; empty requests a shell.
	command string
}

// buildSSHArgs is the pure heart of this command: given an already-resolved
// sshInvocation, it returns exactly the argv vey hands to the native ssh
// client, or an error if the invocation is incomplete. It touches no file,
// makes no network call, and spawns nothing — every other function in this
// file exists to produce the sshInvocation this one consumes.
func buildSSHArgs(in sshInvocation) ([]string, error) {
	switch {
	case strings.TrimSpace(in.identityFile) == "":
		return nil, errors.New("ssh: missing identity file")
	case strings.TrimSpace(in.knownHostsFile) == "":
		return nil, errors.New("ssh: missing known_hosts file")
	case in.port <= 0:
		return nil, fmt.Errorf("ssh: invalid gateway port %d", in.port)
	case strings.TrimSpace(in.username) == "":
		return nil, errors.New("ssh: missing veyport username")
	case strings.TrimSpace(in.server) == "":
		return nil, errors.New("ssh: missing target server")
	case strings.TrimSpace(in.gatewayHost) == "":
		return nil, errors.New("ssh: missing gateway host")
	case strings.Contains(in.username, "+"):
		// contracts/ssh-gateway.md "Addressing the target server": the split
		// is on the *first* '+', so a username containing '+' could never be
		// recovered correctly gateway-side. Caught here rather than silently
		// producing a target the gateway would misparse.
		return nil, fmt.Errorf("ssh: veyport username %q contains '+', which the user+server addressing scheme cannot encode; use the web terminal instead", in.username)
	}

	argv := []string{
		// -F /dev/null: ignore the user's (and system's) ssh config. vey
		// fully specifies this connection, and config-supplied IdentityFile
		// entries survive IdentitiesOnly=yes — they count as "explicit" — so
		// without this, a `Host *` IdentityFile gets offered to the gateway
		// before vey's certificate and the operator sees a spurious
		// "requires a certificate" banner on every connect (T026 finding,
		// 2026-08-12).
		"-F", "/dev/null",
		"-i", in.identityFile,
		// CertificateFile must be EXPLICIT even though ssh auto-discovers
		// "<identity>-cert.pub": with only auto-discovery, OpenSSH offers the
		// plain key BEFORE the certificate (observed via ssh -vv, T026
		// 2026-08-12), so every connect printed the gateway's "key was
		// skipped" banner before the cert attempt succeeded. An explicit
		// CertificateFile makes the certificate the first (and only needed)
		// offer. The path is the writeCredentialFiles pairing convention.
		"-o", "CertificateFile=" + in.identityFile + "-cert.pub",
		"-p", strconv.Itoa(in.port),
		"-o", "UserKnownHostsFile=" + in.knownHostsFile,
		"-o", "StrictHostKeyChecking=yes",
		"-o", "IdentitiesOnly=yes",
	}
	if in.command != "" {
		if err := validateSSHCommand(in.command); err != nil {
			return nil, err
		}
		argv = append(argv, "-T",
			"-o", "RequestTTY=no",
			"-o", "BatchMode=yes",
			"-o", "PasswordAuthentication=no",
			"-o", "KbdInteractiveAuthentication=no")
	}
	argv = append(argv, fmt.Sprintf("%s+%s@%s", in.username, in.server, in.gatewayHost))
	if in.command != "" {
		argv = append(argv, in.command)
	}
	return argv, nil
}

// sshCredentialFiles are the on-disk paths of the temp credential material
// ssh needs, plus the cleanup that removes the whole directory. ssh has no
// way to consume a private key, a certificate, or a pinned host key except
// as files, so this is the one place vey's cert/key material touches disk
// outside the credential store itself.
type sshCredentialFiles struct {
	identityFile   string
	knownHostsFile string
	cleanup        func()
}

// writeSSHCredentialFiles materializes material's private key and
// certificate, plus knownHostsContents, into a fresh 0700 temp directory:
// identityFile (0600), identityFile+"-cert.pub" (ssh's fixed naming
// convention for a certificate paired with -i, 0600), and known_hosts
// (0600). Never touches the operator's real ~/.ssh — everything lives under
// a process-private temp dir removed by the returned cleanup.
func writeSSHCredentialFiles(material auth.StoredSSH, knownHostsContents string) (sshCredentialFiles, error) {
	dir, err := os.MkdirTemp("", "vey-ssh-*")
	if err != nil {
		return sshCredentialFiles{}, cmdutil.NewCodedError(cmdutil.ExitError, fmt.Errorf("creating temp ssh directory: %w", err))
	}
	cleanup := func() { _ = os.RemoveAll(dir) }

	identityFile := filepath.Join(dir, "id_ed25519")
	certFile := identityFile + "-cert.pub"
	knownHostsFile := filepath.Join(dir, "known_hosts")

	if err := os.WriteFile(identityFile, []byte(ensureTrailingNewline(material.PrivateKey)), 0o600); err != nil {
		cleanup()
		return sshCredentialFiles{}, cmdutil.NewCodedError(cmdutil.ExitError, fmt.Errorf("writing SSH identity file: %w", err))
	}
	if err := os.WriteFile(certFile, []byte(ensureTrailingNewline(material.Certificate)), 0o600); err != nil {
		cleanup()
		return sshCredentialFiles{}, cmdutil.NewCodedError(cmdutil.ExitError, fmt.Errorf("writing SSH certificate file: %w", err))
	}
	if err := os.WriteFile(knownHostsFile, []byte(knownHostsContents), 0o600); err != nil {
		cleanup()
		return sshCredentialFiles{}, cmdutil.NewCodedError(cmdutil.ExitError, fmt.Errorf("writing known_hosts file: %w", err))
	}

	return sshCredentialFiles{identityFile: identityFile, knownHostsFile: knownHostsFile, cleanup: cleanup}, nil
}

// ensureTrailingNewline normalizes stored key/cert text to end in exactly
// one newline: ssh's own file parsers are picky about a missing trailing
// newline, and the store's values are trimmed on write (sshcert.go), so this
// is the one place vey adds it back.
func ensureTrailingNewline(s string) string {
	return strings.TrimRight(s, "\n") + "\n"
}

// runSSHClient is execSSH's production implementation: resolve the client on
// PATH, run it with argv wired to the operator's own terminal streams, and
// translate the outcome. An available native exit status always comes back
// as (exitCode, nil), including nonzero exits. Other local failures, including
// cancellation before starting the child, return an error.
func runSSHClient(ctx context.Context, binary string, argv []string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	path, err := exec.LookPath(binary)
	if err != nil {
		return 0, fmt.Errorf("%s not found on PATH: %w", binary, err)
	}

	cmd := exec.CommandContext(ctx, path, argv...)
	if ctx.Done() != nil {
		// Let OpenSSH close the channel first; if it does not terminate, the
		// bounded WaitDelay kills it. Wait reaps the child before temp cleanup.
		cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
		cmd.WaitDelay = 5 * time.Second
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, stderr
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode(), nil
		}
		return 0, fmt.Errorf("running %s: %w", binary, err)
	}
	return 0, nil
}
