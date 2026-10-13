package commands

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"golang.org/x/term"

	"github.com/wyiu/veyport/cli/internal/api"
	"github.com/wyiu/veyport/cli/internal/auth"
	"github.com/wyiu/veyport/cli/internal/cmdutil"
)

const securityUsage = `usage: vey [global flags] security <command> [flags]

Commands:
  request --change FILE|- --reason TEXT --expected-version N [--totp-file FILE|-]
  list [--limit N] [--offset N]
  status [CHANGE_ID]
  approve CHANGE_ID --digest SHA256 [--totp-file FILE|-]
  apply CHANGE_ID --digest SHA256 [--totp-file FILE|-]
  reconcile CHANGE_ID
  secret --kind destination|password [--value-file FILE|-]

request reads one typed change JSON object (maximum 48 KiB). Reason is required
and expected-version must explicitly name the active policy version. The hub's
exact canonical proposal and digest appear on stderr before fresh MFA/submission.
approve/apply require the digest obtained from status, then display and verify
the exact request before fresh MFA. Each operation uses a new session/action/
digest-bound proof. The hub checks live authority, distinct people, quorum,
expiry and version; the CLI supplies no votes or permission overrides.

status without an ID shows current policy, readiness and capabilities. list
returns one page (limit 1..100, offset >=0). reconcile retries an existing applying
decision; it does not create an approval or fresh apply decision.

Mutations require a stored interactive CLI session (vey login). Clear any
VEYPORT_TOKEN/configured api_token to select that session. Reads may use API
tokens, subject to backend permission checks. Default MFA and secret prompts
require a terminal and hide input. Explicit secret/TOTP files must be regular
and mode 0600 or stricter. '-' reads bounded stdin; two inputs cannot share stdin.
TOTP is six digits (64 input bytes maximum); secrets are at most 8192 exact bytes.
Secret output contains only credential_ref/credential_set. Destination values
are JSON containing either certificate_pem/private_key_pem or bearer; password
values are exact text. Use references in change JSON, never credential values.
--json keeps stdout to one result document; preview/prompt diagnostics use stderr.
`

type securityOptions struct {
	command, id, change, reason, digest, totpFile, kind, valueFile string
	expectedVersion                                                uint64
	limit, offset                                                  int
}

func RunSecurity(ctx *Context) int {
	return runSecurity(ctx, securityInput{stdin: os.Stdin, terminal: os.Stdin, readHidden: term.ReadPassword})
}

func runSecurity(ctx *Context, input securityInput) int {
	if len(ctx.Args) > 0 && (ctx.Args[0] == "--help" || ctx.Args[0] == "help" || (len(ctx.Args) == 2 && ctx.Args[1] == "--help")) {
		err := ctx.Printer.Payload(struct {
			Usage string `json:"usage"`
		}{securityUsage}, func(w io.Writer, _ any) error { _, err := io.WriteString(w, securityUsage); return err })
		return securityFinish(ctx, err)
	}
	options, err := parseSecurityOptions(ctx.Args)
	if err != nil {
		return securityFinish(ctx, err)
	}
	var change []byte
	if options.command == "request" {
		change, err = input.read(options.change, maxSecurityChangeBytes, false)
		if err != nil {
			return securityFinish(ctx, err)
		}
		if err = validateSecurityPayload(change); err != nil {
			return securityFinish(ctx, cmdutil.NewUsageError(err))
		}
	}
	hub, err := ctx.RequireHub()
	if err != nil {
		return securityFinish(ctx, err)
	}
	_, session, err := newAuthContext(ctx, hub)
	if err != nil {
		return securityFinish(ctx, err)
	}
	if options.command != "status" && options.command != "list" && session.Mode() != auth.ModeSession {
		return securityFinish(ctx, cmdutil.NewAuthError(errors.New("security mutations require a stored CLI login session; clear API-token overrides and run vey login")))
	}
	bg := context.Background()
	switch options.command {
	case "request":
		var preview api.SecurityPreview
		proposal := api.SecurityProposal{Reason: options.reason, ExpectedVersion: options.expectedVersion, Change: change}
		err = securityDo(bg, session, func(c *api.Client, call context.Context) error {
			return c.Post(call, "/api/security/changes/preview", proposal, &preview)
		})
		if err != nil {
			break
		}
		var actual string
		actual, err = securityProposalDigest(preview.Proposal)
		proposal.Reason = strings.TrimSpace(proposal.Reason)
		proposal.Change = securityCanonicalPayload(change)
		expected, expectedErr := securityProposalDigest(proposal)
		if err != nil || expectedErr != nil || !validSecurityDigest(preview.Digest) || actual != preview.Digest || expected != preview.Digest {
			err = errors.New("backend canonical proposal does not match its digest, reason or expected version; nothing submitted")
			break
		}
		if err = securityPrintPreview(ctx, preview); err != nil {
			break
		}
		var proof string
		proof, err = securityStepup(bg, session, input, ctx.Printer, options, "security.request", preview.Digest)
		if err != nil {
			break
		}
		var result api.SecurityChange
		err = securityDo(bg, session, func(c *api.Client, call context.Context) error {
			return c.Post(call, "/api/security/changes", struct {
				api.SecurityProposal
				Proof string `json:"step_up_proof"`
			}{preview.Proposal, proof}, &result)
		}, proof)
		if err == nil {
			err = securityPrintChange(ctx, result, preview.Digest, "")
		}
	case "list":
		var page api.SecurityChangesPage
		query := url.Values{"limit": {strconv.Itoa(options.limit)}, "offset": {strconv.Itoa(options.offset)}}
		err = securityDo(bg, session, func(c *api.Client, call context.Context) error {
			return c.Get(call, "/api/security/changes", query, &page)
		})
		if err == nil {
			for _, change := range page.Changes {
				if err = securityValidateChange(change, "", ""); err != nil {
					break
				}
			}
		}
		if err == nil {
			err = ctx.Printer.Payload(page, func(w io.Writer, _ any) error {
				table := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
				fmt.Fprintln(table, "ID\tSTATE\tVERSION\tEXPIRES\tDIGEST")
				for _, change := range page.Changes {
					fmt.Fprintf(table, "%s\t%s\t%d\t%s\t%s\n", change.ID, change.State, change.ExpectedVersion, change.ExpiresAt.Format(time.RFC3339), change.Digest)
				}
				return table.Flush()
			})
		}
	case "status":
		if options.id == "" {
			var policy api.SecurityPolicyStatus
			err = securityDo(bg, session, func(c *api.Client, call context.Context) error { return c.Get(call, "/api/audit-policy", nil, &policy) })
			if err == nil && (policy.Policy != nil && !safeSecurityURL(policy.Policy.Policy.Destination) || policy.Pending != nil && !safeSecurityURL(policy.Pending.Policy.Destination)) {
				err = errors.New("hub policy contains an unsafe endpoint URL")
			}
			if err == nil {
				err = ctx.Printer.Payload(policy, func(w io.Writer, _ any) error {
					version, profile := policy.Version, policy.Profile
					if policy.Policy != nil {
						version, profile = policy.Policy.Version, policy.Policy.Policy.Profile
					}
					fmt.Fprintf(w, "Policy: %d (%s)\nState: %s\nCapabilities: %s\n", version, profile, policy.State, strings.Join(policy.Capabilities, ", "))
					if policy.Readiness != nil {
						fmt.Fprintf(w, "Readiness: governance=%t archive_and_transport=%t enrollment_marker=%t\n", policy.Readiness.Governance, policy.Readiness.ArchiveAndTransport, policy.Readiness.EnrollmentMarker)
					}
					encoded, _ := json.MarshalIndent(policy, "", "  ")
					_, writeErr := fmt.Fprintf(w, "%s\n", encoded)
					return writeErr
				})
			}
		} else {
			var change api.SecurityChange
			change, err = securityGetChange(bg, session, options.id)
			if err == nil {
				err = securityPrintChange(ctx, change, "", options.id)
			}
		}
	case "approve", "apply":
		var change api.SecurityChange
		change, err = securityGetChange(bg, session, options.id)
		if err == nil {
			err = securityValidateChange(change, options.digest, options.id)
		}
		if err != nil {
			break
		}
		proposal := api.SecurityProposal{Reason: change.Reason, ExpectedVersion: change.ExpectedVersion, Change: change.Change}
		if err = securityPrintPreview(ctx, api.SecurityPreview{Digest: change.Digest, Proposal: proposal}); err != nil {
			break
		}
		var proof string
		proof, err = securityStepup(bg, session, input, ctx.Printer, options, "security."+options.command, change.Digest)
		if err != nil {
			break
		}
		var result api.SecurityChange
		err = securityDo(bg, session, func(c *api.Client, call context.Context) error {
			return c.Post(call, "/api/security/changes/"+options.id+"/"+options.command, map[string]string{"step_up_proof": proof}, &result)
		}, proof)
		if err == nil {
			err = securityPrintChange(ctx, result, change.Digest, options.id)
		}
	case "reconcile":
		var result api.SecurityChange
		err = securityDo(bg, session, func(c *api.Client, call context.Context) error {
			return c.Post(call, "/api/security/changes/"+options.id+"/reconcile", nil, &result)
		})
		if err == nil {
			err = securityPrintChange(ctx, result, "", options.id)
		}
	case "secret":
		var secret string
		secret, err = input.secret(options.valueFile, 8192, "Write-only "+options.kind+" secret", ctx.Printer)
		if err != nil {
			break
		}
		var result struct {
			CredentialRef string `json:"credential_ref"`
			CredentialSet bool   `json:"credential_set"`
		}
		err = securityDo(bg, session, func(c *api.Client, call context.Context) error {
			return c.Post(call, "/api/security/secrets", map[string]string{"kind": options.kind, "value": secret}, &result)
		}, secret)
		if err == nil && (!validSecuritySecretRef(result.CredentialRef) || !result.CredentialSet || strings.Contains(result.CredentialRef, secret)) {
			err = errors.New("hub returned an invalid write-only secret reference")
		}
		if err == nil {
			err = ctx.Printer.Payload(result, func(w io.Writer, _ any) error {
				_, err := fmt.Fprintf(w, "Credential reference: %s (set)\n", result.CredentialRef)
				return err
			})
		}
	}
	return securityFinish(ctx, err)
}

func parseSecurityOptions(args []string) (securityOptions, error) {
	fail := func() (securityOptions, error) {
		return securityOptions{}, cmdutil.NewUsageError(errors.New("invalid security command arguments; see vey security --help"))
	}
	if len(args) == 0 {
		return fail()
	}
	options := securityOptions{command: args[0], limit: 50}
	args = args[1:]
	flags := flag.NewFlagSet("security", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	switch options.command {
	case "request":
		flags.StringVar(&options.change, "change", "", "typed change JSON file or -")
		flags.StringVar(&options.reason, "reason", "", "required reason")
		flags.Uint64Var(&options.expectedVersion, "expected-version", 0, "explicit policy version")
		flags.StringVar(&options.totpFile, "totp-file", "", "private code file or -")
	case "list":
		flags.IntVar(&options.limit, "limit", 50, "page size 1..100")
		flags.IntVar(&options.offset, "offset", 0, "page offset")
	case "status", "approve", "apply", "reconcile":
		if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
			options.id, args = args[0], args[1:]
		}
		if options.command == "approve" || options.command == "apply" {
			flags.StringVar(&options.digest, "digest", "", "exact request SHA256")
			flags.StringVar(&options.totpFile, "totp-file", "", "private code file or -")
		}
		if options.command != "status" && options.id == "" {
			return fail()
		}
	case "secret":
		flags.StringVar(&options.kind, "kind", "", "destination or password")
		flags.StringVar(&options.valueFile, "value-file", "", "private value file or -")
	default:
		return fail()
	}
	if flags.Parse(args) != nil || len(flags.Args()) != 0 || options.limit < 1 || options.limit > 100 || options.offset < 0 {
		return fail()
	}
	if options.command == "request" && (options.change == "" || strings.TrimSpace(options.reason) == "" || len(options.reason) > 2048 || options.expectedVersion == 0 || options.change == "-" && options.totpFile == "-") {
		return fail()
	}
	if (options.command == "approve" || options.command == "apply") && !validSecurityDigest(options.digest) {
		return fail()
	}
	if options.command == "secret" && options.kind != "destination" && options.kind != "password" {
		return fail()
	}
	if options.id != "" && !validSecurityID(options.id) {
		return fail()
	}
	return options, nil
}

func validSecurityID(id string) bool {
	if len(id) > 128 {
		return false
	}
	for _, char := range id {
		if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '-' || char == '_') {
			return false
		}
	}
	return id != ""
}

func validSecuritySecretRef(ref string) bool {
	if len(ref) != 43 || !strings.HasPrefix(ref, "secret:") {
		return false
	}
	for i, c := range ref[7:] {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
		} else if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func securityDo(bg context.Context, session *auth.AuthContext, operation func(*api.Client, context.Context) error, secrets ...string) error {
	call, cancel := context.WithTimeout(bg, 30*time.Second)
	defer cancel()
	err := session.Do(call, func(c *api.Client) error {
		c.MaxResponseBytes = 8 << 20
		return operation(c, call)
	})
	return securityError(err, secrets...)
}

func securityGetChange(bg context.Context, session *auth.AuthContext, id string) (api.SecurityChange, error) {
	var change api.SecurityChange
	err := securityDo(bg, session, func(c *api.Client, call context.Context) error {
		return c.Get(call, "/api/security/changes/"+id, nil, &change)
	})
	return change, err
}

func securityStepup(bg context.Context, session *auth.AuthContext, input securityInput, printer *cmdutil.Printer, options securityOptions, action, digest string) (string, error) {
	code, err := input.totp(options.totpFile, printer)
	if err != nil {
		return "", err
	}
	var result struct {
		Proof     string    `json:"proof"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	err = securityDo(bg, session, func(c *api.Client, call context.Context) error {
		return c.Post(call, "/api/security/step-up", struct {
			Action   string `json:"action"`
			Digest   string `json:"digest"`
			Code     string `json:"code"`
			ChangeID string `json:"change_id,omitempty"`
		}{action, digest, code, options.id}, &result)
	}, code)
	if err != nil {
		return "", err
	}
	if result.Proof == "" || len(result.Proof) > 4096 || !time.Now().Before(result.ExpiresAt) || result.ExpiresAt.After(time.Now().Add(6*time.Minute)) {
		return "", errors.New("hub returned a missing, expired or unbounded MFA proof; nothing submitted")
	}
	return result.Proof, nil
}

func securityValidateChange(change api.SecurityChange, digest, id string) error {
	if !validSecurityID(change.ID) || id != "" && change.ID != id || !validSecurityDigest(change.Digest) || digest != "" && change.Digest != digest {
		return errors.New("backend request identity or digest does not match; nothing submitted")
	}
	actual, err := securityProposalDigest(api.SecurityProposal{Reason: change.Reason, ExpectedVersion: change.ExpectedVersion, Change: change.Change})
	if err != nil || actual != change.Digest {
		return errors.New("backend request proposal does not match its digest; nothing submitted")
	}
	return nil
}

func securityPrintPreview(ctx *Context, preview api.SecurityPreview) error {
	encoded, err := json.Marshal(preview)
	if err == nil {
		_, err = fmt.Fprintf(ctx.Printer.Err, "{\"preview\":%s}\n", encoded)
	}
	return err
}

func securityPrintChange(ctx *Context, change api.SecurityChange, digest, id string) error {
	if err := securityValidateChange(change, digest, id); err != nil {
		return err
	}
	return ctx.Printer.Payload(change, func(w io.Writer, _ any) error {
		fmt.Fprintf(w, "Change: %s\nState: %s\nDigest: %s\nExpected policy version: %d\nReason: %s\nExpires: %s\n", change.ID, change.State, change.Digest, change.ExpectedVersion, strconv.Quote(change.Reason), change.ExpiresAt.Format(time.RFC3339))
		for _, vote := range change.Approvals {
			state := "recorded"
			if vote.InvalidatedAt != nil {
				state = "invalidated"
			}
			fmt.Fprintf(w, "Approval: user=%s person=%s %s at %s\n", strconv.Quote(vote.UserID), strconv.Quote(vote.PersonID), state, vote.ApprovedAt.Format(time.RFC3339))
		}
		encoded, _ := json.MarshalIndent(change.Change, "", "  ")
		_, err := fmt.Fprintf(w, "Exact change:\n%s\n", encoded)
		return err
	})
}

func securityFinish(ctx *Context, err error) int {
	ctx.Printer.Error(err)
	return cmdutil.Code(err)
}
