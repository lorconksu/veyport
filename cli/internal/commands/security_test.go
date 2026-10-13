package commands

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"golang.org/x/term"

	"github.com/wyiu/veyport/cli/internal/api"
	"github.com/wyiu/veyport/cli/internal/cmdutil"
)

const securityRoleJSON = `{"kind":"role","role":{"user_id":"user-b","role":"security-approver","grant":true}}`
const securityCode = "731629"
const securityProof = "fixture-proof-never-print-this"

func securityFixture() api.SecurityChange {
	raw := []byte(`{"reason":"ticket 42","expected_version":3,"change":` + securityRoleJSON + `}`)
	hash := sha256.Sum256(raw)
	return api.SecurityChange{ID: "change-1", Revision: 1, RequesterID: "requester-a", RequesterPersonID: "person-a", ExpectedVersion: 3, Digest: hex.EncodeToString(hash[:]), Reason: "ticket 42", Change: json.RawMessage(securityRoleJSON), State: "pending", CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(time.Hour).UTC(), Approvals: []api.SecurityApproval{}}
}

func securityFile(t *testing.T, value string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "input")
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func securityRequestArgs(t *testing.T) []string {
	return []string{"request", "--change", securityFile(t, ` {"role":{"grant":true,"role":"security-approver","user_id":"user-b"},"kind":"role"} `), "--reason", " ticket 42 ", "--expected-version", "3", "--totp-file", securityFile(t, securityCode+"\n")}
}

func encodeSecurity(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Error(err)
	}
}

func mountSecurityPreview(t *testing.T, mux *http.ServeMux, fixture api.SecurityChange) {
	t.Helper()
	mux.HandleFunc("POST /api/security/changes/preview", func(w http.ResponseWriter, r *http.Request) {
		var proposal api.SecurityProposal
		if err := json.NewDecoder(r.Body).Decode(&proposal); err != nil {
			t.Error(err)
		}
		if proposal.ExpectedVersion != 3 || strings.TrimSpace(proposal.Reason) != "ticket 42" {
			t.Error("preview changed explicit version/reason")
		}
		encodeSecurity(t, w, api.SecurityPreview{Digest: fixture.Digest, Proposal: api.SecurityProposal{Reason: fixture.Reason, ExpectedVersion: fixture.ExpectedVersion, Change: fixture.Change}})
	})
}

func mountSecurityStepup(t *testing.T, mux *http.ServeMux, fixture api.SecurityChange, action string) {
	t.Helper()
	mux.HandleFunc("POST /api/security/step-up", func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Action, Digest, Code string
			ChangeID             string `json:"change_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
		}
		if request.Action != action || request.Digest != fixture.Digest || request.Code != securityCode || (action != "security.request" && request.ChangeID != fixture.ID) || (action == "security.request" && request.ChangeID != "") {
			t.Errorf("step-up binding changed: action=%q digest=%q change=%q", request.Action, request.Digest, request.ChangeID)
		}
		if !requireBearer(r, "session-access") || !strings.HasPrefix(r.UserAgent(), "vey/") {
			t.Error("step-up did not use refreshed CLI session")
		}
		encodeSecurity(t, w, map[string]any{"proof": securityProof, "expires_at": time.Now().Add(5 * time.Minute)})
	})
}

func TestSecurityRequestCanonicalProposalAndFreshSession(t *testing.T) {
	mux, srv, configDir := seedForServers(t, "session-access")
	fixture := securityFixture()
	var orderMu sync.Mutex
	var order []string
	record := func(name string) { orderMu.Lock(); defer orderMu.Unlock(); order = append(order, name) }
	mux.HandleFunc("POST /api/security/changes/preview", func(w http.ResponseWriter, r *http.Request) {
		record("preview")
		encodeSecurity(t, w, api.SecurityPreview{Digest: fixture.Digest, Proposal: api.SecurityProposal{Reason: fixture.Reason, ExpectedVersion: fixture.ExpectedVersion, Change: fixture.Change}})
	})
	mux.HandleFunc("POST /api/security/step-up", func(w http.ResponseWriter, r *http.Request) {
		record("step-up")
		var value map[string]string
		_ = json.NewDecoder(r.Body).Decode(&value)
		if value["action"] != "security.request" || value["digest"] != fixture.Digest || value["code"] != securityCode || value["change_id"] != "" || !requireBearer(r, "session-access") {
			t.Error("request MFA was not bound to action/digest/current session")
		}
		encodeSecurity(t, w, map[string]any{"proof": securityProof, "expires_at": time.Now().Add(5 * time.Minute)})
	})
	mux.HandleFunc("POST /api/security/changes", func(w http.ResponseWriter, r *http.Request) {
		record("submit")
		var value struct {
			api.SecurityProposal
			Proof string `json:"step_up_proof"`
		}
		_ = json.NewDecoder(r.Body).Decode(&value)
		if value.Reason != fixture.Reason || value.ExpectedVersion != 3 || string(value.Change) != securityRoleJSON || value.Proof != securityProof {
			t.Error("submission did not preserve the returned canonical proposal and proof")
		}
		w.WriteHeader(http.StatusCreated)
		encodeSecurity(t, w, fixture)
	})
	ctx, stdout, stderr := newCmdContext(srv.URL, configDir, true, securityRequestArgs(t))
	if code := runSecurity(ctx, securityInput{}); code != cmdutil.ExitOK {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
	assertSingleJSONDoc(t, "security request", stdout.Bytes())
	if !strings.Contains(stderr.String(), fixture.Digest) || !strings.Contains(stderr.String(), securityRoleJSON) || strings.Contains(stdout.String()+stderr.String(), securityProof) || strings.Contains(stdout.String()+stderr.String(), securityCode) {
		t.Fatal("preview absent or secret leaked")
	}
	orderMu.Lock()
	defer orderMu.Unlock()
	if strings.Join(order, ",") != "preview,step-up,submit" {
		t.Fatalf("operation order=%v", order)
	}
}

func TestSecurityApproveApplyBindFetchedDigestAndAction(t *testing.T) {
	for _, action := range []string{"approve", "apply"} {
		t.Run(action, func(t *testing.T) {
			mux, srv, configDir := seedForServers(t, "session-access")
			fixture := securityFixture()
			mux.HandleFunc("GET /api/security/changes/change-1", func(w http.ResponseWriter, r *http.Request) { encodeSecurity(t, w, fixture) })
			mountSecurityStepup(t, mux, fixture, "security."+action)
			mux.HandleFunc("POST /api/security/changes/change-1/"+action, func(w http.ResponseWriter, r *http.Request) {
				var request map[string]string
				_ = json.NewDecoder(r.Body).Decode(&request)
				if len(request) != 1 || request["step_up_proof"] != securityProof {
					t.Error("mutation supplied invented authority fields")
				}
				fixture.State = "approved"
				fixture.Approvals = []api.SecurityApproval{{UserID: "approver-b", PersonID: "person-b", ApprovedAt: time.Now(), InvalidatedAt: new(time.Time)}}
				encodeSecurity(t, w, fixture)
			})
			ctx, stdout, stderr := newCmdContext(srv.URL, configDir, false, []string{action, fixture.ID, "--digest", fixture.Digest, "--totp-file", securityFile(t, securityCode)})
			if code := runSecurity(ctx, securityInput{}); code != 0 {
				t.Fatalf("exit=%d stderr=%s", code, stderr)
			}
			if !strings.Contains(stdout.String(), "invalidated") || !strings.Contains(stdout.String(), "Exact change") || strings.Contains(stdout.String()+stderr.String(), securityProof) {
				t.Fatal("human result omitted invalidation/exact change or leaked proof")
			}
		})
	}
}

func TestSecurityReadsPolicyListStatusAndReconcile(t *testing.T) {
	for _, jsonMode := range []bool{false, true} {
		mux, srv, configDir := seedForServers(t, "session-access")
		fixture := securityFixture()
		mux.HandleFunc("GET /api/audit-policy", func(w http.ResponseWriter, r *http.Request) {
			encodeSecurity(t, w, map[string]any{"policy": map[string]any{"version": 3, "sha256": strings.Repeat("a", 64), "policy": map[string]any{"profile": "enhanced", "credential_ref": "secret:00000000-0000-0000-0000-000000000000"}}, "state": "enhanced", "capabilities": []string{"security.read"}, "credential_set": true, "readiness": map[string]bool{"governance": true, "archive_and_transport": false, "enrollment_marker": true}, "private_key": "CANARY_UNKNOWN_FIELD"})
		})
		mux.HandleFunc("GET /api/security/changes", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Query().Get("limit") != "5" || r.URL.Query().Get("offset") != "10" {
				t.Error("pagination was not bounded and passed through")
			}
			encodeSecurity(t, w, api.SecurityChangesPage{Changes: []api.SecurityChange{fixture}, Limit: 5, Offset: 10})
		})
		mux.HandleFunc("GET /api/security/changes/change-1", func(w http.ResponseWriter, r *http.Request) { encodeSecurity(t, w, fixture) })
		mux.HandleFunc("POST /api/security/changes/change-1/reconcile", func(w http.ResponseWriter, r *http.Request) {
			raw, _ := io.ReadAll(r.Body)
			if len(raw) != 0 {
				t.Error("reconcile invented an approval or MFA action")
			}
			encodeSecurity(t, w, fixture)
		})
		for _, args := range [][]string{{"status"}, {"status", "change-1"}, {"list", "--limit", "5", "--offset", "10"}, {"reconcile", "change-1"}} {
			ctx, stdout, stderr := newCmdContext(srv.URL, configDir, jsonMode, args)
			if code := runSecurity(ctx, securityInput{}); code != 0 {
				t.Fatalf("args=%v exit=%d stderr=%s", args, code, stderr)
			}
			if jsonMode {
				assertSingleJSONDoc(t, "security reads", stdout.Bytes())
			}
			if strings.Contains(stdout.String(), "CANARY_UNKNOWN_FIELD") {
				t.Fatal("unknown secret response field reached output")
			}
		}
	}
}

func TestSecurityAPITokensCannotSupplyInteractiveMFA(t *testing.T) {
	t.Setenv("VEYPORT_TOKEN", "adt_api-token-canary")
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if !requireBearer(r, "adt_api-token-canary") {
			t.Error("API-token read did not preserve existing auth precedence")
		}
		encodeSecurity(t, w, map[string]any{"version": 3, "profile": "standard", "state": "standard", "capabilities": []string{}})
	}))
	defer srv.Close()
	for _, args := range [][]string{securityRequestArgs(t), {"approve", "change-1", "--digest", securityFixture().Digest}, {"apply", "change-1", "--digest", securityFixture().Digest}, {"reconcile", "change-1"}, {"secret", "--kind", "password"}} {
		ctx, stdout, stderr := newCmdContext(srv.URL, t.TempDir(), true, args)
		if code := runSecurity(ctx, securityInput{}); code != cmdutil.ExitAuth {
			t.Fatalf("args=%v exit=%d stderr=%s", args, code, stderr)
		}
		assertEmptyStdout(t, "API-token mutation", stdout)
		if strings.Contains(stderr.String(), "api-token-canary") {
			t.Fatal("API token leaked")
		}
	}
	if calls != 0 {
		t.Fatal("API token attempted a mutation or MFA call")
	}
	ctx, _, stderr := newCmdContext(srv.URL, t.TempDir(), true, []string{"status"})
	if code := runSecurity(ctx, securityInput{}); code != 0 {
		t.Fatalf("API-token status exit=%d stderr=%s", code, stderr)
	}
}

func TestSecurityRefusesChangedPreviewAndFetchedDigestBeforeMFA(t *testing.T) {
	for _, scenario := range []string{"bad-preview-hash", "changed-preview", "bad-request-hash", "wrong-id", "wrong-expected-digest"} {
		t.Run(scenario, func(t *testing.T) {
			mux, srv, configDir := seedForServers(t, "session-access")
			fixture := securityFixture()
			args := []string{"approve", fixture.ID, "--digest", fixture.Digest, "--totp-file", securityFile(t, securityCode)}
			if strings.Contains(scenario, "preview") {
				args = securityRequestArgs(t)
				if scenario == "bad-preview-hash" {
					fixture.Digest = strings.Repeat("a", 64)
				} else {
					fixture.Reason = "server changed reason"
					fixture.Digest, _ = securityProposalDigest(api.SecurityProposal{Reason: fixture.Reason, ExpectedVersion: 3, Change: fixture.Change})
				}
				mountSecurityPreview(t, mux, fixture)
			} else {
				if scenario == "wrong-id" {
					fixture.ID = "different-id"
				} else if scenario == "bad-request-hash" {
					fixture.Change = json.RawMessage(strings.ReplaceAll(securityRoleJSON, "user-b", "user-c"))
				} else {
					args[3] = strings.Repeat("c", 64)
				}
				mux.HandleFunc("GET /api/security/changes/change-1", func(w http.ResponseWriter, r *http.Request) { encodeSecurity(t, w, fixture) })
			}
			mux.HandleFunc("POST /api/security/step-up", func(w http.ResponseWriter, r *http.Request) {
				t.Error("mismatched request reached MFA")
				w.WriteHeader(500)
			})
			ctx, stdout, stderr := newCmdContext(srv.URL, configDir, true, args)
			if code := runSecurity(ctx, securityInput{}); code != cmdutil.ExitError {
				t.Fatalf("exit=%d stderr=%s", code, stderr)
			}
			assertEmptyStdout(t, scenario, stdout)
		})
	}
}

func TestSecurityBackendDenialsRemainAuthoritative(t *testing.T) {
	for _, test := range []struct {
		name, route, message string
		status, code         int
	}{{"self-approval", "step-up", "independent security identities required", 403, 4}, {"stale-mfa", "step-up", "fresh MFA required", 403, 4}, {"expired-request", "approve", "security change conflict", 409, 1}, {"stale-version", "approve", "security change conflict", 409, 1}, {"revoked-role", "approve", "security authority denied", 403, 4}, {"rate-limit", "step-up", "rate limited", 429, 7}, {"missing-request", "get", "security change not found", 404, 5}} {
		t.Run(test.name, func(t *testing.T) {
			mux, srv, configDir := seedForServers(t, "session-access")
			fixture := securityFixture()
			reject := func(w http.ResponseWriter) {
				w.WriteHeader(test.status)
				encodeSecurity(t, w, map[string]string{"error": test.message})
			}
			mux.HandleFunc("GET /api/security/changes/change-1", func(w http.ResponseWriter, r *http.Request) {
				if test.route == "get" {
					reject(w)
				} else {
					encodeSecurity(t, w, fixture)
				}
			})
			mux.HandleFunc("POST /api/security/step-up", func(w http.ResponseWriter, r *http.Request) {
				if test.route == "step-up" {
					reject(w)
				} else {
					encodeSecurity(t, w, map[string]any{"proof": securityProof, "expires_at": time.Now().Add(time.Minute)})
				}
			})
			mux.HandleFunc("POST /api/security/changes/change-1/approve", func(w http.ResponseWriter, r *http.Request) {
				if test.route != "approve" {
					t.Error("mutation ran after refusal")
				}
				reject(w)
			})
			ctx, stdout, stderr := newCmdContext(srv.URL, configDir, true, []string{"approve", fixture.ID, "--digest", fixture.Digest, "--totp-file", securityFile(t, securityCode)})
			if code := runSecurity(ctx, securityInput{}); code != test.code {
				t.Fatalf("exit=%d want=%d stderr=%s", code, test.code, stderr)
			}
			assertEmptyStdout(t, test.name, stdout)
			if !strings.Contains(stderr.String(), test.message) {
				t.Fatal("backend refusal was hidden")
			}
		})
	}
}

func TestSecurityMFAExpiredMissingAndNonTTYNeverSubmit(t *testing.T) {
	for _, scenario := range []string{"expired", "missing", "long-lived", "non-tty", "invalid-code", "reflected-code"} {
		t.Run(scenario, func(t *testing.T) {
			mux, srv, configDir := seedForServers(t, "session-access")
			fixture := securityFixture()
			mountSecurityPreview(t, mux, fixture)
			args := securityRequestArgs(t)
			if scenario == "non-tty" {
				args = args[:len(args)-2]
			}
			if scenario == "invalid-code" {
				args[len(args)-1] = securityFile(t, "CANARY_INVALID_CODE")
			}
			mux.HandleFunc("POST /api/security/step-up", func(w http.ResponseWriter, r *http.Request) {
				if scenario == "non-tty" || scenario == "invalid-code" {
					t.Error("invalid input reached MFA")
				}
				expires := time.Now().Add(-time.Minute)
				if scenario == "long-lived" {
					expires = time.Now().Add(time.Hour)
				}
				proof := securityProof
				if scenario == "missing" {
					proof = ""
				}
				if scenario == "reflected-code" {
					w.WriteHeader(403)
					encodeSecurity(t, w, map[string]string{"error": "rejected " + securityCode})
					return
				}
				encodeSecurity(t, w, map[string]any{"proof": proof, "expires_at": expires})
			})
			mux.HandleFunc("POST /api/security/changes", func(w http.ResponseWriter, r *http.Request) { t.Error("invalid/expired MFA submitted a request") })
			ctx, stdout, stderr := newCmdContext(srv.URL, configDir, true, args)
			if code := runSecurity(ctx, securityInput{}); code == 0 {
				t.Fatal("invalid MFA accepted")
			}
			assertEmptyStdout(t, scenario, stdout)
			if strings.Contains(stderr.String(), securityCode) || strings.Contains(stderr.String(), securityProof) || strings.Contains(stderr.String(), "CANARY_INVALID_CODE") {
				t.Fatal("MFA material leaked")
			}
		})
	}
}

func TestSecuritySecretsPreserveExactBytesAndPrintReferenceOnly(t *testing.T) {
	for _, value := range []string{`{"bearer":"CANARY_DESTINATION_BEARER"}` + "\n", "CANARY_TEMP_PASSWORD\n"} {
		mux, srv, configDir := seedForServers(t, "session-access")
		mux.HandleFunc("POST /api/security/secrets", func(w http.ResponseWriter, r *http.Request) {
			var request map[string]string
			_ = json.NewDecoder(r.Body).Decode(&request)
			if request["value"] != value {
				t.Error("secret bytes were trimmed or changed")
			}
			encodeSecurity(t, w, map[string]any{"credential_ref": "secret:01234567-89ab-cdef-0123-456789abcdef", "credential_set": true, "value": value, "proof": securityProof})
		})
		ctx, stdout, stderr := newCmdContext(srv.URL, configDir, true, []string{"secret", "--kind", "destination", "--value-file", "-"})
		if code := runSecurity(ctx, securityInput{stdin: strings.NewReader(value)}); code != 0 {
			t.Fatalf("exit=%d stderr=%s", code, stderr)
		}
		assertSingleJSONDoc(t, "secret", stdout.Bytes())
		if strings.Contains(stdout.String()+stderr.String(), "CANARY_") || strings.Contains(stdout.String(), securityProof) {
			t.Fatal("write-only secret leaked")
		}
	}
}

func TestSecurityReflectedSecretsAndProofsAreScrubbed(t *testing.T) {
	for _, operation := range []string{"secret", "request"} {
		mux, srv, configDir := seedForServers(t, "session-access")
		secret := "CANARY_SECRET_\"quoted\"\nvalue"
		var args []string
		if operation == "secret" {
			args = []string{"secret", "--kind", "password", "--value-file", "-"}
			mux.HandleFunc("POST /api/security/secrets", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(400)
				escaped, _ := json.Marshal(secret)
				encodeSecurity(t, w, map[string]string{"error": "reflected " + secret + " " + string(escaped)})
			})
		} else {
			args = securityRequestArgs(t)
			fixture := securityFixture()
			mountSecurityPreview(t, mux, fixture)
			mountSecurityStepup(t, mux, fixture, "security.request")
			mux.HandleFunc("POST /api/security/changes", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(403)
				encodeSecurity(t, w, map[string]string{"error": "reflected " + securityProof})
			})
		}
		ctx, stdout, stderr := newCmdContext(srv.URL, configDir, true, args)
		if code := runSecurity(ctx, securityInput{stdin: strings.NewReader(secret)}); code == 0 {
			t.Fatal("refused operation returned success")
		}
		assertEmptyStdout(t, operation, stdout)
		if strings.Contains(stderr.String(), "CANARY_SECRET") || strings.Contains(stderr.String(), securityProof) {
			t.Fatalf("credential reflection reached stderr: %s", stderr)
		}
	}
}

func TestSecurityUsageBoundsAndClosedPayloads(t *testing.T) {
	for _, args := range [][]string{nil, {"unknown"}, {"list", "--limit", "101"}, {"list", "--offset", "-1"}, {"status", "../other"}, {"request", "--change", "-", "--totp-file", "-", "--reason", "r", "--expected-version", "1"}, {"request", "--change", "-", "--reason", "r"}, {"apply", "change-1"}, {"approve", "change-1", "--digest", "CANARY_DIGEST"}, {"secret", "--kind", "unknown"}, {"secret", "--kind", "password", "--value", "CANARY_ARG_SECRET"}, {"status", "change-1", "extra"}} {
		ctx, stdout, stderr := newCmdContext("", t.TempDir(), true, args)
		if code := runSecurity(ctx, securityInput{}); code != 2 {
			t.Fatalf("args=%v code=%d stderr=%s", args, code, stderr)
		}
		assertEmptyStdout(t, "usage", stdout)
		assertJSONErrorShape(t, "usage", stderr, 2)
		if strings.Contains(stderr.String(), "CANARY_") {
			t.Fatal("argument value echoed")
		}
	}
	for _, raw := range []string{`{"kind":"role","kind":"policy"}`, `{"kind":"role","role":{"user_id":"u","user_id":"v"}}`, `{"kind":"role","Role":{},"role":{}}`, `{"kind":"role","password":"CANARY_PASSWORD"}`, `{"kind":"ldap","ldap":{"bind_password":"CANARY_BIND"}}`, `{"kind":"recovery","recovery":{"prepared_password_hash":"CANARY_HASH"}}`, `{"kind":"policy","policy":{"destination":"https://u:CANARY_URL@x"}}`, `{"kind":"ldap","ldap":{"ca_cert_pem":"-----BEGIN PRIVATE KEY-----CANARY_PEM"}}`, `{"kind":"unknown"}`, `null`, securityRoleJSON + `{}`, "{"} {
		ctx, stdout, stderr := newCmdContext("", t.TempDir(), true, []string{"request", "--change", "-", "--reason", "r", "--expected-version", "1"})
		if code := runSecurity(ctx, securityInput{stdin: strings.NewReader(raw)}); code != 2 {
			t.Fatalf("bad change exit=%d stderr=%s", code, stderr)
		}
		assertEmptyStdout(t, "payload", stdout)
		if strings.Contains(stderr.String(), "CANARY_") {
			t.Fatal("invalid JSON value echoed")
		}
	}
	for _, size := range []int{0, maxSecurityChangeBytes + 1} {
		ctx, _, stderr := newCmdContext("", t.TempDir(), true, []string{"request", "--change", "-", "--reason", "r", "--expected-version", "1"})
		if code := runSecurity(ctx, securityInput{stdin: strings.NewReader(strings.Repeat("x", size))}); code != 2 {
			t.Fatalf("oversize exit=%d stderr=%s", code, stderr)
		}
	}
}

func TestSecurityHelpAndInputFailurePaths(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"request", "--help"}, {"help"}} {
		ctx, stdout, stderr := newCmdContext("", t.TempDir(), true, args)
		if code := runSecurity(ctx, securityInput{}); code != 0 {
			t.Fatal(code, stderr.String())
		}
		assertSingleJSONDoc(t, "help", stdout.Bytes())
		if !strings.Contains(stdout.String(), "--digest") || !strings.Contains(stdout.String(), "hide input") {
			t.Fatal("help omitted security contract")
		}
	}
	in := securityInput{}
	for _, path := range []string{"/nonexistent/security-input", t.TempDir(), "-"} {
		if _, err := in.read(path, 64, true); err == nil {
			t.Fatal("invalid input file accepted")
		}
	}
	path := securityFile(t, "123456")
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := in.read(path, 64, true); err == nil {
		t.Fatal("public secret file accepted")
	}
	if _, err := (securityInput{stdin: strings.NewReader(strings.Repeat("x", 8193))}).secret("-", 8192, "secret", cmdutil.NewPrinter(io.Discard, io.Discard, false)); err == nil {
		t.Fatal("oversized secret accepted")
	}
	if validateSecurityJSON([]byte(strings.Repeat("[", 18)+"0"+strings.Repeat("]", 18))) == nil {
		t.Fatal("unbounded nested JSON accepted")
	}
}

func TestSecurityNoSessionAndNetworkFailures(t *testing.T) {
	t.Setenv("VEYPORT_TOKEN", "")
	ctx, stdout, stderr := newCmdContext("https://hub.example.com", t.TempDir(), true, []string{"reconcile", "change-1"})
	if code := runSecurity(ctx, securityInput{}); code != 3 {
		t.Fatal(code, stderr.String())
	}
	assertEmptyStdout(t, "no session", stdout)
	mux, srv, configDir := seedForServers(t, "session-access")
	mux.HandleFunc("GET /api/audit-policy", func(w http.ResponseWriter, r *http.Request) { encodeSecurity(t, w, map[string]any{}) })
	srv.Close()
	ctx, stdout, stderr = newCmdContext(srv.URL, configDir, true, []string{"status"})
	if code := runSecurity(ctx, securityInput{}); code != 6 {
		t.Fatal(code, stderr.String())
	}
	assertEmptyStdout(t, "network", stdout)
}

func TestSecurityHiddenTerminalInput(t *testing.T) {
	master, slave := openTestPTY(t)
	defer master.Close()
	var called bool
	in := securityInput{terminal: slave, readHidden: func(fd int) ([]byte, error) { called = fd == int(slave.Fd()); return []byte(securityCode), nil }}
	var stderr bytes.Buffer
	code, err := in.totp("", cmdutil.NewPrinter(io.Discard, &stderr, false))
	if err != nil || code != securityCode || !called || strings.Contains(stderr.String(), securityCode) {
		t.Fatal("hidden terminal path failed")
	}
}

func TestSecurityRealTerminalDisablesEchoAndRestoresIt(t *testing.T) {
	master, slave := openTestPTY(t)
	defer master.Close()
	original, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	in := securityInput{terminal: slave, readHidden: term.ReadPassword}
	type result struct {
		secret string
		err    error
	}
	done := make(chan result, 1)
	go func() {
		value, err := in.secret("", 8192, "secret", cmdutil.NewPrinter(io.Discard, io.Discard, false))
		done <- result{value, err}
	}()
	deadline := time.Now().Add(3 * time.Second)
	for {
		state, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
		if err != nil {
			t.Fatal(err)
		}
		if state.Lflag&unix.ECHO == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("hidden prompt did not disable terminal echo")
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := master.Write([]byte("CANARY_HIDDEN_INPUT\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-done:
		if result.err != nil || result.secret != "CANARY_HIDDEN_INPUT" {
			t.Fatal("hidden terminal input failed")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("hidden terminal prompt did not finish")
	}
	restored, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if err != nil || restored.Lflag != original.Lflag {
		t.Fatal("hidden prompt did not restore terminal flags")
	}
}

func TestSecurityNamedPipeInputsRefusedWithoutWaitingForWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "named-pipe")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	// This cleanup also unblocks the old blocking-open implementation on a
	// failing regression, so the test never leaves an unattended reader.
	t.Cleanup(func() {
		file, err := os.OpenFile(path, os.O_RDWR|syscall.O_NONBLOCK, 0)
		if err == nil {
			file.Close()
		}
	})
	for _, private := range []bool{false, true} {
		done := make(chan error, 1)
		go func() { _, err := (securityInput{}).read(path, 8192, private); done <- err }()
		select {
		case err := <-done:
			if cmdutil.Code(err) != cmdutil.ExitUsage {
				t.Fatal("named pipe accepted")
			}
		case <-time.After(time.Second):
			t.Fatal("security file input waited for a FIFO writer")
		}
	}
}
