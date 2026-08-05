package commands

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/wyiu/veyport/cli/internal/auth"
	"github.com/wyiu/veyport/cli/internal/cmdutil"
)

// --- vey audit export ----------------------------------------------------
//
// contracts/cli-commands.md `vey audit export`: "Streams the hub's audit
// export to stdout (already machine-consumable; --json is a no-op
// passthrough). Role-gated: 403 → exit 4."
//
// The real hub route (hub/internal/server/router.go:52) is:
//
//	GET /api/audit-logs/export -> auditAccessOnly(handleExportAuditLogs)
//
// auditAccessOnly (hub/internal/server/middleware.go) allows only
// model.RoleAdmin / model.RoleAuditor and 403s everyone else — the CLI
// itself does no role gating, it just relays whatever status the hub
// returns. handleExportAuditLogs (hub/internal/server/handlers_audit.go)
// responds via respondJSON, so the pinned media type is
// "application/json" (NOT text/csv or any streaming/chunked format), and
// the body shape is model.AuditExportResponse: {"manifest": {...},
// "entries": [...]}. Since the CLI's contract is byte-for-byte passthrough
// (no decode/re-encode), these tests assert on exact bytes rather than
// parsing that shape — but the fixture body below mirrors it so a future
// change to the hub's actual media type/shape would need a matching test
// update here, per the task's "pin what the hub actually emits" charge.

// auditExportFixtureBody mirrors model.AuditExportResponse's real JSON
// shape (hub/internal/model/audit_controls.go AuditExportResponse:
// {"manifest": AuditManifest, "entries": []AuditEntry}) closely enough to
// pin the contract, without importing the hub module from the CLI (the CLI
// talks to the hub only over HTTP, never via Go imports).
const auditExportFixtureBody = `{"manifest":{"generated_at":"2026-08-05T00:00:00Z","generated_by":"alice","record_count":2,"applied_filters":""},"entries":[{"id":"e1","action":"audit.exported"},{"id":"e2","action":"user.login"}]}`

// mountAuditExport registers the export handler at the real hub route and
// media type. wantBearer, when non-empty, requires that exact bearer token
// (session access token) and 403s otherwise, modeling auditAccessOnly's
// role gate at the boundary the CLI actually observes: a status code, not
// a role name.
func mountAuditExport(t *testing.T, mux *http.ServeMux, wantBearer, body string) {
	t.Helper()
	mux.HandleFunc("GET /api/audit-logs/export", func(w http.ResponseWriter, r *http.Request) {
		if wantBearer != "" && !requireBearer(r, wantBearer) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "audit access required"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	})
}

// TestAuditExport_StreamsBodyToStdoutUnmodified covers the admin/auditor
// success path: 200 -> exit 0, and the hub's response body (application/json,
// AuditExportResponse shape) reaches stdout byte-for-byte, with no
// decode/re-encode (contract: "already machine-consumable").
func TestAuditExport_StreamsBodyToStdoutUnmodified(t *testing.T) {
	t.Setenv("VEYPORT_TOKEN", "")

	mux := http.NewServeMux()
	mountRefresh(mux, "access-1", "refresh-2")
	mountAuditExport(t, mux, "access-1", auditExportFixtureBody)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	configDir := t.TempDir()
	seedSession(t, configDir, srv.URL, auth.StoredSession{
		RefreshToken: "refresh-1",
		Username:     "alice",
		Role:         "admin",
		ObtainedAt:   time.Now(),
	})

	ctx, stdout, stderr := newCmdContext(srv.URL, configDir, false, []string{"export"})
	code := RunAudit(ctx)

	if code != cmdutil.ExitOK {
		t.Fatalf("exit code = %d, want %d (ExitOK); stderr=%q", code, cmdutil.ExitOK, stderr.String())
	}
	if stdout.String() != auditExportFixtureBody {
		t.Errorf("stdout = %q, want the hub body verbatim %q", stdout.String(), auditExportFixtureBody)
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr not empty on success: %q", stderr.String())
	}
}

// TestAuditExport_JSONFlagIsNoOp covers "--json is a no-op passthrough": the
// same streamed bytes reach stdout whether or not --json is set, since the
// hub's export is already machine-consumable.
func TestAuditExport_JSONFlagIsNoOp(t *testing.T) {
	t.Setenv("VEYPORT_TOKEN", "")

	mux := http.NewServeMux()
	mountRefresh(mux, "access-1", "refresh-2")
	mountAuditExport(t, mux, "access-1", auditExportFixtureBody)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	configDir := t.TempDir()
	seedSession(t, configDir, srv.URL, auth.StoredSession{
		RefreshToken: "refresh-1",
		Username:     "alice",
		Role:         "auditor",
		ObtainedAt:   time.Now(),
	})

	ctx, stdout, stderr := newCmdContext(srv.URL, configDir, true, []string{"export"})
	code := RunAudit(ctx)

	if code != cmdutil.ExitOK {
		t.Fatalf("exit code = %d, want %d (ExitOK); stderr=%q", code, cmdutil.ExitOK, stderr.String())
	}
	if stdout.String() != auditExportFixtureBody {
		t.Errorf("--json changed the streamed body: stdout = %q, want %q", stdout.String(), auditExportFixtureBody)
	}
}

// TestAuditExport_OtherRole403_ExitForbidden covers the role gate as the
// CLI observes it: a non-admin/auditor session gets 403 from
// auditAccessOnly, which the CLI must map to exit 4 without ever touching
// stdout.
func TestAuditExport_OtherRole403_ExitForbidden(t *testing.T) {
	t.Setenv("VEYPORT_TOKEN", "")

	mux := http.NewServeMux()
	mountRefresh(mux, "access-1", "refresh-2")
	// wantBearer "" plus a handler that always 403s models a role that
	// authenticates fine but isn't admin/auditor (auditAccessOnly's gate is
	// role-based, not token-based; from the CLI's perspective it is
	// observed purely as an unconditional 403 on this route).
	mux.HandleFunc("GET /api/audit-logs/export", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "audit access required"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	configDir := t.TempDir()
	seedSession(t, configDir, srv.URL, auth.StoredSession{
		RefreshToken: "refresh-1",
		Username:     "bob",
		Role:         "operator",
		ObtainedAt:   time.Now(),
	})

	ctx, stdout, stderr := newCmdContext(srv.URL, configDir, false, []string{"export"})
	code := RunAudit(ctx)

	if code != cmdutil.ExitForbidden {
		t.Fatalf("exit code = %d, want %d (ExitForbidden); stderr=%q", code, cmdutil.ExitForbidden, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout not empty on 403: %q", stdout.String())
	}
	if stderr.Len() == 0 {
		t.Error("stderr empty on 403, want an error notice")
	}
}

// TestAuditExport_InterruptedStream_ExitConn covers a stream that starts
// successfully (200, headers sent) but is cut off mid-body: the client must
// still allow whatever bytes arrived onto stdout (documented contract:
// "partial data on stdout must be distinguishable from success via the exit
// code" — spec.md US5 edge cases), report a stderr notice, and exit 6, not
// silently succeed or lose the partial output.
func TestAuditExport_InterruptedStream_ExitConn(t *testing.T) {
	t.Setenv("VEYPORT_TOKEN", "")

	const partial = `{"manifest":{"generated_at":"2026-08-05T00:00:00Z"`

	mux := http.NewServeMux()
	mountRefresh(mux, "access-1", "refresh-2")
	mux.HandleFunc("GET /api/audit-logs/export", func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("response writer does not support hijacking")
		}
		conn, bufrw, err := hj.Hijack()
		if err != nil {
			t.Fatalf("hijack: %v", err)
		}
		defer conn.Close()

		// Promise more bytes than are actually sent (Content-Length lies),
		// then close the connection: the client's body reader observes an
		// unexpected EOF mid-stream, after the partial body already
		// reached its buffer.
		_, _ = bufrw.WriteString("HTTP/1.1 200 OK\r\n")
		_, _ = bufrw.WriteString("Content-Type: application/json\r\n")
		_, _ = bufrw.WriteString("Content-Length: 4096\r\n\r\n")
		_, _ = bufrw.WriteString(partial)
		_ = bufrw.Flush()
		// conn.Close() via defer: truncates the promised body.
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	configDir := t.TempDir()
	seedSession(t, configDir, srv.URL, auth.StoredSession{
		RefreshToken: "refresh-1",
		Username:     "alice",
		Role:         "admin",
		ObtainedAt:   time.Now(),
	})

	ctx, stdout, stderr := newCmdContext(srv.URL, configDir, false, []string{"export"})
	code := RunAudit(ctx)

	if code != cmdutil.ExitConn {
		t.Fatalf("exit code = %d, want %d (ExitConn); stdout=%q stderr=%q", code, cmdutil.ExitConn, stdout.String(), stderr.String())
	}
	// Partial data allowed on stdout (documented contract), never silently
	// discarded: whatever arrived before the drop must still be there.
	if !bytes.Equal(stdout.Bytes(), []byte(partial)) {
		t.Errorf("stdout = %q, want the partial body %q preserved", stdout.String(), partial)
	}
	if stderr.Len() == 0 {
		t.Error("stderr empty on interrupted stream, want a notice")
	}
}

// TestAuditExport_NoArgs_ExitUsage covers `vey audit export` taking no
// positional arguments: the bare "audit" invocation (no "export"
// subcommand) is a usage error.
func TestAuditExport_NoArgs_ExitUsage(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/audit-logs/export", func(w http.ResponseWriter, r *http.Request) {
		t.Error("hub should not be called on a usage error")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	configDir := t.TempDir()
	ctx, stdout, stderr := newCmdContext(srv.URL, configDir, false, nil)
	code := RunAudit(ctx)

	if code != cmdutil.ExitUsage {
		t.Fatalf("exit code = %d, want %d (ExitUsage); stderr=%q", code, cmdutil.ExitUsage, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout not empty on usage error: %q", stdout.String())
	}
}

// TestAuditExport_ExtraArgs_ExitUsage covers "extra args → exit 2": `vey
// audit export <anything>` is rejected before the hub is ever contacted.
func TestAuditExport_ExtraArgs_ExitUsage(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/audit-logs/export", func(w http.ResponseWriter, r *http.Request) {
		t.Error("hub should not be called on a usage error")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	configDir := t.TempDir()
	ctx, stdout, stderr := newCmdContext(srv.URL, configDir, false, []string{"export", "unexpected"})
	code := RunAudit(ctx)

	if code != cmdutil.ExitUsage {
		t.Fatalf("exit code = %d, want %d (ExitUsage); stderr=%q", code, cmdutil.ExitUsage, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout not empty on usage error: %q", stdout.String())
	}
}

// TestAuditExport_NoHubExitUsage covers RunAudit's RequireHub failure
// branch.
func TestAuditExport_NoHubExitUsage(t *testing.T) {
	t.Setenv("VEYPORT_TOKEN", "")
	ctx, stdout, stderr := newCmdContext("", t.TempDir(), false, []string{"export"})
	code := RunAudit(ctx)
	if code != cmdutil.ExitUsage {
		t.Fatalf("exit code = %d, want %d (ExitUsage); stdout=%q stderr=%q", code, cmdutil.ExitUsage, stdout.String(), stderr.String())
	}
}

// TestAuditExport_AuthContextFailure covers RunAudit's newAuthContext error
// branch via a malformed VEYPORT_TOKEN.
func TestAuditExport_AuthContextFailure(t *testing.T) {
	t.Setenv("VEYPORT_TOKEN", "malformed-token")
	srv := httptest.NewServer(http.NewServeMux())
	defer srv.Close()

	ctx, stdout, stderr := newCmdContext(srv.URL, t.TempDir(), false, []string{"export"})
	code := RunAudit(ctx)
	if code != cmdutil.ExitUsage {
		t.Fatalf("exit code = %d, want %d (ExitUsage); stdout=%q stderr=%q", code, cmdutil.ExitUsage, stdout.String(), stderr.String())
	}
}
