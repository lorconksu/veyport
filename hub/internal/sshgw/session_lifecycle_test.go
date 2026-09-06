package sshgw

import (
	"strings"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/account"
	"github.com/wyiu/veyport/hub/internal/lockout"
	"github.com/wyiu/veyport/hub/internal/model"
)

// T013 (gateway half) — a certificate outliving its account's usability.
//
// The gateway publishes no revocation list, so a certificate minted before an
// account was disabled stays cryptographically valid and authentication still
// succeeds. What must not happen is a shell: the account's live status is
// re-read at shell time, exactly as the deleted-account case in authz_test.go
// re-reads existence. Without this, disabling an operator would leave them
// with shell access for the remaining lifetime of their certificate.

// sqliteTimeLayout is how the store writes timestamps; these tests set the
// lifecycle columns directly, so they have to match it.
const sqliteTimeLayout = "2006-01-02 15:04:05"

// disableAccount marks the fixture's user disabled in the database.
func (f *fixture) disableAccount(t *testing.T, userID string) {
	t.Helper()
	if _, err := f.store.DB().Exec(
		`UPDATE users SET disabled_at = ?, disabled_by = ? WHERE id = ?`,
		time.Now().UTC().Format(sqliteTimeLayout), "admin-actor", userID,
	); err != nil {
		t.Fatalf("disable user %s: %v", userID, err)
	}
}

// enableAccount clears the disable, the way an administrator's enable would.
func (f *fixture) enableAccount(t *testing.T, userID string) {
	t.Helper()
	if _, err := f.store.DB().Exec(
		`UPDATE users SET disabled_at = NULL, disabled_by = NULL, reactivated_at = ? WHERE id = ?`,
		time.Now().UTC().Format(sqliteTimeLayout), userID,
	); err != nil {
		t.Fatalf("enable user %s: %v", userID, err)
	}
}

// makeDormant sets a one-day dormancy window and moves every point on the
// account's activity clock two days into the past. All three columns move
// together because the derived status takes the latest of them.
func (f *fixture) makeDormant(t *testing.T, userID string) {
	t.Helper()
	if err := f.store.SetConfig(lockout.KeyDormantDays, "1"); err != nil {
		t.Fatalf("set dormant days: %v", err)
	}
	stamp := time.Now().UTC().Add(-48 * time.Hour).Format(sqliteTimeLayout)
	if _, err := f.store.DB().Exec(
		`UPDATE users SET created_at = ?, last_activity_at = ?, reactivated_at = ? WHERE id = ?`,
		stamp, stamp, stamp, userID,
	); err != nil {
		t.Fatalf("back-date activity for user %s: %v", userID, err)
	}
}

// assertShellRefusedForAccount runs one shell request that must be refused and
// checks the operator's message, the exit status, that no terminal was opened
// on the agent, and the audit trail's reason.
func assertShellRefusedForAccount(t *testing.T, f *fixture, wantMessage, wantReason string) {
	t.Helper()
	stderr, status := f.runRefusedShell(testUsername + "+" + testServerName)

	if !strings.Contains(stderr, wantMessage) {
		t.Errorf("operator message = %q, want it to contain %q", stderr, wantMessage)
	}
	if !strings.Contains(stderr, "veyport: ") {
		t.Errorf("operator message = %q, want the veyport prefix", stderr)
	}
	if status == 0 {
		t.Error("refused session exited 0, want a non-zero status")
	}
	if got := countOpenRequests(f.agent.messages()); got != 0 {
		t.Errorf("the agent received %d TerminalOpenRequests, want none", got)
	}

	entry := f.waitForAudit(model.AuditSSHSessionRefused)
	if entry.Outcome != model.AuditOutcomeFailure {
		t.Errorf("audit outcome = %q, want %q", entry.Outcome, model.AuditOutcomeFailure)
	}
	if entry.Detail == nil || !strings.Contains(*entry.Detail, wantReason) {
		t.Errorf("audit detail = %v, want it to carry %q", entry.Detail, wantReason)
	}
	if entry.UserID == nil || *entry.UserID != testUserID {
		t.Errorf("audit user = %v, want %q", entry.UserID, testUserID)
	}
	if len(f.auditEntries(model.AuditSSHSessionOpened)) != 0 {
		t.Error("a refused session was audited as ssh.session_opened")
	}
}

// A valid certificate held by a disabled account opens no shell.
func TestGatewayRefusesDisabledAccountWithValidCertificate(t *testing.T) {
	f := newFixture(t, nil)
	f.connectAgent()
	f.start()
	f.disableAccount(t, testUserID)

	assertShellRefusedForAccount(t, f, account.MsgDisabled, "reason=account_disabled")
}

// The same for an account that has gone dormant: inactivity refuses the shell
// even though the certificate and the assignment are both still good.
func TestGatewayRefusesDormantAccountWithValidCertificate(t *testing.T) {
	f := newFixture(t, nil)
	f.connectAgent()
	f.start()
	f.makeDormant(t, testUserID)

	assertShellRefusedForAccount(t, f, account.MsgDormant, "reason=account_dormant")
}

// Re-enabling the account restores the shell on the next request, with no new
// certificate needed: the decision was never cached.
func TestGatewayAllowsShellAfterAccountIsEnabled(t *testing.T) {
	f := newFixture(t, nil)
	f.connectAgent()
	f.start()
	f.disableAccount(t, testUserID)

	assertShellRefusedForAccount(t, f, account.MsgDisabled, "reason=account_disabled")

	f.enableAccount(t, testUserID)

	client := f.mustDial(testUsername + "+" + testServerName)
	sess, _, _ := startPTYShell(t, client)
	defer func() { _ = sess.Close() }()

	f.assertOpenRequestGeometry(t, 80, 24)
}
