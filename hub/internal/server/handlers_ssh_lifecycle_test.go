package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/account"
	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/model"
)

// T013 (HTTP half) — certificate issuance for an unusable account.
//
// Issuance is the moment the hub can bound the damage a disabled or dormant
// account can still do over SSH: certificates carry no revocation list, so the
// only two defences are refusing to mint new ones and re-checking at shell
// time (session_lifecycle_test.go covers the second).
//
// Two layers are asserted here. Through the router the request never reaches
// the handler at all — the authentication middleware rejects the access token
// with 401 and the account's own message. The handler nevertheless carries its
// own check, and that check is exercised directly, because it is what keeps
// issuance safe if the credential ever arrives by some other route.

// sshLifecycleState is one way of making the caller's account unusable.
type sshLifecycleState struct {
	name    string
	apply   func(t *testing.T, s *Server, userID string)
	message string
	detail  string
}

func sshLifecycleStates() []sshLifecycleState {
	return []sshLifecycleState{
		{
			name: "disabled",
			apply: func(t *testing.T, s *Server, userID string) {
				markDisabled(t, s, userID, time.Now().UTC())
			},
			message: account.MsgDisabled,
			detail:  detailAccountDisabled,
		},
		{
			name: "dormant",
			apply: func(t *testing.T, s *Server, userID string) {
				setDormantDays(t, s, 1)
				clearDormancyExempt(t, s, userID)
				backdateActivity(t, s, userID, time.Now().UTC().Add(-48*time.Hour))
			},
			message: account.MsgDormant,
			detail:  detailAccountDormant,
		},
	}
}

// postSSHCertAsUser drives the issuance handler directly with an authenticated
// identity, bypassing the middleware so the handler's own guard is what answers.
func postSSHCertAsUser(t *testing.T, s *Server, userID string, publicKey string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", testSSHCertPath, mustJSON(t, map[string]string{"public_key": publicKey}))
	ctx := context.WithValue(req.Context(), ctxUserID, userID)
	ctx = context.WithValue(ctx, ctxTokenType, auth.TokenTypeAccess)
	rec := httptest.NewRecorder()
	s.handleIssueSSHCertificate(rec, req.WithContext(ctx))
	return rec
}

// assertSSHIssuanceRefused checks the refusal audit entry for one unusable-
// account state: exactly one entry, naming the account state, marked as a
// failure, and confirms no certificate was issued alongside the refusal.
func assertSSHIssuanceRefused(t *testing.T, s *Server, admin *model.User, state sshLifecycleState) {
	t.Helper()
	entries := auditEntriesFor(t, s, admin.ID, model.AuditSSHCertIssueRefused)
	if len(entries) != 1 {
		t.Fatalf("expected one %s entry, got %d", model.AuditSSHCertIssueRefused, len(entries))
	}
	if entries[0].Detail == nil || !strings.Contains(*entries[0].Detail, state.detail) {
		t.Fatalf("audit detail = %v, want it to name %q", entries[0].Detail, state.detail)
	}
	if entries[0].Outcome != model.AuditOutcomeFailure {
		t.Fatalf("audit outcome = %q, want %q", entries[0].Outcome, model.AuditOutcomeFailure)
	}
	if got := countSSHAuditAction(t, s, model.AuditSSHCertIssued); got != 0 {
		t.Fatalf("a refused request issued %d certificates", got)
	}
}

// The handler refuses issuance with 403 and the canonical message, and records
// the refusal as ssh.cert_issue_refused naming the account state.
func TestSSHCertLifecycle_UnusableAccountRefused(t *testing.T) {
	for _, state := range sshLifecycleStates() {
		t.Run(state.name, func(t *testing.T) {
			s, _ := testSSHServer(t)
			_ = registerAndGetAdminToken(t, s)
			admin, err := s.store.GetUserByUsername(testSSHAdminUsername)
			if err != nil {
				t.Fatalf("get admin user: %v", err)
			}
			state.apply(t, s, admin.ID)

			rec := postSSHCertAsUser(t, s, admin.ID, testSSHClientPublicKey(t))
			assertRefused(t, rec, http.StatusForbidden, state.message, "certificate issuance")

			assertSSHIssuanceRefused(t, s, admin, state)
		})
	}
}

// Through the full router the middleware answers first, so the operator sees a
// 401 carrying the same account message rather than the handler's 403. Pinning
// it here keeps the CLI's mapping honest about what it will actually receive.
func TestSSHCertLifecycle_RouterRefusesBeforeTheHandler(t *testing.T) {
	for _, state := range sshLifecycleStates() {
		t.Run(state.name, func(t *testing.T) {
			s, _ := testSSHServer(t)
			token := registerAndGetAdminToken(t, s)
			admin, err := s.store.GetUserByUsername(testSSHAdminUsername)
			if err != nil {
				t.Fatalf("get admin user: %v", err)
			}
			state.apply(t, s, admin.ID)

			rec := postSSHCert(t, s.routes(), token, map[string]string{"public_key": testSSHClientPublicKey(t)})
			assertRefused(t, rec, http.StatusUnauthorized, state.message, "certificate issuance via router")

			if got := countSSHAuditAction(t, s, model.AuditSSHCertIssued); got != 0 {
				t.Fatalf("a refused request issued %d certificates", got)
			}
		})
	}
}

// A usable account still gets a certificate: the guard must not have made
// issuance conditional on anything else.
func TestSSHCertLifecycle_UsableAccountStillIssued(t *testing.T) {
	s, _ := testSSHServer(t)
	token := registerAndGetAdminToken(t, s)

	rec := postSSHCert(t, s.routes(), token, map[string]string{"public_key": testSSHClientPublicKey(t)})
	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}
}
