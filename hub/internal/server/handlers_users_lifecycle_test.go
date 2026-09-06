package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/lockout"
	"github.com/wyiu/veyport/hub/internal/model"
)

// Account-lifecycle handler tests (tasks T011, T017 and the users-handler half
// of T019). Every case drives the real route table, so the admin-only guard,
// the path pattern and the JSON shape are all under test alongside the handler
// body; the two cases that cannot be reached through the router (the last-admin
// race) call the handler directly with a caller identity in the context, which
// is exactly the state a concurrent pair of disables produces.

const (
	lifecycleStatusSuffix    = "/status"
	lifecycleUnlockSuffix    = "/unlock"
	lifecycleExemptSuffix    = "/dormancy-exemption"
	lifecycleSelfDisableMsg  = "cannot disable your own account"
	lifecycleLastAdminMsg    = "cannot disable the last enabled administrator"
	lifecycleNotAdminMsg     = "dormancy exemption applies to administrator accounts only"
	lifecycleUserNotFoundMsg = "user not found"
	lifecycleUnknownID       = "00000000-0000-0000-0000-000000000000"
	lifecycleViewerName      = "lifecycleviewer"
	lifecycleExpected403     = "expected 403, got %d: %s"
	lifecycleExpected404     = "expected 404, got %d: %s"
	lifecycleExpected409     = "expected 409, got %d: %s"
	lifecycleGetUserErr      = "get user %s: %v"
)

// lifecycleFixture is the common starting point: a hub with a registered admin
// and one viewer account created through the admin API.
type lifecycleFixture struct {
	s          *Server
	adminToken string
	adminID    string
	viewerID   string
	viewerPass string
}

func newLifecycleFixture(t *testing.T) *lifecycleFixture {
	t.Helper()
	s := testServer(t)
	adminToken := registerAndGetAdminToken(t, s)

	admin, err := s.store.GetUserByUsername("admin")
	if err != nil {
		t.Fatalf("get admin: %v", err)
	}

	viewerID, viewerPass := createLifecycleUser(t, s, adminToken, lifecycleViewerName, model.RoleViewer)

	return &lifecycleFixture{
		s:          s,
		adminToken: adminToken,
		adminID:    admin.ID,
		viewerID:   viewerID,
		viewerPass: viewerPass,
	}
}

// createLifecycleUser creates an account through POST /api/users and returns
// its id and temporary password.
func createLifecycleUser(t *testing.T, s *Server, adminToken, username string, role model.Role) (userID, tempPassword string) {
	t.Helper()
	req := httptest.NewRequest("POST", testUsersPath, mustJSON(t, model.CreateUserRequest{
		Username: username,
		Email:    username + "@test.com",
		Role:     role,
	}))
	req.Header.Set("Authorization", testBearerPrefix+adminToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create user %s: expected 201, got %d: %s", username, rec.Code, rec.Body.String())
	}
	var created model.CreateUserResponse
	if err := json.NewDecoder(rec.Body).Decode(&created); err != nil {
		t.Fatalf(testDecodeRespErr, err)
	}
	return created.User.ID, created.TemporaryPassword
}

// lifecycleRequest issues an authenticated request through the router.
func lifecycleRequest(t *testing.T, s *Server, method, path, token string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	if body == nil {
		req = httptest.NewRequest(method, path, nil)
	} else if raw, ok := body.(string); ok {
		req = httptest.NewRequest(method, path, strings.NewReader(raw))
	} else {
		req = httptest.NewRequest(method, path, mustJSON(t, body))
	}
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)
	return rec
}

func putStatus(t *testing.T, s *Server, token, userID string, disabled bool) *httptest.ResponseRecorder {
	t.Helper()
	return lifecycleRequest(t, s, "PUT", testUsersPrefix+userID+lifecycleStatusSuffix, token,
		model.UpdateUserStatusRequest{Disabled: disabled})
}

func postUnlock(t *testing.T, s *Server, token, userID string) *httptest.ResponseRecorder {
	t.Helper()
	return lifecycleRequest(t, s, "POST", testUsersPrefix+userID+lifecycleUnlockSuffix, token, nil)
}

func putExemption(t *testing.T, s *Server, token, userID string, exempt bool) *httptest.ResponseRecorder {
	t.Helper()
	return lifecycleRequest(t, s, "PUT", testUsersPrefix+userID+lifecycleExemptSuffix, token,
		model.SetDormancyExemptRequest{Exempt: exempt})
}

// decodeUser reads the {"user": …} envelope every lifecycle endpoint returns.
func decodeUser(t *testing.T, rec *httptest.ResponseRecorder) model.User {
	t.Helper()
	var resp model.UserResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf(testDecodeRespErr, err)
	}
	if resp.User == nil {
		t.Fatal("expected a user in the response body")
	}
	return *resp.User
}

// errorMessage reads the {"error": …} envelope.
func errorMessage(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var resp map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf(testDecodeRespErr, err)
	}
	return resp["error"]
}

// storedUser reloads an account from the store.
func storedUser(t *testing.T, s *Server, userID string) *model.User {
	t.Helper()
	user, err := s.store.GetUserByID(userID)
	if err != nil {
		t.Fatalf(lifecycleGetUserErr, userID, err)
	}
	return user
}

// mintAPIToken creates an active API token for a user and returns its id.
func mintAPIToken(t *testing.T, s *Server, userID, name string) string {
	t.Helper()
	_, hash, prefix, err := auth.GenerateAPIToken()
	if err != nil {
		t.Fatalf("generate api token: %v", err)
	}
	id := uuid.NewString()
	if err := s.store.CreateAPIToken(&model.APIToken{
		ID:          id,
		UserID:      userID,
		Name:        name,
		TokenHash:   hash,
		TokenPrefix: prefix,
	}); err != nil {
		t.Fatalf("create api token: %v", err)
	}
	return id
}

// activeTokenCount counts a user's unrevoked API tokens.
func activeTokenCount(t *testing.T, s *Server, userID string) int {
	t.Helper()
	tokens, err := s.store.ListAPITokensByUserID(userID)
	if err != nil {
		t.Fatalf("list api tokens: %v", err)
	}
	active := 0
	for _, token := range tokens {
		if token.RevokedAt == nil {
			active++
		}
	}
	return active
}

// lockAccount drives one credential failure under a threshold-1 policy so the
// account ends up genuinely locked by the 007 path.
func lockAccount(t *testing.T, s *Server, userID string) {
	t.Helper()
	policy := lockout.Policy{Threshold: 1, Window: time.Hour, Duration: time.Hour}
	res, err := s.store.RecordLoginFailure(userID, s.now(), policy)
	if err != nil {
		t.Fatalf("record login failure: %v", err)
	}
	if !res.NewlyLocked {
		t.Fatal("expected the account to lock on the first failure under a threshold of 1")
	}
}

// singleAuditEntry asserts exactly one entry exists for the action and returns it.
func singleAuditEntry(t *testing.T, s *Server, userID, action string) model.AuditEntry {
	t.Helper()
	entries := auditEntriesFor(t, s, userID, action)
	if len(entries) != 1 {
		t.Fatalf("expected exactly 1 %s audit entry, got %d", action, len(entries))
	}
	return entries[0]
}

// assertAuditTarget checks the actor/target pairing shared by every lifecycle event.
func assertAuditTarget(t *testing.T, entry model.AuditEntry, actorID, targetID string) {
	t.Helper()
	if entry.UserID == nil || *entry.UserID != actorID {
		t.Fatalf("expected audit actor %s, got %v", actorID, entry.UserID)
	}
	if entry.Target == nil || *entry.Target != targetID {
		t.Fatalf("expected audit target %s, got %v", targetID, entry.Target)
	}
}

// ---------------------------------------------------------------------------
// T011 — PUT /api/users/{id}/status
// ---------------------------------------------------------------------------

// TestUpdateUserStatus_DisableRevokesAccess covers the whole disable side
// effect in one pass: the response, the persisted markers, the generation bump
// that kills sessions, the API-token revocation, and the audit entry that
// records how many tokens went with it (FR-002, FR-003, FR-011).
func TestUpdateUserStatus_DisableRevokesAccess(t *testing.T) {
	f := newLifecycleFixture(t)

	mintAPIToken(t, f.s, f.viewerID, "token-a")
	mintAPIToken(t, f.s, f.viewerID, "token-b")
	otherID, _ := createLifecycleUser(t, f.s, f.adminToken, "bystander", model.RoleViewer)
	mintAPIToken(t, f.s, otherID, "bystander-token")

	before := storedUser(t, f.s, f.viewerID)

	rec := putStatus(t, f.s, f.adminToken, f.viewerID, true)
	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}

	body := decodeUser(t, rec)
	if body.Status != "disabled" {
		t.Fatalf("expected status \"disabled\" in the response, got %q", body.Status)
	}
	if body.DisabledAt == nil {
		t.Fatal("expected disabled_at in the response")
	}
	if body.DisabledBy == nil || *body.DisabledBy != f.adminID {
		t.Fatalf("expected disabled_by %s, got %v", f.adminID, body.DisabledBy)
	}

	after := storedUser(t, f.s, f.viewerID)
	if after.TokenGeneration != before.TokenGeneration+1 {
		t.Fatalf("expected token_generation %d, got %d", before.TokenGeneration+1, after.TokenGeneration)
	}
	if got := activeTokenCount(t, f.s, f.viewerID); got != 0 {
		t.Fatalf("expected all API tokens revoked, %d still active", got)
	}
	if got := activeTokenCount(t, f.s, otherID); got != 1 {
		t.Fatalf("expected another user's token untouched, got %d active", got)
	}

	entry := singleAuditEntry(t, f.s, f.adminID, model.AuditUserDisabled)
	assertAuditTarget(t, entry, f.adminID, f.viewerID)
	if entry.Detail == nil {
		t.Fatal("expected a detail on the user.disabled audit entry")
	}
	var detail struct {
		RevokedAPITokens int `json:"revoked_api_tokens"`
	}
	if err := json.Unmarshal([]byte(*entry.Detail), &detail); err != nil {
		t.Fatalf("decode user.disabled detail %q: %v", *entry.Detail, err)
	}
	if detail.RevokedAPITokens != 2 {
		t.Fatalf("expected revoked_api_tokens 2, got %d", detail.RevokedAPITokens)
	}
}

// TestUpdateUserStatus_DisableIsIdempotent pins the contract's idempotency
// row: a second disable changes nothing but is still answered 200 and still
// audited, so a retried request never looks like a failure.
func TestUpdateUserStatus_DisableIsIdempotent(t *testing.T) {
	f := newLifecycleFixture(t)

	if rec := putStatus(t, f.s, f.adminToken, f.viewerID, true); rec.Code != http.StatusOK {
		t.Fatalf("first disable: %s", rec.Body.String())
	}
	first := storedUser(t, f.s, f.viewerID)

	rec := putStatus(t, f.s, f.adminToken, f.viewerID, true)
	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}
	if body := decodeUser(t, rec); body.Status != "disabled" {
		t.Fatalf("expected status \"disabled\", got %q", body.Status)
	}

	second := storedUser(t, f.s, f.viewerID)
	if second.TokenGeneration != first.TokenGeneration {
		t.Fatalf("expected token_generation unchanged at %d, got %d", first.TokenGeneration, second.TokenGeneration)
	}
	if !second.DisabledAt.Equal(*first.DisabledAt) {
		t.Fatalf("expected disabled_at unchanged at %s, got %s", first.DisabledAt, second.DisabledAt)
	}
	if got := len(auditEntriesFor(t, f.s, f.adminID, model.AuditUserDisabled)); got != 2 {
		t.Fatalf("expected 2 user.disabled audit entries, got %d", got)
	}
}

// TestUpdateUserStatus_EnableClearsLockAndCount covers FR-004: enabling clears
// the disabled marker, the lock and the failure count, and stamps the
// reactivation time the dormancy clock reads.
func TestUpdateUserStatus_EnableClearsLockAndCount(t *testing.T) {
	f := newLifecycleFixture(t)

	lockAccount(t, f.s, f.viewerID)
	if rec := putStatus(t, f.s, f.adminToken, f.viewerID, true); rec.Code != http.StatusOK {
		t.Fatalf("disable: %s", rec.Body.String())
	}

	rec := putStatus(t, f.s, f.adminToken, f.viewerID, false)
	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}

	body := decodeUser(t, rec)
	if body.Status != "active" {
		t.Fatalf("expected status \"active\", got %q", body.Status)
	}
	if body.ReactivatedAt == nil {
		t.Fatal("expected reactivated_at in the response")
	}

	after := storedUser(t, f.s, f.viewerID)
	if after.DisabledAt != nil || after.DisabledBy != nil {
		t.Fatalf("expected the disabled markers cleared, got %v / %v", after.DisabledAt, after.DisabledBy)
	}
	if after.LockedUntil != nil {
		t.Fatalf("expected locked_until cleared, got %s", after.LockedUntil)
	}
	if after.FailedLoginCount != 0 {
		t.Fatalf("expected failed_login_count 0, got %d", after.FailedLoginCount)
	}

	entry := singleAuditEntry(t, f.s, f.adminID, model.AuditUserEnabled)
	assertAuditTarget(t, entry, f.adminID, f.viewerID)
	if entry.Detail == nil {
		t.Fatal("expected a detail on the user.enabled audit entry")
	}
	var detail struct {
		WasDisabled bool `json:"was_disabled"`
	}
	if err := json.Unmarshal([]byte(*entry.Detail), &detail); err != nil {
		t.Fatalf("decode user.enabled detail %q: %v", *entry.Detail, err)
	}
	if !detail.WasDisabled {
		t.Fatal("expected was_disabled true on the user.enabled audit entry")
	}
}

// TestUpdateUserStatus_SelfDisableRefused pins the self-disable guard and its
// exact wording — an administrator must not be able to lock themselves out.
func TestUpdateUserStatus_SelfDisableRefused(t *testing.T) {
	f := newLifecycleFixture(t)

	rec := putStatus(t, f.s, f.adminToken, f.adminID, true)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf(testExpected400Body, rec.Code, rec.Body.String())
	}
	if msg := errorMessage(t, rec); msg != lifecycleSelfDisableMsg {
		t.Fatalf("expected %q, got %q", lifecycleSelfDisableMsg, msg)
	}
	if storedUser(t, f.s, f.adminID).DisabledAt != nil {
		t.Fatal("the administrator's own account was disabled despite the guard")
	}
}

// TestUpdateUserStatus_SelfEnableAllowed shows the self guard is scoped to
// disabling: enabling one's own (already enabled) account is harmless and must
// not be refused by the same check.
func TestUpdateUserStatus_SelfEnableAllowed(t *testing.T) {
	f := newLifecycleFixture(t)

	rec := putStatus(t, f.s, f.adminToken, f.adminID, false)
	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}
}

// TestUpdateUserStatus_LastAdminRefused covers the guard that keeps a hub
// administrable. The scenario is the one a concurrent pair of disables
// produces: the caller's own account has already been disabled by the time
// their request runs, leaving the target as the only enabled administrator.
// It is driven through the handler directly because the middleware would
// (correctly) refuse the caller's now-dead credential.
func TestUpdateUserStatus_LastAdminRefused(t *testing.T) {
	f := newLifecycleFixture(t)

	secondAdminID, _ := createLifecycleUser(t, f.s, f.adminToken, "secondadmin", model.RoleAdmin)
	if _, err := f.s.store.DisableUser(f.adminID, secondAdminID, f.s.now()); err != nil {
		t.Fatalf("disable the first admin: %v", err)
	}

	req := httptest.NewRequest("PUT", testUsersPrefix+secondAdminID+lifecycleStatusSuffix,
		mustJSON(t, model.UpdateUserStatusRequest{Disabled: true}))
	req.SetPathValue("id", secondAdminID)
	req = req.WithContext(context.WithValue(req.Context(), ctxUserID, f.adminID))
	rec := httptest.NewRecorder()
	f.s.handleUpdateUserStatus(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf(lifecycleExpected409, rec.Code, rec.Body.String())
	}
	if msg := errorMessage(t, rec); msg != lifecycleLastAdminMsg {
		t.Fatalf("expected %q, got %q", lifecycleLastAdminMsg, msg)
	}
	if storedUser(t, f.s, secondAdminID).DisabledAt != nil {
		t.Fatal("the last enabled administrator was disabled despite the guard")
	}
}

// TestUpdateUserStatus_NonAdminRefused pins FR-015: lifecycle actions are
// administrator-only, enforced by the route rather than the handler.
func TestUpdateUserStatus_NonAdminRefused(t *testing.T) {
	f := newLifecycleFixture(t)
	viewerToken := createViewerAndGetToken(t, f.s, f.adminToken)

	rec := putStatus(t, f.s, viewerToken, f.viewerID, true)
	if rec.Code != http.StatusForbidden {
		t.Fatalf(lifecycleExpected403, rec.Code, rec.Body.String())
	}
	if storedUser(t, f.s, f.viewerID).DisabledAt != nil {
		t.Fatal("a viewer managed to disable an account")
	}
}

// TestUpdateUserStatus_UnknownUser covers the 404 row of the contract.
func TestUpdateUserStatus_UnknownUser(t *testing.T) {
	f := newLifecycleFixture(t)

	rec := putStatus(t, f.s, f.adminToken, lifecycleUnknownID, true)
	if rec.Code != http.StatusNotFound {
		t.Fatalf(lifecycleExpected404, rec.Code, rec.Body.String())
	}
	if msg := errorMessage(t, rec); msg != lifecycleUserNotFoundMsg {
		t.Fatalf("expected %q, got %q", lifecycleUserNotFoundMsg, msg)
	}
}

// TestUpdateUserStatus_BadBody covers both malformed JSON and a well-formed
// body that omits the field. The second is refused rather than defaulted:
// silently reading a missing "disabled" as false would turn a typo into an
// unintended enable.
func TestUpdateUserStatus_BadBody(t *testing.T) {
	f := newLifecycleFixture(t)

	for _, tc := range []struct {
		name string
		body string
	}{
		{"malformed json", testNotJSON},
		{"missing field", `{}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := lifecycleRequest(t, f.s, "PUT",
				testUsersPrefix+f.viewerID+lifecycleStatusSuffix, f.adminToken, tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf(testExpected400Body, rec.Code, rec.Body.String())
			}
			if storedUser(t, f.s, f.viewerID).DisabledAt != nil {
				t.Fatal("a rejected request still changed the account")
			}
		})
	}
}

// TestListUsers_CarriesDerivedStatus covers FR-008 on the wire: the admin list
// labels every account, including the ones this feature introduces.
func TestListUsers_CarriesDerivedStatus(t *testing.T) {
	f := newLifecycleFixture(t)

	lockedID, _ := createLifecycleUser(t, f.s, f.adminToken, "lockedviewer", model.RoleViewer)
	lockAccount(t, f.s, lockedID)
	if rec := putStatus(t, f.s, f.adminToken, f.viewerID, true); rec.Code != http.StatusOK {
		t.Fatalf("disable: %s", rec.Body.String())
	}

	rec := lifecycleRequest(t, f.s, "GET", testUsersPath, f.adminToken, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}
	var list model.UserListResponse
	if err := json.NewDecoder(rec.Body).Decode(&list); err != nil {
		t.Fatalf(testDecodeRespErr, err)
	}

	want := map[string]string{
		f.adminID:  "active",
		f.viewerID: "disabled",
		lockedID:   "locked",
	}
	seen := 0
	for _, u := range list.Users {
		expected, ok := want[u.ID]
		if !ok {
			continue
		}
		seen++
		if u.Status != expected {
			t.Errorf("user %s: expected status %q, got %q", u.Username, expected, u.Status)
		}
	}
	if seen != len(want) {
		t.Fatalf("expected %d known users in the list, found %d", len(want), seen)
	}
}

// ---------------------------------------------------------------------------
// T017 — POST /api/users/{id}/unlock
// ---------------------------------------------------------------------------

// TestUnlockUser_ClearsLock covers FR-005: an administrator can end a lockout
// before its expiry, and the action is audited as a real transition.
func TestUnlockUser_ClearsLock(t *testing.T) {
	f := newLifecycleFixture(t)
	lockAccount(t, f.s, f.viewerID)

	rec := postUnlock(t, f.s, f.adminToken, f.viewerID)
	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}

	body := decodeUser(t, rec)
	if body.Status != "active" {
		t.Fatalf("expected status \"active\", got %q", body.Status)
	}
	if body.ReactivatedAt == nil {
		t.Fatal("expected reactivated_at after a real unlock")
	}

	after := storedUser(t, f.s, f.viewerID)
	if after.LockedUntil != nil {
		t.Fatalf("expected locked_until cleared, got %s", after.LockedUntil)
	}
	if after.FailedLoginCount != 0 {
		t.Fatalf("expected failed_login_count 0, got %d", after.FailedLoginCount)
	}

	entry := singleAuditEntry(t, f.s, f.adminID, model.AuditUserUnlocked)
	assertAuditTarget(t, entry, f.adminID, f.viewerID)
	if entry.Detail == nil || !strings.Contains(*entry.Detail, `"was_locked":true`) {
		t.Fatalf("expected was_locked true in the audit detail, got %v", entry.Detail)
	}
}

// TestUnlockUser_IdempotentOnUnlocked pins the edge case: unlocking an account
// that is not locked succeeds and is audited, but must not touch the activity
// clock — otherwise an administrator could reset dormancy by clicking Unlock.
func TestUnlockUser_IdempotentOnUnlocked(t *testing.T) {
	f := newLifecycleFixture(t)
	before := storedUser(t, f.s, f.viewerID)

	rec := postUnlock(t, f.s, f.adminToken, f.viewerID)
	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}

	after := storedUser(t, f.s, f.viewerID)
	if before.ReactivatedAt == nil && after.ReactivatedAt != nil {
		t.Fatal("expected reactivated_at to stay unset when no lock was in force")
	}

	entry := singleAuditEntry(t, f.s, f.adminID, model.AuditUserUnlocked)
	if entry.Detail == nil || !strings.Contains(*entry.Detail, `"was_locked":false`) {
		t.Fatalf("expected was_locked false in the audit detail, got %v", entry.Detail)
	}
}

// TestUnlockUser_NonAdminRefused pins FR-015 for the unlock route.
func TestUnlockUser_NonAdminRefused(t *testing.T) {
	f := newLifecycleFixture(t)
	lockAccount(t, f.s, f.viewerID)
	viewerToken := createViewerAndGetToken(t, f.s, f.adminToken)

	rec := postUnlock(t, f.s, viewerToken, f.viewerID)
	if rec.Code != http.StatusForbidden {
		t.Fatalf(lifecycleExpected403, rec.Code, rec.Body.String())
	}
	if storedUser(t, f.s, f.viewerID).LockedUntil == nil {
		t.Fatal("a viewer managed to unlock an account")
	}
}

// TestUnlockUser_UnknownUser covers the 404 case.
func TestUnlockUser_UnknownUser(t *testing.T) {
	f := newLifecycleFixture(t)

	rec := postUnlock(t, f.s, f.adminToken, lifecycleUnknownID)
	if rec.Code != http.StatusNotFound {
		t.Fatalf(lifecycleExpected404, rec.Code, rec.Body.String())
	}
	if msg := errorMessage(t, rec); msg != lifecycleUserNotFoundMsg {
		t.Fatalf("expected %q, got %q", lifecycleUserNotFoundMsg, msg)
	}
}

// ---------------------------------------------------------------------------
// T019 (users-handler half) — PUT /api/users/{id}/dormancy-exemption
// ---------------------------------------------------------------------------

// TestSetDormancyExempt_ViewerRefused pins FR-017's restriction: the exemption
// exists to preserve an administrative recovery path, so it is meaningless —
// and refused — on a non-administrator.
func TestSetDormancyExempt_ViewerRefused(t *testing.T) {
	f := newLifecycleFixture(t)

	rec := putExemption(t, f.s, f.adminToken, f.viewerID, true)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf(testExpected400Body, rec.Code, rec.Body.String())
	}
	if msg := errorMessage(t, rec); msg != lifecycleNotAdminMsg {
		t.Fatalf("expected %q, got %q", lifecycleNotAdminMsg, msg)
	}
	if storedUser(t, f.s, f.viewerID).DormancyExempt {
		t.Fatal("a viewer was granted the dormancy exemption")
	}
}

// TestSetDormancyExempt_AdminSetAndClear walks both directions on an
// administrator account and checks each writes its own audit event.
func TestSetDormancyExempt_AdminSetAndClear(t *testing.T) {
	f := newLifecycleFixture(t)
	secondAdminID, _ := createLifecycleUser(t, f.s, f.adminToken, "exemptadmin", model.RoleAdmin)

	rec := putExemption(t, f.s, f.adminToken, secondAdminID, true)
	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}
	if body := decodeUser(t, rec); !body.DormancyExempt {
		t.Fatal("expected dormancy_exempt true in the response")
	}
	if !storedUser(t, f.s, secondAdminID).DormancyExempt {
		t.Fatal("expected dormancy_exempt persisted")
	}
	assertAuditTarget(t, singleAuditEntry(t, f.s, f.adminID, model.AuditUserDormancyExemptSet),
		f.adminID, secondAdminID)

	rec = putExemption(t, f.s, f.adminToken, secondAdminID, false)
	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}
	if body := decodeUser(t, rec); body.DormancyExempt {
		t.Fatal("expected dormancy_exempt false in the response")
	}
	assertAuditTarget(t, singleAuditEntry(t, f.s, f.adminID, model.AuditUserDormancyExemptCleared),
		f.adminID, secondAdminID)
}

// TestSetDormancyExempt_NonAdminAndUnknown covers the route guard and the 404.
func TestSetDormancyExempt_NonAdminAndUnknown(t *testing.T) {
	f := newLifecycleFixture(t)
	viewerToken := createViewerAndGetToken(t, f.s, f.adminToken)

	if rec := putExemption(t, f.s, viewerToken, f.adminID, true); rec.Code != http.StatusForbidden {
		t.Fatalf(lifecycleExpected403, rec.Code, rec.Body.String())
	}
	if rec := putExemption(t, f.s, f.adminToken, lifecycleUnknownID, true); rec.Code != http.StatusNotFound {
		t.Fatalf(lifecycleExpected404, rec.Code, rec.Body.String())
	}
}

// TestUpdateUserRole_ClearsExemptionOnDemotion covers R6: an exempt
// administrator demoted to a lesser role loses the exemption in the same
// request, with its own audit entry naming the cause.
func TestUpdateUserRole_ClearsExemptionOnDemotion(t *testing.T) {
	f := newLifecycleFixture(t)
	secondAdminID, _ := createLifecycleUser(t, f.s, f.adminToken, "demotedadmin", model.RoleAdmin)

	if rec := putExemption(t, f.s, f.adminToken, secondAdminID, true); rec.Code != http.StatusOK {
		t.Fatalf("set exemption: %s", rec.Body.String())
	}

	rec := lifecycleRequest(t, f.s, "PUT", testUsersPrefix+secondAdminID+"/role", f.adminToken,
		model.UpdateRoleRequest{Role: model.RoleViewer})
	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}
	if body := decodeUser(t, rec); body.DormancyExempt {
		t.Fatal("expected the exemption cleared in the role-change response")
	}
	if storedUser(t, f.s, secondAdminID).DormancyExempt {
		t.Fatal("expected the exemption cleared in the store")
	}

	entry := singleAuditEntry(t, f.s, f.adminID, model.AuditUserDormancyExemptCleared)
	assertAuditTarget(t, entry, f.adminID, secondAdminID)
	if entry.Detail == nil || *entry.Detail != "role changed" {
		t.Fatalf("expected detail %q, got %v", "role changed", entry.Detail)
	}
}

// TestUpdateUserRole_KeepsExemptionOnAdminRole is the negative half of R6: a
// role change that leaves the account an administrator must not disturb the
// exemption, and must not write a spurious cleared event.
func TestUpdateUserRole_KeepsExemptionOnAdminRole(t *testing.T) {
	f := newLifecycleFixture(t)
	secondAdminID, _ := createLifecycleUser(t, f.s, f.adminToken, "stayadmin", model.RoleAdmin)

	if rec := putExemption(t, f.s, f.adminToken, secondAdminID, true); rec.Code != http.StatusOK {
		t.Fatalf("set exemption: %s", rec.Body.String())
	}
	rec := lifecycleRequest(t, f.s, "PUT", testUsersPrefix+secondAdminID+"/role", f.adminToken,
		model.UpdateRoleRequest{Role: model.RoleAdmin})
	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}

	if !storedUser(t, f.s, secondAdminID).DormancyExempt {
		t.Fatal("expected the exemption to survive an admin → admin role change")
	}
	if got := len(auditEntriesFor(t, f.s, f.adminID, model.AuditUserDormancyExemptCleared)); got != 0 {
		t.Fatalf("expected no cleared audit entries, got %d", got)
	}
}
