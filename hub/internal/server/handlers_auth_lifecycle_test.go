package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/wyiu/veyport/hub/internal/account"
	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/model"
)

// T012 — the account-lifecycle enforcement matrix on the authentication paths.
//
// The claim under test is FR-009: an account that is disabled or dormant is
// refused at EVERY path, including the ones a credential it already holds
// would otherwise open. Each state is driven through the same matrix — both
// sign-in stages, refresh, an access token and an API token — so a path that
// forgets the check fails here rather than in production.
//
// The states are set by writing the underlying columns directly. That is
// deliberate: enforcement has to hold on the stored data alone, independently
// of the administrative endpoints that normally write it.

// authLifecycleUsername is the fixture account every matrix runs against.
const authLifecycleUsername = "vera"

// authLifecycleState is one account state that must refuse access everywhere,
// together with the wording and audit detail it is refused with.
type authLifecycleState struct {
	name    string
	apply   func(t *testing.T, f *authLifecycleFixture)
	restore func(t *testing.T, f *authLifecycleFixture)
	message string
	detail  string
}

// refusingAccountStates are the two states FR-009 covers. Every test in this file
// runs its whole matrix against both, so disabled and dormant cannot drift
// apart in behaviour — only in wording.
func refusingAccountStates() []authLifecycleState {
	return []authLifecycleState{
		{
			name: "disabled",
			apply: func(t *testing.T, f *authLifecycleFixture) {
				markDisabled(t, f.s, f.user.ID, f.clk.now())
			},
			restore: func(t *testing.T, f *authLifecycleFixture) {
				clearDisabled(t, f.s, f.user.ID, f.clk.now())
			},
			message: account.MsgDisabled,
			detail:  detailAccountDisabled,
		},
		{
			name: "dormant",
			apply: func(t *testing.T, f *authLifecycleFixture) {
				setDormantDays(t, f.s, 1)
				backdateActivity(t, f.s, f.user.ID, f.clk.now().Add(-48*time.Hour))
			},
			restore: func(t *testing.T, f *authLifecycleFixture) {
				setLastActivity(t, f.s, f.user.ID, f.clk.now())
			},
			message: account.MsgDormant,
			detail:  detailAccountDormant,
		},
	}
}

// authLifecycleFixture is a signed-in viewer holding every kind of credential the
// hub issues, all minted while the account was still usable.
type authLifecycleFixture struct {
	s            *Server
	clk          *testClock
	user         *model.User
	totpSecret   string
	accessToken  string
	refreshToken string
	apiToken     string
	apiTokenID   string
}

// newAuthLifecycleFixture creates the account and issues its credentials.
//
// The token pair is generated the same way the code stage generates it rather
// than by completing a sign-in, so the account's one-time-code replay window is
// left untouched and the code stage can still be exercised below.
func newAuthLifecycleFixture(t *testing.T) *authLifecycleFixture {
	t.Helper()
	s, clk := lockoutServer(t)
	setLockoutPolicy(t, s, 5, 15, 15)

	user := newLocalUser(t, s, authLifecycleUsername, lockoutTestPassword)
	f := &authLifecycleFixture{s: s, clk: clk, user: user}
	f.totpSecret = enableTOTPForUser(t, s, user)

	// Bound to a session, as a completed sign-in binds them: 009 refuses a
	// token that carries none, and this fixture's whole point is that the
	// credentials were valid before the account state changed.
	access, refresh, _ := sessionTokenPair(t, s, user.ID)
	f.accessToken, f.refreshToken = access, refresh
	f.apiToken, f.apiTokenID = f.mintAPIToken(t, "automation")
	return f
}

// mintAPIToken creates an API token for the fixture's user.
func (f *authLifecycleFixture) mintAPIToken(t *testing.T, name string) (raw, id string) {
	t.Helper()
	raw, hash, prefix, err := auth.GenerateAPIToken()
	if err != nil {
		t.Fatalf("generate api token: %v", err)
	}
	id = uuid.NewString()
	if err := f.s.store.CreateAPIToken(&model.APIToken{
		ID: id, UserID: f.user.ID, Name: name, TokenHash: hash, TokenPrefix: prefix,
	}); err != nil {
		t.Fatalf("create api token: %v", err)
	}
	return raw, id
}

// reload returns the account's persisted state.
func (f *authLifecycleFixture) reload(t *testing.T) *model.User {
	t.Helper()
	return reloadUser(t, f.s, f.user.ID)
}

// bearer issues an authenticated request through the full router.
func (f *authLifecycleFixture) bearer(t *testing.T, method, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	f.s.routes().ServeHTTP(rec, req)
	return rec
}

// refresh posts the fixture's refresh token to the refresh handler.
func (f *authLifecycleFixture) refresh(t *testing.T) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", testRefreshPath,
		mustJSON(t, model.RefreshRequest{RefreshToken: f.refreshToken}))
	rec := httptest.NewRecorder()
	f.s.handleRefresh(rec, req)
	return rec
}

// totpStageToken completes the password stage and returns the one-time-code
// token it hands out — a credential issued while the account was usable.
func (f *authLifecycleFixture) totpStageToken(t *testing.T) string {
	t.Helper()
	return primaryLoginTOTPToken(t, f.s, f.user.Username, lockoutTestPassword)
}

// apiTokenRow reads the fixture's API token row back.
func (f *authLifecycleFixture) apiTokenRow(t *testing.T) model.APIToken {
	t.Helper()
	tokens, err := f.s.store.ListAPITokensByUserID(f.user.ID)
	if err != nil {
		t.Fatalf("list api tokens: %v", err)
	}
	for _, tok := range tokens {
		if tok.ID == f.apiTokenID {
			return tok
		}
	}
	t.Fatalf("api token %s not found", f.apiTokenID)
	return model.APIToken{}
}

// assertRefused checks a refusal's status code and message together.
func assertRefused(t *testing.T, rec *httptest.ResponseRecorder, wantCode int, wantMsg, label string) {
	t.Helper()
	if rec.Code != wantCode {
		t.Fatalf("%s: status = %d, want %d: %s", label, rec.Code, wantCode, rec.Body.String())
	}
	if got := errorBody(t, rec); got != wantMsg {
		t.Fatalf("%s: message = %q, want %q", label, got, wantMsg)
	}
}

// (a) The password stage refuses before the credential is ever examined: the
// answer is identical for a right and a wrong password, and neither moves the
// failure counter. Together those two facts show ComparePassword was skipped.
// assertNoCredentialWasChecked confirms neither refused attempt moved the
// failure counter or set a lock, then confirms the audit trail recorded both
// as refusals carrying the account-state detail rather than a bad password.
func assertNoCredentialWasChecked(t *testing.T, f *authLifecycleFixture, state authLifecycleState) {
	t.Helper()
	after := f.reload(t)
	if after.FailedLoginCount != 0 {
		t.Fatalf("failure counter moved to %d: a credential was checked", after.FailedLoginCount)
	}
	if after.LockedUntil != nil {
		t.Fatalf("refused attempts locked the account until %s", after.LockedUntil)
	}

	entries := auditEntriesFor(t, f.s, f.user.ID, model.AuditUserLoginFailed)
	if len(entries) != 2 {
		t.Fatalf("expected two %s entries, got %d", model.AuditUserLoginFailed, len(entries))
	}
	for _, entry := range entries {
		if entry.Detail == nil || *entry.Detail != state.detail {
			t.Fatalf("audit detail = %v, want %q", entry.Detail, state.detail)
		}
	}
}

func TestAccountLifecycle_LoginRefusedBeforeCredentialCheck(t *testing.T) {
	for _, state := range refusingAccountStates() {
		t.Run(state.name, func(t *testing.T) {
			f := newAuthLifecycleFixture(t)
			state.apply(t, f)

			correct := attemptLogin(t, f.s, f.user.Username, lockoutTestPassword)
			assertRefused(t, correct, http.StatusForbidden, state.message, "correct password")

			wrong := attemptLogin(t, f.s, f.user.Username, lockoutWrongPassword)
			assertRefused(t, wrong, http.StatusForbidden, state.message, "wrong password")

			if correct.Body.String() != wrong.Body.String() {
				t.Fatalf("refusal bodies differ:\n correct=%q\n wrong  =%q",
					correct.Body.String(), wrong.Body.String())
			}

			assertNoCredentialWasChecked(t, f, state)
		})
	}
}

// (b) Precedence: an account that is BOTH locked and unusable is refused for
// the unusable state, not the lock. Answering 423 would invite the operator to
// wait for an expiry that will not help them.
func TestAccountLifecycle_RefusalOutranksLock(t *testing.T) {
	for _, state := range refusingAccountStates() {
		t.Run(state.name, func(t *testing.T) {
			f := newAuthLifecycleFixture(t)
			lockAccountNow(t, f.s, f.user.ID, f.clk.now(), 15*time.Minute)
			state.apply(t, f)

			rec := attemptLogin(t, f.s, f.user.Username, lockoutTestPassword)
			assertRefused(t, rec, http.StatusForbidden, state.message, "locked and "+state.name)

			if got := f.s.accountStatus(f.reload(t)); string(got) != state.name {
				t.Fatalf("derived status = %q, want %q", got, state.name)
			}
		})
	}
}

// (c) A one-time-code token minted while the account was usable does not
// survive the account becoming unusable: the second stage refuses before the
// stored secret is decrypted or the code evaluated.
func TestAccountLifecycle_TOTPStageRefusesPreIssuedToken(t *testing.T) {
	for _, state := range refusingAccountStates() {
		t.Run(state.name, func(t *testing.T) {
			f := newAuthLifecycleFixture(t)
			totpToken := f.totpStageToken(t)
			state.apply(t, f)

			code := validTOTPCode(t, f.totpSecret)
			rec := attemptTOTP(t, f.s, totpToken, code)
			assertRefused(t, rec, http.StatusForbidden, state.message, "code stage")

			if findCookie(rec.Result().Cookies(), cookieAccess) != nil {
				t.Fatal("a refused code stage set an access cookie")
			}
		})
	}
}

// (d) A refresh token issued before the account became unusable cannot mint a
// new pair. 401 is what the web client already knows how to handle: it gives
// up and returns the operator to the sign-in page.
func TestAccountLifecycle_RefreshRefusesPreIssuedToken(t *testing.T) {
	for _, state := range refusingAccountStates() {
		t.Run(state.name, func(t *testing.T) {
			f := newAuthLifecycleFixture(t)
			state.apply(t, f)

			assertRefused(t, f.refresh(t), http.StatusUnauthorized, state.message, "refresh")
		})
	}
}

// (e) An access token issued before the account became unusable stops working
// mid-session: the middleware rejects it with the account's own message rather
// than the generic "invalid token".
func TestAccountLifecycle_AccessTokenRefused(t *testing.T) {
	for _, state := range refusingAccountStates() {
		t.Run(state.name, func(t *testing.T) {
			f := newAuthLifecycleFixture(t)
			state.apply(t, f)

			rec := f.bearer(t, "GET", testMePath, f.accessToken)
			assertRefused(t, rec, http.StatusUnauthorized, state.message, "access token")
		})
	}
}

// (f) The same for an API token — and the refused request must leave no trace
// of use, or an unusable account's own rejected calls would keep resetting the
// dormancy clock that made it unusable.
func TestAccountLifecycle_APITokenRefusedAndLeavesNoActivity(t *testing.T) {
	for _, state := range refusingAccountStates() {
		t.Run(state.name, func(t *testing.T) {
			f := newAuthLifecycleFixture(t)
			state.apply(t, f)
			before := f.reload(t)

			rec := f.bearer(t, "GET", testMePath, f.apiToken)
			assertRefused(t, rec, http.StatusUnauthorized, state.message, "api token")

			if row := f.apiTokenRow(t); row.LastUsedAt != nil {
				t.Fatalf("refused api request stamped last_used_at = %s", row.LastUsedAt)
			}
			after := f.reload(t)
			if !sameTimePtr(before.LastActivityAt, after.LastActivityAt) {
				t.Fatalf("refused api request moved last_activity_at: %v → %v",
					before.LastActivityAt, after.LastActivityAt)
			}
		})
	}
}

// (g) Restoring the account restores every path at once, because they all read
// the same derived status: nothing has to be undone path by path.
func TestAccountLifecycle_RestoredAccountRegainsEveryPath(t *testing.T) {
	for _, state := range refusingAccountStates() {
		t.Run(state.name, func(t *testing.T) {
			f := newAuthLifecycleFixture(t)
			state.apply(t, f)
			assertRefused(t, f.bearer(t, "GET", testMePath, f.accessToken),
				http.StatusUnauthorized, state.message, "access token while "+state.name)

			state.restore(t, f)

			if rec := f.bearer(t, "GET", testMePath, f.accessToken); rec.Code != http.StatusOK {
				t.Fatalf("access token after restore: %d: %s", rec.Code, rec.Body.String())
			}
			if rec := f.bearer(t, "GET", testMePath, f.apiToken); rec.Code != http.StatusOK {
				t.Fatalf("api token after restore: %d: %s", rec.Code, rec.Body.String())
			}
			// Refresh rotates the generation, so it runs after the tokens above.
			if rec := f.refresh(t); rec.Code != http.StatusOK {
				t.Fatalf("refresh after restore: %d: %s", rec.Code, rec.Body.String())
			}

			totpToken := f.totpStageToken(t)
			code := validTOTPCode(t, f.totpSecret)
			if rec := attemptTOTP(t, f.s, totpToken, code); rec.Code != http.StatusOK {
				t.Fatalf("code stage after restore: %d: %s", rec.Code, rec.Body.String())
			}
		})
	}
}

// The exemption is the hub's recovery path: an exempt administrator that has
// not signed in for far longer than the window still signs in (FR-013).
func TestAccountLifecycle_ExemptAccountNeverGoesDormant(t *testing.T) {
	f := newAuthLifecycleFixture(t)
	setDormantDays(t, f.s, 1)
	markDormancyExempt(t, f.s, f.user.ID)
	backdateActivity(t, f.s, f.user.ID, f.clk.now().Add(-365*24*time.Hour))

	if got := f.s.accountStatus(f.reload(t)); got != account.StatusActive {
		t.Fatalf("derived status = %q, want %q for an exempt account", got, account.StatusActive)
	}
	if rec := attemptLogin(t, f.s, f.user.Username, lockoutTestPassword); rec.Code != http.StatusAccepted {
		t.Fatalf("exempt account sign-in: %d: %s", rec.Code, rec.Body.String())
	}
}

// A dormancy window of zero turns the control off entirely: however stale the
// account, it signs in.
func TestAccountLifecycle_DormancyDisabledByPolicy(t *testing.T) {
	f := newAuthLifecycleFixture(t)
	setDormantDays(t, f.s, 0)
	backdateActivity(t, f.s, f.user.ID, f.clk.now().Add(-365*24*time.Hour))

	if got := f.s.accountStatus(f.reload(t)); got != account.StatusActive {
		t.Fatalf("derived status = %q, want %q with dormancy disabled", got, account.StatusActive)
	}
	if rec := attemptLogin(t, f.s, f.user.Username, lockoutTestPassword); rec.Code != http.StatusAccepted {
		t.Fatalf("sign-in with dormancy disabled: %d: %s", rec.Code, rec.Body.String())
	}
}

// The hub's very first administrator is created exempt, so a single-operator
// hub can never lock its only administrator out through inactivity, and
// GET /api/auth/me reports the derived status alongside it.
func TestAccountLifecycle_RegisteredAdminIsExemptAndActive(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	req := httptest.NewRequest("GET", testMePath, nil)
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}

	var me model.User
	if err := json.Unmarshal(rec.Body.Bytes(), &me); err != nil {
		t.Fatalf(testDecodeRespErr, err)
	}
	if !me.DormancyExempt {
		t.Fatal("the first administrator is not exempt from dormancy")
	}
	if me.Status != string(account.StatusActive) {
		t.Fatalf("status = %q, want %q", me.Status, account.StatusActive)
	}
}

// sameTimePtr compares two optional timestamps for equality, nil included.
func sameTimePtr(a, b *time.Time) bool {
	switch {
	case a == nil && b == nil:
		return true
	case a == nil || b == nil:
		return false
	default:
		return a.Equal(*b)
	}
}

// validTOTPCode generates a code the fixture's secret currently accepts.
func validTOTPCode(t *testing.T, secret string) string {
	t.Helper()
	code, err := auth.GenerateValidCode(secret)
	if err != nil {
		t.Fatalf("generate totp code: %v", err)
	}
	return code
}

// An API-token request by a usable account counts as activity, which is what
// keeps an automation account that never signs in interactively out of
// dormancy (FR-012). The stamp is throttled to one write per minute, so a busy
// token cannot turn every request into a write.
func TestAccountLifecycle_APITokenUseStampsActivity(t *testing.T) {
	f := newAuthLifecycleFixture(t)
	if before := f.reload(t); before.LastActivityAt != nil {
		t.Fatalf("expected no activity before the first request, got %s", before.LastActivityAt)
	}

	if rec := f.bearer(t, "GET", testMePath, f.apiToken); rec.Code != http.StatusOK {
		t.Fatalf("api token request: %d: %s", rec.Code, rec.Body.String())
	}
	first := f.reload(t).LastActivityAt
	if first == nil {
		t.Fatal("an API-token request did not stamp last_activity_at")
	}
	if !first.Equal(f.clk.now()) {
		t.Fatalf("last_activity_at = %s, want %s", first, f.clk.now())
	}

	// Inside the throttle window a second request writes nothing.
	f.clk.advance(30 * time.Second)
	if rec := f.bearer(t, "GET", testMePath, f.apiToken); rec.Code != http.StatusOK {
		t.Fatalf("second api token request: %d: %s", rec.Code, rec.Body.String())
	}
	if got := f.reload(t).LastActivityAt; got == nil || !got.Equal(*first) {
		t.Fatalf("throttled request moved last_activity_at to %v, want %s", got, first)
	}

	// Past the window it writes again.
	f.clk.advance(2 * time.Minute)
	if rec := f.bearer(t, "GET", testMePath, f.apiToken); rec.Code != http.StatusOK {
		t.Fatalf("third api token request: %d: %s", rec.Code, rec.Body.String())
	}
	got := f.reload(t).LastActivityAt
	if got == nil || !got.Equal(f.clk.now()) {
		t.Fatalf("last_activity_at = %v, want %s after the throttle window", got, f.clk.now())
	}
}
