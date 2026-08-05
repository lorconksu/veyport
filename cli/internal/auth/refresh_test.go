package auth

// Tests for AuthContext resolution and transparent refresh-token rotation
// (spec 004-cli-connector: data-model.md "AuthContext", research.md R3,
// contracts/rest-api.md POST /api/auth/refresh).
//
// Secret hygiene: every token minted here embeds refreshSecret, and no
// assertion ever prints a token value — failures report token *generations*
// instead, so a failing test can never dump credential material into CI logs.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wyiu/veyport/cli/internal/api"
	"github.com/wyiu/veyport/cli/internal/cmdutil"
	"github.com/wyiu/veyport/cli/internal/config"
)

// refreshSecret is embedded in every token the stub hub mints so leak
// assertions cannot pass by accident.
const refreshSecret = "SECRET-MUST-NOT-LEAK-4b7a1c"

// stubRefreshToken/stubAccessToken model the hub's single-use rotation: the
// hub holds exactly one live generation, and every successful refresh issues
// generation n+1 while invalidating generation n
// (hub/internal/server/handlers_auth.go generation increment, cited by R3).
func stubRefreshToken(gen int) string { return fmt.Sprintf("refresh-gen%d-%s", gen, refreshSecret) }
func stubAccessToken(gen int) string  { return fmt.Sprintf("access-gen%d-%s", gen, refreshSecret) }

// tokenGen recovers the generation encoded in a stub token, or -1 when the
// value is not one of ours. Tests report generations, never token values.
func tokenGen(tok string) int {
	for _, prefix := range []string{"refresh-gen", "access-gen"} {
		if !strings.HasPrefix(tok, prefix) {
			continue
		}
		rest := strings.TrimPrefix(tok, prefix)
		dash := strings.Index(rest, "-")
		if dash < 0 {
			return -1
		}
		n, err := strconv.Atoi(rest[:dash])
		if err != nil {
			return -1
		}
		return n
	}
	return -1
}

// --- stub hub ---------------------------------------------------------------

// stubHub is an in-process stand-in for the hub's auth + a protected route.
// Refresh semantics mirror contracts/rest-api.md: JSON body
// {"refresh_token"}, 200 {access_token, refresh_token}, single-use rotation,
// 401 for a stale/rotated token.
type stubHub struct {
	srv *httptest.Server

	mu             sync.Mutex
	gen            int
	refreshCalls   int
	protectedCalls int
	presentedGens  []int // generation presented on each refresh call
	nonJSONRefresh int   // refresh requests that did not carry a JSON body
	authHeaderSeen int   // refresh requests that carried an Authorization header

	// beforeRefresh runs on entry to the refresh handler, before any state
	// is consulted, and outside the hub's lock. It is the seam the flock
	// test uses to observe the CLI mid-critical-section.
	beforeRefresh func(call int)
	// onProtected runs on entry to the protected handler, outside the hub's
	// lock, so a test can inspect on-disk state at that instant.
	onProtected func(call int)
	// protectedPolicy decides the status for a protected call; nil means
	// "accept only the current access token".
	protectedPolicy func(h *stubHub, token string, call int) int
}

func newStubHub(t *testing.T) *stubHub {
	t.Helper()
	h := &stubHub{gen: 1}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth/refresh", h.handleRefresh)
	mux.HandleFunc("/api/servers", h.handleProtected)

	h.srv = httptest.NewServer(mux)
	t.Cleanup(h.srv.Close)
	return h
}

func (h *stubHub) url() string { return h.srv.URL }

func (h *stubHub) handleRefresh(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	h.refreshCalls++
	call := h.refreshCalls
	if r.Header.Get("Authorization") != "" {
		h.authHeaderSeen++
	}
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		h.nonJSONRefresh++
	}
	h.mu.Unlock()

	if h.beforeRefresh != nil {
		h.beforeRefresh(call)
	}

	if r.Method != http.MethodPost {
		writeStubJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	var body struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeStubJSON(w, http.StatusBadRequest, map[string]string{"error": "malformed body"})
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	h.presentedGens = append(h.presentedGens, tokenGen(body.RefreshToken))

	if body.RefreshToken != stubRefreshToken(h.gen) {
		// Single-use: the presented token was already rotated away.
		writeStubJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid or expired refresh token"})
		return
	}
	h.gen++
	writeStubJSON(w, http.StatusOK, map[string]string{
		"access_token":  stubAccessToken(h.gen),
		"refresh_token": stubRefreshToken(h.gen),
	})
}

func (h *stubHub) handleProtected(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	h.protectedCalls++
	call := h.protectedCalls
	h.mu.Unlock()

	if h.onProtected != nil {
		h.onProtected(call)
	}

	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	status := http.StatusOK
	if h.protectedPolicy != nil {
		status = h.protectedPolicy(h, token, call)
	} else if token != h.currentAccess() {
		status = http.StatusUnauthorized
	}

	switch status {
	case http.StatusOK:
		writeStubJSON(w, http.StatusOK, map[string]any{
			"servers": []any{}, "total": 0, "limit": 50, "offset": 0,
		})
	case http.StatusUnauthorized:
		writeStubJSON(w, status, map[string]string{"error": "invalid or expired token"})
	default:
		writeStubJSON(w, status, map[string]string{"error": http.StatusText(status)})
	}
}

func (h *stubHub) currentAccess() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return stubAccessToken(h.gen)
}

func (h *stubHub) counts() (refresh, protected int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.refreshCalls, h.protectedCalls
}

func (h *stubHub) presented() []int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]int(nil), h.presentedGens...)
}

func writeStubJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// --- fixture ----------------------------------------------------------------

// refreshFixture wires a stub hub to a file-backed store in a private config
// directory: the file backend is used deliberately, because it is the backend
// the flock in R3 actually guards and the one whose on-disk bytes a test can
// inspect for the atomic-persistence assertions.
type refreshFixture struct {
	hub   *stubHub
	dir   string
	store Store
}

func newRefreshFixture(t *testing.T) *refreshFixture {
	t.Helper()
	f := &refreshFixture{
		hub:   newStubHub(t),
		dir:   t.TempDir(),
		store: nil,
	}
	f.store = newFileStore(f.dir)
	return f
}

// seedSession persists the generation-1 refresh token, as a completed login
// would.
func (f *refreshFixture) seedSession(t *testing.T) StoredSession {
	t.Helper()
	sess := StoredSession{
		RefreshToken: stubRefreshToken(1),
		Username:     "alice",
		Role:         "admin",
		ObtainedAt:   time.Now().UTC().Truncate(time.Second),
	}
	if err := f.store.Save(f.hub.url(), sess); err != nil {
		t.Fatalf("seed session: %v", err)
	}
	return sess
}

func (f *refreshFixture) resolve(t *testing.T, envToken string, cfg config.Config, store Store) *AuthContext {
	t.Helper()
	if store == nil {
		store = f.store
	}
	ac, err := Resolve(f.hub.url(), envToken, cfg, store, f.dir)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	return ac
}

// storedGen returns the generation of the refresh token currently persisted
// for the hub, or -1 when nothing is stored. Never returns the token itself.
func (f *refreshFixture) storedGen(t *testing.T) int {
	t.Helper()
	// A fresh reader, as another process would use.
	sess, ok, err := newFileStore(f.dir).Load(f.hub.url())
	if err != nil {
		t.Fatalf("load stored session: %v", err)
	}
	if !ok {
		return -1
	}
	return tokenGen(sess.RefreshToken)
}

func (f *refreshFixture) storedSession(t *testing.T) (StoredSession, bool) {
	t.Helper()
	sess, ok, err := newFileStore(f.dir).Load(f.hub.url())
	if err != nil {
		t.Fatalf("load stored session: %v", err)
	}
	return sess, ok
}

// listServers is the operation under test: one authenticated GET.
func listServers(ctx context.Context) func(*api.Client) error {
	return func(c *api.Client) error {
		var page api.ServersPage
		return c.Get(ctx, "/api/servers", nil, &page)
	}
}

func assertNoTokenLeak(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	if strings.Contains(err.Error(), refreshSecret) {
		t.Error("error message leaked token material")
	}
}

func assertCounts(t *testing.T, h *stubHub, wantRefresh, wantProtected int) {
	t.Helper()
	refresh, protected := h.counts()
	if refresh != wantRefresh {
		t.Errorf("refresh calls = %d, want %d", refresh, wantRefresh)
	}
	if protected != wantProtected {
		t.Errorf("protected calls = %d, want %d", protected, wantProtected)
	}
}

// --- resolution -------------------------------------------------------------

func TestResolvePrefersAPITokenOverStoredSession(t *testing.T) {
	f := newRefreshFixture(t)
	f.seedSession(t)

	cfg := config.Config{Hubs: map[string]config.HubProfile{
		f.hub.url(): {APIToken: "adt_from_config"},
	}}

	t.Run("env token wins over config and session", func(t *testing.T) {
		ac := f.resolve(t, "adt_from_env", cfg, nil)
		if got := ac.Mode(); got != ModeAPIToken {
			t.Errorf("Mode() = %q, want %q", got, ModeAPIToken)
		}
		// Identity fields belong to session mode only.
		if ac.Username() != "" || ac.Role() != "" {
			t.Errorf("api_token mode exposed identity: username %q role %q", ac.Username(), ac.Role())
		}
		c, err := ac.Client(context.Background())
		if err != nil {
			t.Fatalf("Client: %v", err)
		}
		if c.Token != "adt_from_env" {
			t.Error("client bearer is not the env API token")
		}
		if refresh, _ := f.hub.counts(); refresh != 0 {
			t.Errorf("resolution/client construction hit the refresh endpoint %d times", refresh)
		}
	})

	t.Run("config token used when env is empty", func(t *testing.T) {
		ac := f.resolve(t, "", cfg, nil)
		if got := ac.Mode(); got != ModeAPIToken {
			t.Errorf("Mode() = %q, want %q", got, ModeAPIToken)
		}
		c, err := ac.Client(context.Background())
		if err != nil {
			t.Fatalf("Client: %v", err)
		}
		if c.Token != "adt_from_config" {
			t.Error("client bearer is not the config API token")
		}
	})

	t.Run("config token for a different hub is ignored", func(t *testing.T) {
		other := config.Config{Hubs: map[string]config.HubProfile{
			"https://other.example.com": {APIToken: "adt_other_hub"},
		}}
		ac := f.resolve(t, "", other, nil)
		if got := ac.Mode(); got != ModeSession {
			t.Errorf("Mode() = %q, want %q (hub B's token must not apply to hub A)", got, ModeSession)
		}
	})
}

func TestResolveSessionModeCarriesStoredIdentity(t *testing.T) {
	f := newRefreshFixture(t)
	want := f.seedSession(t)

	ac := f.resolve(t, "", config.Config{}, nil)
	if got := ac.Mode(); got != ModeSession {
		t.Fatalf("Mode() = %q, want %q", got, ModeSession)
	}
	if ac.Username() != want.Username {
		t.Errorf("Username() = %q, want %q", ac.Username(), want.Username)
	}
	if ac.Role() != want.Role {
		t.Errorf("Role() = %q, want %q", ac.Role(), want.Role)
	}
	// Resolution alone must not talk to the hub.
	assertCounts(t, f.hub, 0, 0)
}

func TestResolveNoCredentialsIsNotAnError(t *testing.T) {
	f := newRefreshFixture(t) // nothing seeded

	ac := f.resolve(t, "", config.Config{}, nil)
	if got := ac.Mode(); got != ModeNone {
		t.Fatalf("Mode() = %q, want %q", got, ModeNone)
	}
	if ac.Username() != "" || ac.Role() != "" {
		t.Errorf("none mode exposed identity: username %q role %q", ac.Username(), ac.Role())
	}

	_, err := ac.Client(context.Background())
	if err == nil {
		t.Fatal("Client in none mode succeeded, want an auth error")
	}
	if code := cmdutil.Code(err); code != cmdutil.ExitAuth {
		t.Errorf("Client error exit code = %d, want %d", code, cmdutil.ExitAuth)
	}
	if !strings.Contains(err.Error(), "vey login") {
		t.Errorf("error lacks re-login guidance: %s", err)
	}

	if err := ac.Do(context.Background(), listServers(context.Background())); err == nil {
		t.Error("Do in none mode succeeded, want an auth error")
	} else if code := cmdutil.Code(err); code != cmdutil.ExitAuth {
		t.Errorf("Do error exit code = %d, want %d", code, cmdutil.ExitAuth)
	}
	assertCounts(t, f.hub, 0, 0)
}

func TestResolveRejectsEmptyHubURL(t *testing.T) {
	f := newRefreshFixture(t)
	if _, err := Resolve("   ", "", config.Config{}, f.store, f.dir); err == nil {
		t.Error("Resolve with a blank hub URL succeeded, want error")
	}
}

// --- transparent refresh ----------------------------------------------------

// TestAuthContextDoRefreshesOn401AndRetriesOnce is the core US1 behavior: an
// expired access token produces one transparent refresh and exactly one
// retry, with the rotated pair persisted before the retried request goes out
// (data-model.md credential persistence invariant).
func TestAuthContextDoRefreshesOn401AndRetriesOnce(t *testing.T) {
	f := newRefreshFixture(t)
	seeded := f.seedSession(t)

	// The first protected call is rejected as if the access token had aged
	// out mid-session; afterwards only the newest access token is accepted.
	f.hub.protectedPolicy = func(h *stubHub, token string, call int) int {
		if call == 1 {
			return http.StatusUnauthorized
		}
		if token == h.currentAccess() {
			return http.StatusOK
		}
		return http.StatusUnauthorized
	}

	// Observe the store exactly when the retried request is being served:
	// the rotated refresh token must already be durable, and the file must
	// be complete JSON (never a torn write).
	var genAtRetry int
	f.hub.onProtected = func(call int) {
		if call == 2 {
			genAtRetry = f.storedGen(t)
		}
	}

	ac := f.resolve(t, "", config.Config{}, nil)
	ctx := context.Background()
	if err := ac.Do(ctx, listServers(ctx)); err != nil {
		assertNoTokenLeak(t, err)
		t.Fatalf("Do: %v", err)
	}

	// Two refreshes: one to mint the first access token (access tokens are
	// never persisted, so session mode always starts by refreshing), one
	// after the 401. Two protected calls: original + single retry.
	assertCounts(t, f.hub, 2, 2)

	if got := f.storedGen(t); got != 3 {
		t.Errorf("stored refresh token generation = %d, want 3", got)
	}
	if genAtRetry != 3 {
		t.Errorf("stored generation when the retried request was served = %d, want 3 (rotated pair must be persisted first)", genAtRetry)
	}
	if want := []int{1, 2}; !equalInts(f.hub.presented(), want) {
		t.Errorf("refresh token generations presented = %v, want %v", f.hub.presented(), want)
	}

	sess, ok := f.storedSession(t)
	if !ok {
		t.Fatal("session vanished after rotation")
	}
	if sess.Username != seeded.Username || sess.Role != seeded.Role {
		t.Errorf("rotation dropped identity: username %q role %q", sess.Username, sess.Role)
	}
}

// TestRefreshNeverPersistsAccessToken pins the data-model rule that only the
// refresh token is ever written to storage.
func TestRefreshNeverPersistsAccessToken(t *testing.T) {
	f := newRefreshFixture(t)
	f.seedSession(t)

	ac := f.resolve(t, "", config.Config{}, nil)
	ctx := context.Background()
	if err := ac.Do(ctx, listServers(ctx)); err != nil {
		assertNoTokenLeak(t, err)
		t.Fatalf("Do: %v", err)
	}

	raw, err := readCredentialsFile(f.dir)
	if err != nil {
		t.Fatalf("read credentials file: %v", err)
	}
	if strings.Contains(raw, "access-gen") {
		t.Error("an access token was persisted to the credentials file")
	}
	// The stored value is a refresh token, and it is the rotated one.
	if got := f.storedGen(t); got != 2 {
		t.Errorf("stored refresh token generation = %d, want 2", got)
	}
}

// TestAuthContextDoRetriesAtMostOnce covers contracts/rest-api.md "exactly
// one transparent refresh attempt, then exit 3": a route that always answers
// 401 must not loop.
func TestAuthContextDoRetriesAtMostOnce(t *testing.T) {
	f := newRefreshFixture(t)
	f.seedSession(t)
	f.hub.protectedPolicy = func(*stubHub, string, int) int { return http.StatusUnauthorized }

	ac := f.resolve(t, "", config.Config{}, nil)
	ctx := context.Background()
	err := ac.Do(ctx, listServers(ctx))
	if err == nil {
		t.Fatal("Do succeeded against an always-401 route")
	}
	assertNoTokenLeak(t, err)
	if code := cmdutil.Code(err); code != cmdutil.ExitAuth {
		t.Errorf("exit code = %d, want %d", code, cmdutil.ExitAuth)
	}
	assertCounts(t, f.hub, 2, 2)
}

// TestAuthContextDoPropagatesNonAuthErrors: only 401 triggers a refresh; a
// 429 must surface as exit 7 without the CLI retrying into the limiter.
func TestAuthContextDoPropagatesNonAuthErrors(t *testing.T) {
	f := newRefreshFixture(t)
	f.seedSession(t)
	f.hub.protectedPolicy = func(*stubHub, string, int) int { return http.StatusTooManyRequests }

	ac := f.resolve(t, "", config.Config{}, nil)
	ctx := context.Background()
	err := ac.Do(ctx, listServers(ctx))
	if err == nil {
		t.Fatal("Do succeeded against a 429 route")
	}
	assertNoTokenLeak(t, err)
	if code := cmdutil.Code(err); code != cmdutil.ExitRateLimited {
		t.Errorf("exit code = %d, want %d", code, cmdutil.ExitRateLimited)
	}
	// One refresh to mint the initial access token, one protected call, no
	// retry.
	assertCounts(t, f.hub, 1, 1)
}

// TestAuthContextDoAPITokenModeNeverRefreshes covers contracts/rest-api.md
// "401 in api_token mode: no refresh possible → exit 3 immediately", even
// when a perfectly good stored session exists alongside the token.
func TestAuthContextDoAPITokenModeNeverRefreshes(t *testing.T) {
	f := newRefreshFixture(t)
	f.seedSession(t)
	f.hub.protectedPolicy = func(*stubHub, string, int) int { return http.StatusUnauthorized }

	ac := f.resolve(t, "adt_revoked", config.Config{}, nil)
	if ac.Mode() != ModeAPIToken {
		t.Fatalf("Mode() = %q, want %q", ac.Mode(), ModeAPIToken)
	}

	ctx := context.Background()
	err := ac.Do(ctx, listServers(ctx))
	if err == nil {
		t.Fatal("Do succeeded with a revoked API token")
	}
	assertNoTokenLeak(t, err)
	if code := cmdutil.Code(err); code != cmdutil.ExitAuth {
		t.Errorf("exit code = %d, want %d", code, cmdutil.ExitAuth)
	}
	assertCounts(t, f.hub, 0, 1)
	if got := f.storedGen(t); got != 1 {
		t.Errorf("api_token mode touched the stored session: generation = %d, want 1", got)
	}
}

// --- refresh failure --------------------------------------------------------

// TestRefreshFailsWhenNoNewerTokenExists is the RaceLost → NoSession
// transition (data-model.md): refresh 401, reread finds nothing newer, so the
// user is told to log in again and the process exits 3.
func TestRefreshFailsWhenNoNewerTokenExists(t *testing.T) {
	f := newRefreshFixture(t)
	// Seed a token the hub has never heard of: refresh answers 401 and the
	// store still holds that same dead token on reread.
	if err := f.store.Save(f.hub.url(), StoredSession{
		RefreshToken: stubRefreshToken(99),
		Username:     "alice",
		Role:         "admin",
		ObtainedAt:   time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	ac := f.resolve(t, "", config.Config{}, nil)
	ctx := context.Background()
	err := ac.Do(ctx, listServers(ctx))
	if err == nil {
		t.Fatal("Do succeeded with a dead refresh token")
	}
	assertNoTokenLeak(t, err)
	if code := cmdutil.Code(err); code != cmdutil.ExitAuth {
		t.Errorf("exit code = %d, want %d", code, cmdutil.ExitAuth)
	}
	if !strings.Contains(err.Error(), "vey login") {
		t.Errorf("error lacks re-login guidance: %s", err)
	}
	// Exactly one refresh attempt: the reread found nothing newer, so there
	// was nothing to retry with, and the protected route was never reached.
	assertCounts(t, f.hub, 1, 0)
}

func TestRefreshFailsWhenNothingIsStored(t *testing.T) {
	f := newRefreshFixture(t)
	f.seedSession(t)
	ac := f.resolve(t, "", config.Config{}, nil)

	// Another process logged out between resolution and use.
	if err := f.store.Delete(f.hub.url()); err != nil {
		t.Fatalf("delete: %v", err)
	}

	err := ac.Do(context.Background(), listServers(context.Background()))
	if err == nil {
		t.Fatal("Do succeeded with no stored session")
	}
	assertNoTokenLeak(t, err)
	if code := cmdutil.Code(err); code != cmdutil.ExitAuth {
		t.Errorf("exit code = %d, want %d", code, cmdutil.ExitAuth)
	}
	if !strings.Contains(err.Error(), "vey login") {
		t.Errorf("error lacks re-login guidance: %s", err)
	}
	assertCounts(t, f.hub, 0, 0)
}

// --- two-process race (R3) --------------------------------------------------

// staleFirstLoadStore returns a pre-rotation snapshot on its first Load and
// delegates to the real store afterwards.
//
// This is how the loser of a refresh race is simulated deterministically. A
// genuine two-process race cannot be reproduced in a unit test: flock is
// per-file-descriptor and per-process, so two goroutines in this process
// would contend on the lock exactly as two processes do, but their *timing*
// is not controllable, and the interesting window (one racer reading the
// store before the other's write lands) is precisely the window flock
// closes for the file backend. The window stays open for keyring-backed
// stores, which flock does not guard — which is exactly what this wrapper
// models. Real multi-process behavior is covered by the flock contract test
// below (TestRefreshHoldsFlockAcrossEntireCriticalSection) plus
// TestLockRefreshSerializesHolders in store_test.go; end-to-end multi-process
// verification belongs to the quickstart, not to `go test`.
type staleFirstLoadStore struct {
	Store
	mu    sync.Mutex
	stale *StoredSession
	loads int
}

func (s *staleFirstLoadStore) Load(hubURL string) (StoredSession, bool, error) {
	s.mu.Lock()
	s.loads++
	if s.stale != nil {
		snapshot := *s.stale
		s.stale = nil
		s.mu.Unlock()
		return snapshot, true, nil
	}
	s.mu.Unlock()
	return s.Store.Load(hubURL)
}

func (s *staleFirstLoadStore) loadCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loads
}

// armStale arms the snapshot and zeroes the load counter, so the count that
// follows measures only the loads made by the refresh under test (Resolve
// does its own Load).
func (s *staleFirstLoadStore) armStale(sess StoredSession) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stale = &sess
	s.loads = 0
}

// TestRefreshRecoversWhenAnotherProcessRotatedFirst is the RaceLost → Active
// transition (R3 "reread-after-fail"): the loser's refresh 401s, it rereads
// the store inside the lock, finds the winner's newer token, and retries once
// — transparently, with no user-visible failure.
func TestRefreshRecoversWhenAnotherProcessRotatedFirst(t *testing.T) {
	f := newRefreshFixture(t)
	seeded := f.seedSession(t)

	// Winner: a first process refreshes normally, rotating gen1 → gen2.
	winner := f.resolve(t, "", config.Config{}, nil)
	if _, err := winner.Client(context.Background()); err != nil {
		t.Fatalf("winner Client: %v", err)
	}
	if got := f.storedGen(t); got != 2 {
		t.Fatalf("after the winner refreshed, stored generation = %d, want 2", got)
	}

	// Loser: a second process that resolved before the winner's write landed
	// and therefore still holds the pre-rotation snapshot the winner spent.
	loserStore := &staleFirstLoadStore{Store: newFileStore(f.dir)}
	loser := f.resolve(t, "", config.Config{}, loserStore)
	loserStore.armStale(seeded)

	ctx := context.Background()
	if err := loser.Do(ctx, listServers(ctx)); err != nil {
		assertNoTokenLeak(t, err)
		t.Fatalf("loser did not recover from the lost race: %v", err)
	}

	// Refresh calls: winner's gen1, loser's doomed gen1, loser's retry with
	// the winner's gen2.
	refresh, protected := f.hub.counts()
	if refresh != 3 {
		t.Errorf("refresh calls = %d, want 3", refresh)
	}
	if protected != 1 {
		t.Errorf("protected calls = %d, want 1 (the recovery must be transparent)", protected)
	}
	if want := []int{1, 1, 2}; !equalInts(f.hub.presented(), want) {
		t.Errorf("refresh token generations presented = %v, want %v", f.hub.presented(), want)
	}
	if got := f.storedGen(t); got != 3 {
		t.Errorf("stored refresh token generation = %d, want 3", got)
	}
	// The reread happened inside the same refresh: exactly two loads (the
	// stale one, then the recovery reread).
	if got := loserStore.loadCount(); got != 2 {
		t.Errorf("store loads during the losing refresh = %d, want 2 (reread-after-fail)", got)
	}

	sess, ok := f.storedSession(t)
	if !ok {
		t.Fatal("session vanished after the race")
	}
	if sess.Username != seeded.Username || sess.Role != seeded.Role {
		t.Errorf("race recovery dropped identity: username %q role %q", sess.Username, sess.Role)
	}
}

// TestRefreshHoldsFlockAcrossEntireCriticalSection proves the serialization
// half of R3: the lock is held across read → POST → persist, not merely
// around the store write. A second holder (another process, modeled by a
// second flock acquisition — flock is per-descriptor, so this contends
// exactly as a separate process would) must block for the whole window.
func TestRefreshHoldsFlockAcrossEntireCriticalSection(t *testing.T) {
	f := newRefreshFixture(t)
	f.seedSession(t)

	entered := make(chan struct{})
	release := make(chan struct{})
	f.hub.beforeRefresh = func(call int) {
		if call != 1 {
			return
		}
		close(entered)
		<-release
	}

	ac := f.resolve(t, "", config.Config{}, nil)
	done := make(chan error, 1)
	go func() {
		ctx := context.Background()
		done <- ac.Do(ctx, listServers(ctx))
	}()

	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("refresh request never reached the hub")
	}

	// The CLI is mid-refresh (the hub has the request, no response yet).
	// Another process must not be able to start its own refresh.
	acquired := make(chan struct{})
	go func() {
		unlock, err := LockRefresh(f.dir)
		if err != nil {
			return
		}
		close(acquired)
		unlock()
	}()

	select {
	case <-acquired:
		close(release)
		t.Fatal("a competing holder acquired the refresh lock while a refresh was in flight")
	case <-time.After(200 * time.Millisecond):
	}

	close(release)
	select {
	case err := <-done:
		if err != nil {
			assertNoTokenLeak(t, err)
			t.Fatalf("Do: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Do never completed")
	}

	select {
	case <-acquired:
	case <-time.After(5 * time.Second):
		t.Fatal("the refresh lock was never released")
	}

	if got := f.storedGen(t); got != 2 {
		t.Errorf("stored refresh token generation = %d, want 2", got)
	}
}

// --- helpers ----------------------------------------------------------------

func readCredentialsFile(dir string) (string, error) {
	data, err := os.ReadFile(newFileStore(dir).path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func equalInts(got, want []int) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
