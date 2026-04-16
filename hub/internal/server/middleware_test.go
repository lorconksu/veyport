package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/wyiu/aerodocs/hub/internal/auth"
	"github.com/wyiu/aerodocs/hub/internal/model"
)

func TestAuthMiddleware_ValidToken(t *testing.T) {
	s := testServer(t)
	_ = registerAndGetAdminToken(t, s)

	user, err := s.store.GetUserByUsername("admin")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}

	access, _, _ := auth.GenerateTokenPair(s.jwtSecret, user.ID, string(user.Role), user.TokenGeneration)

	handler := s.authMiddleware(auth.TokenTypeAccess, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uid := UserIDFromContext(r.Context())
		if uid != user.ID {
			t.Fatalf("expected %s, got %s", user.ID, uid)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", testBearerPrefix+access)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200, rec.Code)
	}
}

func TestAuthMiddleware_RejectsRevokedAccessToken(t *testing.T) {
	s := testServer(t)
	_ = registerAndGetAdminToken(t, s)

	user, err := s.store.GetUserByUsername("admin")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}

	access, _, _ := auth.GenerateTokenPair(s.jwtSecret, user.ID, string(user.Role), user.TokenGeneration)
	if _, err := s.store.IncrementTokenGeneration(user.ID); err != nil {
		t.Fatalf("increment token generation: %v", err)
	}

	handler := s.authMiddleware(auth.TokenTypeAccess, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal(testHandlerNotCall)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", testBearerPrefix+access)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf(testExpected401Body, rec.Code, rec.Body.String())
	}
}

func TestAuthMiddleware_MissingToken(t *testing.T) {
	s := &Server{jwtSecret: "secret"}

	handler := s.authMiddleware(auth.TokenTypeAccess, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal(testHandlerNotCall)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf(testExpected401, rec.Code)
	}
}

func TestAuthMiddleware_ValidAPIToken(t *testing.T) {
	s := testServer(t)
	_ = registerAndGetAdminToken(t, s)

	user, err := s.store.GetUserByUsername("admin")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}

	raw, hash, prefix, err := auth.GenerateAPIToken()
	if err != nil {
		t.Fatalf("generate api token: %v", err)
	}
	if err := s.store.CreateAPIToken(&model.APIToken{
		ID:          uuid.NewString(),
		UserID:      user.ID,
		Name:        "nightly",
		TokenHash:   hash,
		TokenPrefix: prefix,
	}); err != nil {
		t.Fatalf("create api token: %v", err)
	}

	handler := s.authMiddleware(auth.TokenTypeAccess, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := UserIDFromContext(r.Context()); got != user.ID {
			t.Fatalf("expected user id %q, got %q", user.ID, got)
		}
		if got := UserRoleFromContext(r.Context()); got != string(user.Role) {
			t.Fatalf("expected role %q, got %q", user.Role, got)
		}
		if got := TokenTypeFromContext(r.Context()); got != auth.TokenTypeAPIToken {
			t.Fatalf("expected token type %q, got %q", auth.TokenTypeAPIToken, got)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", testBearerPrefix+raw)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}
}

func TestInteractiveOnly_RejectsAPIToken(t *testing.T) {
	s := testServer(t)
	_ = registerAndGetAdminToken(t, s)

	user, err := s.store.GetUserByUsername("admin")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}

	raw, hash, prefix, err := auth.GenerateAPIToken()
	if err != nil {
		t.Fatalf("generate api token: %v", err)
	}
	if err := s.store.CreateAPIToken(&model.APIToken{
		ID:          uuid.NewString(),
		UserID:      user.ID,
		Name:        "nightly",
		TokenHash:   hash,
		TokenPrefix: prefix,
	}); err != nil {
		t.Fatalf("create api token: %v", err)
	}

	handler := s.authMiddleware(auth.TokenTypeAccess, s.interactiveOnly(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal(testHandlerNotCall)
	})))

	req := httptest.NewRequest("PUT", "/test", nil)
	req.Header.Set("Authorization", testBearerPrefix+raw)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAuthMiddleware_WrongTokenType(t *testing.T) {
	secret := testJWTSecret
	s := &Server{jwtSecret: secret}

	// Generate a setup token, try to use it on an access-required endpoint
	setupToken, _ := auth.GenerateSetupToken(secret, testUserID1, "admin")

	handler := s.authMiddleware(auth.TokenTypeAccess, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal(testHandlerNotCall)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", testBearerPrefix+setupToken)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}

func TestRateLimiter(t *testing.T) {
	rl := newRateLimiter(3, time.Minute)

	for i := 0; i < 3; i++ {
		if !rl.allow(testIP1234) {
			t.Fatalf("attempt %d should be allowed", i+1)
		}
	}

	if rl.allow(testIP1234) {
		t.Fatal("4th attempt should be blocked")
	}

	// Different IP should still be allowed
	if !rl.allow("5.6.7.8") {
		t.Fatal("different IP should be allowed")
	}
}

func TestRateLimiter_Middleware_Blocked(t *testing.T) {
	rl := newRateLimiter(1, time.Minute)

	handler := rl.middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// First request using RemoteAddr with port
	req1 := httptest.NewRequest("POST", testLoginRoute, nil)
	req1.RemoteAddr = "10.0.0.1:12345"
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("first request: expected 200, got %d", rec1.Code)
	}

	// Second request same IP, different port - should still be blocked
	req2 := httptest.NewRequest("POST", testLoginRoute, nil)
	req2.RemoteAddr = "10.0.0.1:12346"
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusTooManyRequests {
		t.Fatalf("second request: expected 429, got %d", rec2.Code)
	}
}

// TestRateLimiter_Middleware_XFFSpoofIgnored verifies that spoofed
// X-Forwarded-For headers do NOT bypass rate limiting.
func TestRateLimiter_Middleware_XFFSpoofIgnored(t *testing.T) {
	rl := newRateLimiter(1, time.Minute)

	handler := rl.middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// First request exhausts the limit for RemoteAddr 10.0.0.1
	req1 := httptest.NewRequest("POST", testLoginRoute, nil)
	req1.RemoteAddr = "10.0.0.1:40000"
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("first request: expected 200, got %d", rec1.Code)
	}

	// Second request: same RemoteAddr but spoofed X-Forwarded-For
	// Should still be blocked because we ignore XFF
	req2 := httptest.NewRequest("POST", testLoginRoute, nil)
	req2.RemoteAddr = "10.0.0.1:40001"
	req2.Header.Set(testXForwardedFor, "99.99.99.99")
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusTooManyRequests {
		t.Fatalf("spoofed XFF should not bypass rate limit: expected 429, got %d", rec2.Code)
	}
}

// TestRateLimiter_Middleware_PortStripped verifies that the same IP
// with different ports is correctly rate-limited as one client.
func TestRateLimiter_Middleware_PortStripped(t *testing.T) {
	rl := newRateLimiter(2, time.Minute)

	handler := rl.middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Two requests from the same IP but different ports
	for i, addr := range []string{"192.168.1.1:50000", "192.168.1.1:50001"} {
		req := httptest.NewRequest("POST", testLoginRoute, nil)
		req.RemoteAddr = addr
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: expected 200, got %d", i+1, rec.Code)
		}
	}

	// Third request from same IP, different port - should be blocked
	req3 := httptest.NewRequest("POST", testLoginRoute, nil)
	req3.RemoteAddr = "192.168.1.1:50002"
	rec3 := httptest.NewRecorder()
	handler.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusTooManyRequests {
		t.Fatalf("third request with different port: expected 429, got %d", rec3.Code)
	}
}

func TestCORSMiddleware_Dev(t *testing.T) {
	s := &Server{isDev: true}

	handler := s.corsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", testAPITest, nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200, rec.Code)
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "http://localhost:5173" {
		t.Fatal("expected CORS header in dev mode")
	}
}

func TestCORSMiddleware_DevOptions(t *testing.T) {
	s := &Server{isDev: true}

	handler := s.corsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called for OPTIONS preflight")
	}))

	req := httptest.NewRequest("OPTIONS", testAPITest, nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204 for OPTIONS, got %d", rec.Code)
	}
}

func TestCORSMiddleware_Production(t *testing.T) {
	s := &Server{isDev: false}

	handler := s.corsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", testAPITest, nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200, rec.Code)
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("expected no CORS header in production mode")
	}
}

func TestAdminOnly_Viewer(t *testing.T) {
	s := testServer(t)
	adminToken := registerAndGetAdminToken(t, s)
	viewerAccess := createViewerAndGetToken(t, s, adminToken)

	handler := s.authMiddleware(auth.TokenTypeAccess,
		s.adminOnly(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Fatal("handler should not be called for viewer")
		})))

	req := httptest.NewRequest("GET", "/admin", nil)
	req.Header.Set("Authorization", testBearerPrefix+viewerAccess)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}

func TestAdminOnly_Admin(t *testing.T) {
	s := testServer(t)
	adminAccess := registerAndGetAdminToken(t, s)

	called := false
	handler := s.authMiddleware(auth.TokenTypeAccess,
		s.adminOnly(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.WriteHeader(http.StatusOK)
		})))

	req := httptest.NewRequest("GET", "/admin", nil)
	req.Header.Set("Authorization", testBearerPrefix+adminAccess)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200, rec.Code)
	}
	if !called {
		t.Fatal("expected handler to be called for admin")
	}
}

func TestAuthMiddleware_InvalidToken(t *testing.T) {
	s := &Server{jwtSecret: "test-secret"}

	handler := s.authMiddleware(auth.TokenTypeAccess, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal(testHandlerNotCall)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer totally-invalid-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf(testExpected401, rec.Code)
	}
}

func TestLoggingMiddleware(t *testing.T) {
	called := false
	handler := loggingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !called {
		t.Fatal("expected handler to be called")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200, rec.Code)
	}
}

func TestClientIP_IgnoresXForwardedFor(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = testIP10054321
	req.Header.Set(testXForwardedFor, "203.0.113.1, 10.0.0.1")

	ip := clientIP(req)
	if ip != testIP10001 {
		t.Fatalf("expected '%s' (RemoteAddr), got '%s'", testIP10001, ip)
	}
}

func TestClientIP_FallsBackToRemoteAddr(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = testIP10054321
	// No X-Forwarded-For header

	ip := clientIP(req)
	if ip != testIP10001 {
		t.Fatalf("expected '10.0.0.1' (RemoteAddr fallback), got '%s'", ip)
	}
}

func TestClientIP_RemoteAddr(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.1:12345"

	ip := clientIP(req)
	if ip != testIP19216811 {
		t.Fatalf("expected '192.168.1.1', got '%s'", ip)
	}
}

func TestSecurityHeaders(t *testing.T) {
	dummy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := securityHeaders(dummy)

	t.Run("common headers on API request", func(t *testing.T) {
		req := httptest.NewRequest("GET", testServersPath, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		checks := map[string]string{
			"X-Frame-Options":        "DENY",
			"X-Content-Type-Options": "nosniff",
			"Referrer-Policy":        "strict-origin-when-cross-origin",
			"Permissions-Policy":     "camera=(), microphone=(), geolocation=()",
		}
		for header, want := range checks {
			if got := rec.Header().Get(header); got != want {
				t.Errorf("%s = %q, want %q", header, got, want)
			}
		}

		if csp := rec.Header().Get(testCSPHeader); csp != "" {
			t.Errorf("CSP should not be set on /api/ paths, got %q", csp)
		}
	})

	t.Run("CSP on root path", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Header().Get(testCSPHeader) == "" {
			t.Error("expected Content-Security-Policy on root path, got empty")
		}
	})

	t.Run("CSP on non-API path", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/dashboard", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Header().Get(testCSPHeader) == "" {
			t.Error("expected Content-Security-Policy on non-API path, got empty")
		}
	})
}

func TestContextHelpers(t *testing.T) {
	ctx := httptest.NewRequest("GET", "/", nil).Context()

	if UserIDFromContext(ctx) != "" {
		t.Fatal("expected empty user ID from bare context")
	}
	if UserRoleFromContext(ctx) != "" {
		t.Fatal("expected empty role from bare context")
	}
	if TokenTypeFromContext(ctx) != "" {
		t.Fatal("expected empty token type from bare context")
	}
}

// TestEvictOldest verifies that evictOldest removes the entry with the oldest
// last attempt while preserving the skipIP.
func TestEvictOldest(t *testing.T) {
	rl := newRateLimiter(10, time.Minute)

	now := time.Now()

	// Add entries with different timestamps
	rl.attempts[testIP1111] = []time.Time{now.Add(-3 * time.Minute)}
	rl.attempts["2.2.2.2"] = []time.Time{now.Add(-1 * time.Minute)}
	rl.attempts["3.3.3.3"] = []time.Time{now.Add(-2 * time.Minute)}

	// Evict oldest, skipping 1.1.1.1 (oldest but should be preserved)
	rl.evictOldest(testIP1111)

	// 1.1.1.1 should still exist (skipped)
	if _, ok := rl.attempts[testIP1111]; !ok {
		t.Fatal("expected 1.1.1.1 to be preserved (skipIP)")
	}
	// 3.3.3.3 should be evicted (oldest after skip)
	if _, ok := rl.attempts["3.3.3.3"]; ok {
		t.Fatal("expected 3.3.3.3 to be evicted")
	}
	// 2.2.2.2 should still exist
	if _, ok := rl.attempts["2.2.2.2"]; !ok {
		t.Fatal("expected 2.2.2.2 to remain")
	}
}

// TestEvictOldest_EmptyMap verifies evictOldest is a no-op on empty map.
func TestEvictOldest_EmptyMap(t *testing.T) {
	rl := newRateLimiter(10, time.Minute)
	rl.evictOldest(testIP1111) // should not panic
}

// TestEvictOldest_OnlySkipIP verifies evictOldest when only the skipIP exists.
func TestEvictOldest_OnlySkipIP(t *testing.T) {
	rl := newRateLimiter(10, time.Minute)
	rl.attempts[testIP1111] = []time.Time{time.Now()}
	rl.evictOldest(testIP1111)
	if _, ok := rl.attempts[testIP1111]; !ok {
		t.Fatal("expected skipIP to be preserved")
	}
}

// TestRateLimiter_EvictsWhenFull verifies that allow() evicts the oldest entry
// when the tracked IP count reaches maxTrackedIPs.
func TestRateLimiter_EvictsWhenFull(t *testing.T) {
	rl := newRateLimiter(5, time.Minute)

	// Fill the map to maxTrackedIPs
	for i := 0; i < maxTrackedIPs; i++ {
		ip := fmt.Sprintf("10.%d.%d.%d", i/(256*256), (i/256)%256, i%256)
		rl.attempts[ip] = []time.Time{time.Now()}
	}

	if len(rl.attempts) != maxTrackedIPs {
		t.Fatalf("expected %d entries, got %d", maxTrackedIPs, len(rl.attempts))
	}

	// Next allow() should evict one entry to make room
	newIP := "99.99.99.99"
	if !rl.allow(newIP) {
		t.Fatal("expected allow to succeed for new IP")
	}

	// Total should be maxTrackedIPs (one evicted, one added)
	if len(rl.attempts) != maxTrackedIPs {
		t.Fatalf("expected %d entries after eviction, got %d", maxTrackedIPs, len(rl.attempts))
	}
}

// TestRateLimiter_ExpiredEntriesCleanedUp verifies that expired entries are
// removed and the IP key is deleted when all entries expire.
func TestRateLimiter_ExpiredEntriesCleanedUp(t *testing.T) {
	rl := newRateLimiter(5, 100*time.Millisecond)

	rl.allow(testIP1234)
	time.Sleep(150 * time.Millisecond) // let the entry expire

	// Next call should clean up the expired entry
	if !rl.allow(testIP1234) {
		t.Fatal("expected allow after expiry")
	}

	// The map should have exactly one entry (the new one)
	if len(rl.attempts[testIP1234]) != 1 {
		t.Fatalf("expected 1 attempt after cleanup, got %d", len(rl.attempts[testIP1234]))
	}
}

// TestRateLimiter_Middleware_NoPort verifies the fallback path when
// RemoteAddr has no port (net.SplitHostPort fails).
func TestRateLimiter_Middleware_NoPort(t *testing.T) {
	rl := newRateLimiter(1, time.Minute)

	handler := rl.middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// RemoteAddr without port
	req := httptest.NewRequest("POST", testLoginRoute, nil)
	req.RemoteAddr = testIP10001 // no port
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200, rec.Code)
	}

	// Second request same IP (no port) - should be blocked
	req2 := httptest.NewRequest("POST", testLoginRoute, nil)
	req2.RemoteAddr = testIP10001
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", rec2.Code)
	}
}

func TestPasswordChange_RevokesExistingAccessToken(t *testing.T) {
	s := testServer(t)
	accessToken := registerAndGetAdminToken(t, s)

	changeBody, _ := json.Marshal(model.ChangePasswordRequest{
		CurrentPassword: testPassword,
		NewPassword:     "An0ther$ecurePass!",
	})
	changeReq := httptest.NewRequest("PUT", testPasswordPath, bytes.NewReader(changeBody))
	changeReq.Header.Set("Authorization", testBearerPrefix+accessToken)
	changeRec := httptest.NewRecorder()
	s.routes().ServeHTTP(changeRec, changeReq)

	if changeRec.Code != http.StatusOK {
		t.Fatalf("change password: expected 200, got %d: %s", changeRec.Code, changeRec.Body.String())
	}

	meReq := httptest.NewRequest("GET", testMePath, nil)
	meReq.Header.Set("Authorization", testBearerPrefix+accessToken)
	meRec := httptest.NewRecorder()
	s.routes().ServeHTTP(meRec, meReq)

	if meRec.Code != http.StatusUnauthorized {
		t.Fatalf("old access token after password change: expected 401, got %d: %s", meRec.Code, meRec.Body.String())
	}
}

// TestClientIP_RemoteAddrNoPort verifies clientIP when RemoteAddr has no port.
func TestClientIP_RemoteAddrNoPort(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = testIP19216811 // no port

	ip := clientIP(req)
	if ip != testIP19216811 {
		t.Fatalf("expected '192.168.1.1', got '%s'", ip)
	}
}

// TestAuthMiddleware_BlacklistedToken verifies that a blacklisted token is rejected.
func TestAuthMiddleware_BlacklistedToken(t *testing.T) {
	secret := testJWTSecret
	bl := auth.NewTokenBlacklist()
	s := &Server{jwtSecret: secret, tokenBlacklist: bl}

	access, _, _ := auth.GenerateTokenPair(secret, testUserID1, "admin", 0)

	// Parse the token to get its JTI and blacklist it
	claims, err := auth.ValidateToken(secret, access)
	if err != nil {
		t.Fatalf("validate token: %v", err)
	}
	bl.Add(claims.ID, claims.ExpiresAt.Time)

	handler := s.authMiddleware(auth.TokenTypeAccess, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called for blacklisted token")
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", testBearerPrefix+access)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf(testExpected401, rec.Code)
	}
}
