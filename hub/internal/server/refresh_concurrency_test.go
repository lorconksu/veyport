package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/model"
)

// These tests use real HTTP, password/TOTP sign-in, the production router and
// its middleware. A CLI process releases its refresh lock before its later API
// call; another process must be able to refresh without revoking that call.
func refreshHTTPFixture(t *testing.T) (*Server, *testClock, *httptest.Server, *model.User, string) {
	t.Helper()
	s, clock := sessionServer(t)
	user := newLocalUser(t, s, "parallel_refresh", lockoutTestPassword)
	secret := enableTOTPForUser(t, s, user)
	httpServer := httptest.NewServer(s.routes())
	t.Cleanup(httpServer.Close)
	httpServer.Client().Timeout = 5 * time.Second
	return s, clock, httpServer, user, secret
}

func refreshHTTPPost(h *httptest.Server, path string, body any) (int, model.TokenPair, error) {
	encoded, err := json.Marshal(body)
	if err != nil {
		return 0, model.TokenPair{}, err
	}
	response, err := h.Client().Post(h.URL+path, "application/json", bytes.NewReader(encoded))
	if err != nil {
		return 0, model.TokenPair{}, err
	}
	defer response.Body.Close()
	var pair model.TokenPair
	if response.StatusCode == http.StatusOK {
		err = json.NewDecoder(response.Body).Decode(&pair)
	} else {
		_, err = io.Copy(io.Discard, response.Body)
	}
	return response.StatusCode, pair, err
}

func refreshHTTPSignIn(t *testing.T, s *Server, h *httptest.Server, user *model.User, secret string) model.TokenPair {
	t.Helper()
	body, err := json.Marshal(model.LoginRequest{Username: user.Username, Password: lockoutTestPassword})
	if err != nil {
		t.Fatal(err)
	}
	response, err := h.Client().Post(h.URL+"/api/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("password sign-in status=%d", response.StatusCode)
	}
	var login model.LoginResponse
	if err := json.NewDecoder(response.Body).Decode(&login); err != nil {
		t.Fatal(err)
	}
	status, pair, err := refreshHTTPPost(h, "/api/auth/login/totp", model.LoginTOTPRequest{
		TOTPToken: login.TOTPToken, Code: validTOTPCode(t, secret, s.now()),
	})
	if err != nil || status != http.StatusOK || pair.AccessToken == "" || pair.RefreshToken == "" {
		t.Fatalf("MFA sign-in status=%d err=%v", status, err)
	}
	return pair
}

func refreshHTTPGet(t *testing.T, h *httptest.Server, path, accessToken string, want int) {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, h.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", testBearerPrefix+accessToken)
	response, err := h.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != want {
		t.Fatalf("authenticated GET %s status=%d, want %d", path, response.StatusCode, want)
	}
	_, _ = io.Copy(io.Discard, response.Body)
}

func TestRefreshHTTPConcurrentSessionsKeepEarlierAccessValid(t *testing.T) {
	s, clock, h, user, secret := refreshHTTPFixture(t)
	first := refreshHTTPSignIn(t, s, h, user, secret)
	clock.advance(31 * time.Second)
	second := refreshHTTPSignIn(t, s, h, user, secret)
	before := reloadUser(t, s, user.ID)

	type result struct {
		status int
		pair   model.TokenPair
		err    error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	for _, token := range []string{first.RefreshToken, second.RefreshToken} {
		go func() {
			<-start
			status, pair, err := refreshHTTPPost(h, testRefreshPath, model.RefreshRequest{RefreshToken: token})
			results <- result{status, pair, err}
		}()
	}
	close(start)
	var rotated []model.TokenPair
	for range 2 {
		got := <-results
		if got.err != nil || got.status != http.StatusOK {
			t.Fatalf("independent session refresh status=%d err=%v", got.status, got.err)
		}
		rotated = append(rotated, got.pair)
	}
	// Read each pair only after both refreshes have completed, just as a
	// process can resume its API request after another process rotated.
	for _, pair := range rotated {
		refreshHTTPGet(t, h, testMePath, pair.AccessToken, http.StatusOK)
	}
	refreshHTTPGet(t, h, testMePath, first.AccessToken, http.StatusOK)
	refreshHTTPGet(t, h, testMePath, second.AccessToken, http.StatusOK)
	if after := reloadUser(t, s, user.ID); after.TokenGeneration != before.TokenGeneration {
		t.Fatal("routine refresh advanced the user-wide revocation generation")
	}
}

func TestRefreshHTTPReplayHasOneWinnerAndDoesNotRevokeOtherSessions(t *testing.T) {
	s, clock, h, user, secret := refreshHTTPFixture(t)
	first := refreshHTTPSignIn(t, s, h, user, secret)
	clock.advance(31 * time.Second)
	other := refreshHTTPSignIn(t, s, h, user, secret)

	var wg sync.WaitGroup
	start := make(chan struct{})
	results := make(chan struct {
		status int
		pair   model.TokenPair
		err    error
	}, 6)
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			status, pair, err := refreshHTTPPost(h, testRefreshPath, model.RefreshRequest{RefreshToken: first.RefreshToken})
			results <- struct {
				status int
				pair   model.TokenPair
				err    error
			}{status, pair, err}
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	winners := 0
	var winner model.TokenPair
	for result := range results {
		if result.err != nil {
			t.Fatal(result.err)
		}
		switch result.status {
		case http.StatusOK:
			winners++
			winner = result.pair
		case http.StatusUnauthorized:
		default:
			t.Fatalf("refresh replay status=%d", result.status)
		}
	}
	if winners != 1 {
		t.Fatalf("refresh replay winners=%d, want exactly one", winners)
	}
	for _, access := range []string{first.AccessToken, other.AccessToken, winner.AccessToken} {
		refreshHTTPGet(t, h, testMePath, access, http.StatusOK)
	}
	status, _, err := refreshHTTPPost(h, testRefreshPath, model.RefreshRequest{RefreshToken: other.RefreshToken})
	if err != nil || status != http.StatusOK {
		t.Fatalf("other session refresh status=%d err=%v", status, err)
	}
	status, _, err = refreshHTTPPost(h, testRefreshPath, model.RefreshRequest{RefreshToken: winner.RefreshToken})
	if err != nil || status != http.StatusOK {
		t.Fatalf("winning replacement refresh status=%d err=%v", status, err)
	}
}

func TestSpentRefreshDoesNotTouchActivityOrSurviveExplicitRevocation(t *testing.T) {
	s, clock := sessionServer(t)
	user, access, refresh, sid := quickSecurityUser(t, s, "refresh-activity", model.RoleViewer)
	response := postRefresh(t, s, refresh)
	if response.Code != http.StatusOK {
		t.Fatalf("first rotation status=%d", response.Code)
	}
	var pair model.TokenPair
	if err := json.Unmarshal(response.Body.Bytes(), &pair); err != nil {
		t.Fatal(err)
	}
	before := reloadSession(t, s, sid)
	clock.advance(2 * time.Minute)
	response = postRefresh(t, s, refresh)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("spent refresh status=%d", response.Code)
	}
	if after := reloadSession(t, s, sid); !after.LastSeenAt.Equal(before.LastSeenAt) {
		t.Fatal("spent refresh replay extended session activity")
	}
	if _, err := s.store.IncrementTokenGeneration(user.ID); err != nil {
		t.Fatal(err)
	}
	if response := postRefresh(t, s, pair.RefreshToken); response.Code != http.StatusUnauthorized {
		t.Fatalf("explicitly revoked replacement refresh status=%d", response.Code)
	}
	for _, token := range []string{access, pair.AccessToken} {
		if response := authedGet(t, s, testMePath, token); response.Code != http.StatusUnauthorized {
			t.Fatalf("explicitly revoked access status=%d", response.Code)
		}
	}
}

func TestSessionTokensNeverPublishAnUncommittedRefresh(t *testing.T) {
	for _, failure := range []string{"read_only", "closed"} {
		t.Run(failure, func(t *testing.T) {
			s, _ := sessionServer(t)
			u, _, refresh, sid := quickSecurityUser(t, s, "refresh-storage-failure", model.RoleViewer)
			if failure == "read_only" {
				if _, err := s.store.DB().Exec("PRAGMA query_only=ON"); err != nil {
					t.Fatal(err)
				}
			} else if err := s.store.Close(); err != nil {
				t.Fatal(err)
			}
			access, replacement, err := s.issueSessionTokens(context.Background(), u, sid, refresh, s.now())
			if err == nil || access != "" || replacement != "" {
				t.Fatal("tokens returned without durable refresh authority")
			}
		})
	}
}
