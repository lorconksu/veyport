package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/session"
)

func TestSessions_CLIIdlePolicyThroughHTTP(t *testing.T) {
	h := StartHarness(t)
	setup := registerUser(t, h, sessionsAdminUser, "cli-idle@test.invalid", "TestPassword123!")
	secret := setupTOTP(t, h, setup)
	code, err := auth.GenerateValidCode(secret)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(model.TOTPEnableRequest{Code: code})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest("POST", "http://"+h.HTTPAddr+"/api/auth/totp/enable", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", bearerPrefix+setup)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "vey/cli-idle-regression")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	requireStatusOK(t, resp, "CLI enroll sign-in")
	var signedIn model.AuthResponse
	decodeJSON(t, resp, &signedIn, "CLI enroll sign-in")
	sid := sessionIDOf(t, h, signedIn.AccessToken)
	before := sessionByID(t, h, sid)
	if before.Kind != model.SessionKindCLI {
		t.Fatalf("CLI kind=%q", before.Kind)
	}
	ageSession(t, h, sid, 20*time.Minute)
	refresh := h.HTTPPost(t, refreshPath, model.RefreshRequest{RefreshToken: signedIn.RefreshToken}, "")
	defer refresh.Body.Close()
	requireStatusOK(t, refresh, "CLI refresh after20m")
	var pair model.TokenPair
	decodeJSON(t, refresh, &pair, "CLI refresh after20m")
	after := sessionByID(t, h, sid)
	if after.ExpiresAt == nil || before.ExpiresAt == nil || !after.ExpiresAt.Equal(*before.ExpiresAt) {
		t.Fatal("refresh moved12h absolute expiry")
	}
	listing := h.HTTPGet(t, authSessionsPath, pair.AccessToken)
	defer listing.Body.Close()
	requireStatusOK(t, listing, "CLI session listing")
	var result model.SessionListResponse
	decodeJSON(t, listing, &result, "CLI session listing")
	rows := result.Sessions
	if len(rows) != 1 || rows[0].IdleDeadlineAt == nil || !rows[0].IdleDeadlineAt.Equal(rows[0].LastSeenAt.Add(45*time.Minute)) {
		t.Fatalf("CLI listing deadline=%+v", rows)
	}
	ageSession(t, h, sid, 46*time.Minute)
	assertResponse(t, h.HTTPPost(t, refreshPath, model.RefreshRequest{RefreshToken: pair.RefreshToken}, ""), "CLI refresh after46m", http.StatusUnauthorized, session.MsgExpired)
	// A subsequent browser sign-in still receives the independent15m policy.
	totpToken := loginAndGetTOTPToken(t, h, sessionsAdminUser, "TestPassword123!")
	webAccess, _ := completeTOTPLogin(t, h, totpToken, secret)
	webSID := sessionIDOf(t, h, webAccess)
	if sessionByID(t, h, webSID).Kind != model.SessionKindWeb {
		t.Fatal("browser sign-in did not record webkind")
	}
	ageSession(t, h, webSID, 20*time.Minute)
	assertResponse(t, h.HTTPGet(t, mePath, webAccess), "web access after20m", http.StatusUnauthorized, session.MsgExpired)
}
