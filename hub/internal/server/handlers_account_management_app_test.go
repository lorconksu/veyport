package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/wyiu/veyport/hub/internal/model"
)

func managementApplicationCredential(t *testing.T, s *Server, app *model.Application, userID, anchorID string) (string, *model.ApplicationSession) {
	t.Helper()
	now := s.now()
	user, err := s.store.GetUserByID(userID)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.EnsureApplicationAnchor(model.ApplicationAnchor{ID: anchorID, UserID: userID, CompletedMFAAt: now, TokenGeneration: user.TokenGeneration}); err != nil {
		t.Fatal(err)
	}
	revision, err := s.store.ApplicationAccessRevision(userID)
	if err != nil {
		t.Fatal(err)
	}
	digest := uuid.NewString()
	ticket := model.ApplicationLaunchTicket{Digest: digest, ApplicationID: app.ID, UserID: userID, AnchorID: anchorID, Hostname: app.PublicHostname, Path: "/", ConfigVersion: app.ConfigVersion, AccessRevision: revision, ExpiresAt: now.Add(time.Minute)}
	if err := s.store.CreateApplicationTicket(ticket); err != nil {
		t.Fatal(err)
	}
	cookie := uuid.NewString()
	session := model.ApplicationSession{ID: uuid.NewString(), CredentialDigest: refreshDigest(cookie), ExpiresAt: now.Add(time.Hour)}
	if _, err := s.store.ConsumeApplicationTicket(digest, app.PublicHostname, session, now); err != nil {
		t.Fatal(err)
	}
	stored, err := s.store.ApplicationSessionByID(session.ID)
	if err != nil {
		t.Fatal(err)
	}
	return cookie, stored
}

func TestPasswordResetRevokesActualApplicationCookieTicketAndLiveStream(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(managementApplicationBackend))
	defer backend.Close()
	s, app, oldCookie := applicationFixture(t, backend.URL)
	portal := func(method, path, token string, body any) *httptest.ResponseRecorder {
		request := httptest.NewRequest(method, "https://portal.example.test"+path, mustJSON(t, body))
		if token != "" {
			request.Header.Set("Authorization", "Bearer "+token)
		}
		response := httptest.NewRecorder()
		s.routes().ServeHTTP(response, request)
		return response
	}
	original, err := s.store.GetApplicationSession(refreshDigest(oldCookie))
	if err != nil {
		t.Fatal(err)
	}
	secret := managementMFASecret
	if err := s.store.UpdateUserTOTP(original.UserID, &secret, true); err != nil {
		t.Fatal(err)
	}
	cookie, session := managementApplicationCredential(t, s, app, original.UserID, uuid.NewString())
	// Independent user has an explicit grant and a separate anchor/session.
	other := &model.User{ID: uuid.NewString(), Username: uuid.NewString(), Email: "other@test.invalid", Role: model.RoleViewer, TOTPEnabled: true}
	if err := s.store.CreateUser(other); err != nil {
		t.Fatal(err)
	}
	if _, err := s.store.DB().Exec("INSERT INTO application_grants(application_id,kind,subject_id) VALUES(?,'user',?)", app.ID, other.ID); err != nil {
		t.Fatal(err)
	}
	otherCookie, otherSession := managementApplicationCredential(t, s, app, other.ID, uuid.NewString())
	pendingSecret, err := applicationSecret()
	if err != nil {
		t.Fatal(err)
	}
	pending := model.ApplicationLaunchTicket{Digest: refreshDigest(pendingSecret), ApplicationID: app.ID, UserID: session.UserID, AnchorID: session.AnchorID, Hostname: app.PublicHostname, Path: "/", ConfigVersion: app.ConfigVersion, AccessRevision: session.AccessRevision, ExpiresAt: s.now().Add(time.Minute)}
	if err := s.store.CreateApplicationTicket(pending); err != nil {
		t.Fatal(err)
	}
	admin := &model.User{ID: uuid.NewString(), Username: uuid.NewString(), Email: "admin@test.invalid", Role: model.RoleAdmin, TOTPEnabled: true, TOTPSecret: &secret}
	if err := s.store.CreateUser(admin); err != nil {
		t.Fatal(err)
	}
	adminToken, _, _ := sessionTokenPair(t, s, admin.ID)
	gateway := httptest.NewServer(s.routes())
	defer gateway.Close()
	client := &http.Client{Timeout: 8 * time.Second}

	targetStream := openManagementApplicationStream(t, client, gateway.URL, app, cookie)
	defer targetStream.Body.Close()
	otherStream := openManagementApplicationStream(t, client, gateway.URL, app, otherCookie)
	defer otherStream.Body.Close()
	targetEnded := make(chan struct{})
	otherEnded := make(chan struct{})
	go func() { io.Copy(io.Discard, targetStream.Body); close(targetEnded) }()
	go func() { io.Copy(io.Discard, otherStream.Body); close(otherEnded) }()
	user, err := s.store.GetUserByID(session.UserID)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	reset := portal("POST", "/api/users/"+user.ID+"/password-reset", adminToken, map[string]int{"expected_revision": user.TokenGeneration})
	if reset.Code != 200 {
		t.Fatalf("reset status %d", reset.Code)
	}
	select {
	case <-targetEnded:
	case <-time.After(5 * time.Second):
		t.Fatal("reset did not close application stream within five seconds")
	}
	if time.Since(started) > 5*time.Second {
		t.Fatal("password reset stream closure exceeded bound")
	}
	select {
	case <-otherEnded:
		t.Fatal("reset closed another user's app stream")
	default:
	}
	assertManagementApplicationAuthorityRevoked(t, s, session, user.ID)
	// Complete the real password+MFA recovery route, then prove the old authority
	// stays revoked even after mandatory replacement has been cleared.
	temporary := managementJSON(t, reset)["temporary_password"].(string)
	completeManagementApplicationRecovery(t, s, user, temporary, secret, portal)
	refused := httptest.NewRecorder()
	s.routes().ServeHTTP(refused, appRequest(app, cookie, "GET", "/"))
	if refused.Code == 200 {
		t.Fatal("old application cookie resurrected after recovery completion")
	}
	exchange := httptest.NewRequest("POST", "https://"+app.PublicHostname+"/_veyport/launch", strings.NewReader("ticket="+pendingSecret))
	exchange.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	exchange.Header.Set("Origin", s.applicationPortalOrigin)
	exchanged := httptest.NewRecorder()
	s.exchangeApplicationLaunch(exchanged, exchange, app)
	if exchanged.Code == 200 || len(exchanged.Result().Cookies()) > 0 {
		t.Fatal("old launch ticket exchanged after recovery completion")
	}
	allowed := httptest.NewRecorder()
	s.routes().ServeHTTP(allowed, appRequest(app, otherCookie, "GET", "/"))
	if allowed.Code != 200 || allowed.Body.String() != "allowed" {
		t.Fatalf("other user's application access changed: status %d", allowed.Code)
	}
	currentOther, err := s.store.ApplicationSessionByID(otherSession.ID)
	if err != nil || currentOther.EndedAt != nil || s.checkApplicationSession(context.Background(), app, currentOther, false) != nil {
		t.Fatal("other user's durable authority revoked")
	}
}

func managementApplicationBackend(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/events" {
		w.Write([]byte("allowed"))
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Write([]byte("data: ready\n\n"))
	w.(http.Flusher).Flush()
	<-r.Context().Done()
}

func openManagementApplicationStream(t *testing.T, client *http.Client, gatewayURL string, app *model.Application, credential string) *http.Response {
	t.Helper()
	req, err := http.NewRequest("GET", gatewayURL+"/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = app.PublicHostname
	req.AddCookie(&http.Cookie{Name: applicationCookie, Value: credential})
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 200 {
		t.Fatalf("stream status %d", response.StatusCode)
	}
	if _, err := io.ReadFull(response.Body, make([]byte, 13)); err != nil {
		t.Fatal(err)
	}
	return response
}

func assertManagementApplicationAuthorityRevoked(t *testing.T, s *Server, session *model.ApplicationSession, userID string) {
	t.Helper()
	live, err := s.store.ApplicationSessionByID(session.ID)
	if err != nil || live.EndedAt == nil {
		t.Fatal("application session remained durable after reset")
	}
	anchor, err := s.store.GetApplicationAnchor(session.AnchorID)
	if err != nil || anchor.RevokedAt == nil {
		t.Fatal("application anchor remained durable after reset")
	}
	var tickets int
	if err := s.store.DB().QueryRow("SELECT COUNT(*) FROM application_launch_tickets WHERE user_id=?", userID).Scan(&tickets); err != nil || tickets != 0 {
		t.Fatal("reset retained a launch ticket")
	}
}

type managementPortalCall func(method, path, token string, body any) *httptest.ResponseRecorder

func completeManagementApplicationRecovery(t *testing.T, s *Server, user *model.User, temporary, secret string, portal managementPortalCall) {
	t.Helper()
	primary := portal("POST", "/api/auth/login", "", model.LoginRequest{Username: user.Username, Password: temporary})
	if primary.Code != 202 {
		t.Fatalf("recovery login status %d", primary.Code)
	}
	challenge := managementJSON(t, primary)["totp_token"].(string)
	mfa := portal("POST", "/api/auth/login/totp", "", model.LoginTOTPRequest{TOTPToken: challenge, Code: validTOTPCode(t, secret, s.now())})
	if mfa.Code != 200 {
		t.Fatalf("recovery MFA status %d", mfa.Code)
	}
	recovery := managementJSON(t, mfa)["recovery_token"].(string)
	completed := portal("POST", "/api/auth/password/recovery", recovery, map[string]string{"new_password": "NewPermanent!Password123"})
	if completed.Code != 200 {
		t.Fatalf("recovery completion status %d", completed.Code)
	}
}
