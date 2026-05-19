package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/model"
)

// TestGetSMTPConfig_Default verifies that an empty store returns a default config.
func TestGetSMTPConfig_Default(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	req := httptest.NewRequest("GET", testSMTPPath, nil)
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}

	var cfg model.SMTPConfig
	if err := json.NewDecoder(rec.Body).Decode(&cfg); err != nil {
		t.Fatalf(testDecodeRespErr, err)
	}

	if cfg.Host != "" {
		t.Errorf("expected empty host, got %q", cfg.Host)
	}
	if cfg.Password != "" {
		t.Errorf("expected empty password, got %q", cfg.Password)
	}
	// Default port is 587
	if cfg.Port != 587 {
		t.Errorf("expected default port 587, got %d", cfg.Port)
	}
}

// TestUpdateAndGetSMTPConfig verifies that a PUT saves and GET returns the config with masked password.
func TestUpdateAndGetSMTPConfig(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	// PUT new config
	putBody := mustJSON(t, model.SMTPConfig{
		Host:     testSMTPHost,
		Port:     465,
		Username: "user@example.com",
		Password: "supersecret",
		From:     testNoReplyEmail,
		TLS:      true,
		Enabled:  true,
	})
	putReq := httptest.NewRequest("PUT", testSMTPPath, putBody)
	putReq.Header.Set("Authorization", testBearerPrefix+token)
	putRec := httptest.NewRecorder()
	s.routes().ServeHTTP(putRec, putReq)

	if putRec.Code != http.StatusOK {
		t.Fatalf("expected 200 on PUT, got %d: %s", putRec.Code, putRec.Body.String())
	}

	var putResp map[string]string
	json.NewDecoder(putRec.Body).Decode(&putResp)
	if putResp["status"] != "ok" {
		t.Fatalf("expected status=ok, got %v", putResp["status"])
	}

	// GET the config back
	getReq := httptest.NewRequest("GET", testSMTPPath, nil)
	getReq.Header.Set("Authorization", testBearerPrefix+token)
	getRec := httptest.NewRecorder()
	s.routes().ServeHTTP(getRec, getReq)

	if getRec.Code != http.StatusOK {
		t.Fatalf("expected 200 on GET, got %d: %s", getRec.Code, getRec.Body.String())
	}

	var cfg model.SMTPConfig
	json.NewDecoder(getRec.Body).Decode(&cfg)

	if cfg.Host != testSMTPHost {
		t.Errorf("expected host smtp.example.com, got %q", cfg.Host)
	}
	if cfg.Port != 465 {
		t.Errorf("expected port 465, got %d", cfg.Port)
	}
	if cfg.Username != "user@example.com" {
		t.Errorf("expected username user@example.com, got %q", cfg.Username)
	}
	// Password must be masked
	if cfg.Password != "********" {
		t.Errorf("expected masked password, got %q", cfg.Password)
	}
	if cfg.From != testNoReplyEmail {
		t.Errorf("expected from noreply@example.com, got %q", cfg.From)
	}
	if !cfg.TLS {
		t.Error("expected TLS=true")
	}
	if !cfg.Enabled {
		t.Error("expected Enabled=true")
	}
}

// TestUpdateSMTPConfig_MaskedPasswordPreservesExisting verifies that sending "********"
// as the password does not overwrite the stored password.
func TestUpdateSMTPConfig_MaskedPasswordPreservesExisting(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	// First, store a real password
	firstPut := mustJSON(t, model.SMTPConfig{
		Host:     testSMTPHost,
		Port:     587,
		Password: "original-secret",
		From:     "from@example.com",
	})
	req1 := httptest.NewRequest("PUT", testSMTPPath, firstPut)
	req1.Header.Set("Authorization", testBearerPrefix+token)
	s.routes().ServeHTTP(httptest.NewRecorder(), req1)

	// Now update with masked password — original should be preserved
	secondPut := mustJSON(t, model.SMTPConfig{
		Host:     "smtp.updated.com",
		Port:     587,
		Password: "********",
		From:     "from@example.com",
	})
	req2 := httptest.NewRequest("PUT", testSMTPPath, secondPut)
	req2.Header.Set("Authorization", testBearerPrefix+token)
	rec2 := httptest.NewRecorder()
	s.routes().ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec2.Code, rec2.Body.String())
	}

	// Read password directly from store to confirm it wasn't overwritten
	storedPassword, err := s.store.GetConfig("smtp_password")
	if err != nil {
		t.Fatalf("get config smtp_password: %v", err)
	}
	// Password is now stored encrypted with "enc:" prefix
	decrypted, err := DecryptSMTPPassword(s.jwtSecret, storedPassword)
	if err != nil {
		t.Fatalf("failed to decrypt stored password: %v", err)
	}
	if decrypted != "original-secret" {
		t.Errorf("expected preserved password 'original-secret', got %q", decrypted)
	}

	// Host should have been updated
	storedHost, _ := s.store.GetConfig("smtp_host")
	if storedHost != "smtp.updated.com" {
		t.Errorf("expected updated host smtp.updated.com, got %q", storedHost)
	}
}

// TestGetNotificationPreferences_Default verifies that all event types are returned with defaults.
func TestGetNotificationPreferences_Default(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	req := httptest.NewRequest("GET", testPrefsPath, nil)
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)

	prefs, ok := resp["preferences"]
	if !ok {
		t.Fatal("expected 'preferences' key in response")
	}

	prefsSlice, ok := prefs.([]interface{})
	if !ok {
		t.Fatal("expected preferences to be an array")
	}

	if len(prefsSlice) != len(model.AllNotifyEvents) {
		t.Errorf("expected %d preferences, got %d", len(model.AllNotifyEvents), len(prefsSlice))
	}
}

// TestUpdateNotificationPreferences verifies that preferences can be toggled.
func TestUpdateNotificationPreferences(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	// Update a preference
	updateBody := mustJSON(t, model.NotificationPreferencesRequest{
		Preferences: []model.NotificationPrefUpdate{
			{EventType: model.NotifyAgentOnline, Enabled: true},
			{EventType: model.NotifyAgentOffline, Enabled: false},
		},
	})
	putReq := httptest.NewRequest("PUT", testPrefsPath, updateBody)
	putReq.Header.Set("Authorization", testBearerPrefix+token)
	putRec := httptest.NewRecorder()
	s.routes().ServeHTTP(putRec, putReq)

	if putRec.Code != http.StatusOK {
		t.Fatalf("expected 200 on PUT, got %d: %s", putRec.Code, putRec.Body.String())
	}

	var putResp map[string]string
	json.NewDecoder(putRec.Body).Decode(&putResp)
	if putResp["status"] != "ok" {
		t.Fatalf("expected status=ok, got %v", putResp)
	}

	// Verify by GETting preferences
	getReq := httptest.NewRequest("GET", testPrefsPath, nil)
	getReq.Header.Set("Authorization", testBearerPrefix+token)
	getRec := httptest.NewRecorder()
	s.routes().ServeHTTP(getRec, getReq)

	var resp map[string]interface{}
	json.NewDecoder(getRec.Body).Decode(&resp)

	prefsSlice := resp["preferences"].([]interface{})
	prefMap := make(map[string]bool)
	for _, p := range prefsSlice {
		entry := p.(map[string]interface{})
		prefMap[entry["event_type"].(string)] = entry["enabled"].(bool)
	}

	if !prefMap[model.NotifyAgentOnline] {
		t.Errorf("expected agent.online to be enabled")
	}
	if prefMap[model.NotifyAgentOffline] {
		t.Errorf("expected agent.offline to be disabled")
	}
}

// TestListNotificationLog_Empty verifies that an empty log returns an empty entries list.
func TestListNotificationLog_Empty(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	req := httptest.NewRequest("GET", testNotifLogPath, nil)
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)

	if _, ok := resp["entries"]; !ok {
		t.Fatal("expected 'entries' key in response")
	}
	if _, ok := resp["total"]; !ok {
		t.Fatal("expected 'total' key in response")
	}

	total := int(resp["total"].(float64))
	if total != 0 {
		t.Errorf("expected total=0, got %d", total)
	}

	entries := resp["entries"].([]interface{})
	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
}

// TestSMTPConfig_NonAdminForbidden verifies that non-admin users cannot access admin-only endpoints.
func TestSMTPConfig_NonAdminForbidden(t *testing.T) {
	s := testServer(t)
	adminToken := registerAndGetAdminToken(t, s)
	viewerToken := createViewerAndGetToken(t, s, adminToken)

	endpoints := []struct {
		method string
		path   string
	}{
		{"GET", testSMTPPath},
		{"PUT", testSMTPPath},
		{"POST", testSMTPTestPath},
		{"GET", testNotifLogPath},
	}

	for _, ep := range endpoints {
		req := httptest.NewRequest(ep.method, ep.path, nil)
		req.Header.Set("Authorization", testBearerPrefix+viewerToken)
		rec := httptest.NewRecorder()
		s.routes().ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Errorf("%s %s: expected 403 for viewer, got %d", ep.method, ep.path, rec.Code)
		}
	}
}

// TestTestSMTP_EmptyRecipient verifies that sending a test email without a recipient returns 400.
func TestTestSMTP_EmptyRecipient(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	body := mustJSON(t, model.SMTPTestRequest{Recipient: ""})
	req := httptest.NewRequest("POST", testSMTPTestPath, body)
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty recipient, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestTestSMTP_InvalidBody verifies that a malformed request body returns 400.
func TestTestSMTP_InvalidBody(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	req := httptest.NewRequest("POST", testSMTPTestPath, bytes.NewBufferString(testNotJSON))
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid body, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestTestSMTP_SMTPDialError verifies that a connection failure to the SMTP server returns 502.
func TestTestSMTP_SMTPDialError(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	// Configure SMTP with an unreachable host/port so SendEmail fails
	putBody := mustJSON(t, model.SMTPConfig{
		Host:    testLocalhost,
		Port:    19999, // unlikely to be listening
		From:    testNoReplyEmail,
		Enabled: true,
	})
	putReq := httptest.NewRequest("PUT", testSMTPPath, putBody)
	putReq.Header.Set("Authorization", testBearerPrefix+token)
	s.routes().ServeHTTP(httptest.NewRecorder(), putReq)

	body := mustJSON(t, model.SMTPTestRequest{Recipient: "admin@example.com"})
	req := httptest.NewRequest("POST", testSMTPTestPath, body)
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 when SMTP unreachable, got %d: %s", rec.Code, rec.Body.String())
	}
}

// mockSMTPServerForTest runs a minimal SMTP server and signals when a message is received.
func mockSMTPServerForTest(t *testing.T, ln net.Listener, done chan<- struct{}) {
	t.Helper()
	conn, err := ln.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	fmt.Fprintf(conn, "220 localhost ESMTP\r\n")
	buf := make([]byte, 4096)
	var allData string
	for {
		n, err := conn.Read(buf)
		if err != nil {
			break
		}
		data := string(buf[:n])
		allData += data
		if strings.HasPrefix(data, "EHLO") || strings.HasPrefix(data, "HELO") {
			fmt.Fprintf(conn, "250-localhost\r\n250 OK\r\n")
		} else if strings.HasPrefix(data, "MAIL FROM") {
			fmt.Fprintf(conn, testSMTP250OK)
		} else if strings.HasPrefix(data, "RCPT TO") {
			fmt.Fprintf(conn, testSMTP250OK)
		} else if strings.HasPrefix(data, "DATA") {
			fmt.Fprintf(conn, "354 Send data\r\n")
		} else if strings.Contains(data, "\r\n.\r\n") {
			fmt.Fprintf(conn, testSMTP250OK)
		} else if strings.HasPrefix(data, "QUIT") {
			fmt.Fprintf(conn, "221 Bye\r\n")
			break
		}
	}
	close(done)
}

// TestTestSMTP_Success verifies that a valid SMTP config and recipient returns 200.
func TestTestSMTP_Success(t *testing.T) {
	// Start a mock SMTP server
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("start mock smtp: %v", err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go mockSMTPServerForTest(t, ln, done)

	addr := ln.Addr().(*net.TCPAddr)

	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	// Configure SMTP pointing at mock server
	putBody := mustJSON(t, model.SMTPConfig{
		Host:    testLocalhost,
		Port:    addr.Port,
		From:    "noreply@veyport.local",
		Enabled: true,
	})
	putReq := httptest.NewRequest("PUT", testSMTPPath, putBody)
	putReq.Header.Set("Authorization", testBearerPrefix+token)
	s.routes().ServeHTTP(httptest.NewRecorder(), putReq)

	// Send test email
	body := mustJSON(t, model.SMTPTestRequest{Recipient: "admin@example.com"})
	req := httptest.NewRequest("POST", testSMTPTestPath, body)
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for successful test email, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]string
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["status"] != "sent" {
		t.Errorf("expected status=sent, got %q", resp["status"])
	}

	// Wait for mock server to receive the message
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Error("timeout waiting for mock SMTP to receive message")
	}
}

// getAdminUserID retrieves the admin user's ID directly from the store.
func getAdminUserID(t *testing.T, s *Server) string {
	t.Helper()
	users, err := s.store.ListUsers()
	if err != nil {
		t.Fatalf("list users: %v", err)
	}
	if len(users) == 0 {
		t.Fatal("no users found")
	}
	return users[0].ID
}

// TestListNotificationLog_WithEntries verifies that log entries are returned after being written.
func TestListNotificationLog_WithEntries(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)
	adminID := getAdminUserID(t, s)

	// Insert notification log entries using the real admin user ID
	errMsg := "dial error"
	if err := s.store.LogNotification("test-id-1", adminID, model.NotifyAgentOnline, "Agent online", "failed", &errMsg); err != nil {
		t.Fatalf(testLogNotifErr, err)
	}
	if err := s.store.LogNotification("test-id-2", adminID, model.NotifyAgentOffline, "Agent offline", "sent", nil); err != nil {
		t.Fatalf(testLogNotifErr, err)
	}

	req := httptest.NewRequest("GET", testNotifLogPath, nil)
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)

	total := int(resp["total"].(float64))
	if total != 2 {
		t.Errorf("expected total=2, got %d", total)
	}

	entries := resp["entries"].([]interface{})
	if len(entries) != 2 {
		t.Errorf("expected 2 entries, got %d", len(entries))
	}
}

// TestNotificationLog_Pagination verifies limit/offset parameters.
func TestNotificationLog_Pagination(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)
	adminID := getAdminUserID(t, s)

	// Insert 3 entries using the real admin user ID
	for i := 0; i < 3; i++ {
		id := fmt.Sprintf("log-id-%d", i)
		if err := s.store.LogNotification(id, adminID, model.NotifyAgentOnline, "subj", "sent", nil); err != nil {
			t.Fatalf(testLogNotifErr, err)
		}
	}

	// Fetch with limit=2, offset=1
	req := httptest.NewRequest("GET", "/api/notifications/log?limit=2&offset=1", nil)
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(testExpected200Body, rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)

	total := int(resp["total"].(float64))
	if total != 3 {
		t.Errorf("expected total=3, got %d", total)
	}

	entries := resp["entries"].([]interface{})
	if len(entries) != 2 {
		t.Errorf("expected 2 entries with limit=2, got %d", len(entries))
	}
}

// TestGetNotificationPreferences_Viewer verifies that a viewer can read their own preferences.
func TestGetNotificationPreferences_Viewer(t *testing.T) {
	s := testServer(t)
	adminToken := registerAndGetAdminToken(t, s)
	viewerToken := createViewerAndGetToken(t, s, adminToken)

	req := httptest.NewRequest("GET", testPrefsPath, nil)
	req.Header.Set("Authorization", testBearerPrefix+viewerToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for viewer preferences, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)

	if _, ok := resp["preferences"]; !ok {
		t.Fatal("expected 'preferences' key in response")
	}
}

// TestUpdateNotificationPreferences_Viewer verifies that a viewer can update their own preferences.
func TestUpdateNotificationPreferences_Viewer(t *testing.T) {
	s := testServer(t)
	adminToken := registerAndGetAdminToken(t, s)
	viewerToken := createViewerAndGetToken(t, s, adminToken)

	updateBody := mustJSON(t, model.NotificationPreferencesRequest{
		Preferences: []model.NotificationPrefUpdate{
			{EventType: model.NotifyAgentOnline, Enabled: false},
		},
	})
	req := httptest.NewRequest("PUT", testPrefsPath, updateBody)
	req.Header.Set("Authorization", testBearerPrefix+viewerToken)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for viewer update preferences, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestUpdateNotificationPreferences_InvalidBody verifies that a malformed body returns 400.
func TestUpdateNotificationPreferences_InvalidBody(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	req := httptest.NewRequest("PUT", testPrefsPath, bytes.NewBufferString(testNotJSON))
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid body, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestEncryptDecryptSMTPPassword verifies round-trip encrypt/decrypt of SMTP passwords.
func TestEncryptDecryptSMTPPassword(t *testing.T) {
	secret := "test-jwt-secret-256-bits-long!!!"
	password := "my-smtp-password"

	encrypted, err := encryptSMTPPassword(secret, password)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if !strings.HasPrefix(encrypted, "enc:") {
		t.Fatalf("expected enc: prefix, got %q", encrypted)
	}

	decrypted, err := DecryptSMTPPassword(secret, encrypted)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if decrypted != password {
		t.Fatalf("expected %q, got %q", password, decrypted)
	}
}

// TestDecryptSMTPPassword_LegacyPlaintext verifies backward compat with unencrypted passwords.
func TestDecryptSMTPPassword_LegacyPlaintext(t *testing.T) {
	decrypted, err := DecryptSMTPPassword("any-secret", "plain-password")
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if decrypted != "plain-password" {
		t.Fatalf("expected plain-password, got %q", decrypted)
	}
}

// TestDecryptSMTPPassword_InvalidHex verifies error on invalid hex after enc: prefix.
func TestDecryptSMTPPassword_InvalidHex(t *testing.T) {
	_, err := DecryptSMTPPassword("secret", "enc:not-valid-hex!!")
	if err == nil {
		t.Fatal("expected error for invalid hex")
	}
}

// TestDecryptSMTPPassword_WrongKey verifies error on wrong decryption key.
func TestDecryptSMTPPassword_WrongKey(t *testing.T) {
	encrypted, err := encryptSMTPPassword("correct-secret", "password")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	_, err = DecryptSMTPPassword("wrong-secret", encrypted)
	if err != nil {
		// Expected — wrong key should fail
		return
	}
	t.Fatal("expected error for wrong decryption key")
}

// TestValidateSMTPConfig verifies SMTP config validation.
func TestValidateSMTPConfig(t *testing.T) {
	const (
		testSMTPHost = "smtp.test.com"
		testSMTPFrom = "a@b.com"
	)
	tests := []struct {
		name    string
		cfg     model.SMTPConfig
		wantErr bool
	}{
		{"disabled config is always valid", model.SMTPConfig{Enabled: false}, false},
		{"valid enabled config", model.SMTPConfig{Enabled: true, Host: testSMTPHost, Port: 587, From: testSMTPFrom}, false},
		{"invalid port low", model.SMTPConfig{Enabled: true, Host: testSMTPHost, Port: 0, From: testSMTPFrom}, true},
		{"invalid port high", model.SMTPConfig{Enabled: true, Host: testSMTPHost, Port: 70000, From: testSMTPFrom}, true},
		{"missing from @", model.SMTPConfig{Enabled: true, Host: testSMTPHost, Port: 587, From: "invalid"}, true},
		{"missing host", model.SMTPConfig{Enabled: true, Host: "", Port: 587, From: testSMTPFrom}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSMTPConfig(tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateSMTPConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestUpdateNotificationPreferences_UnknownEventType verifies unknown event types are rejected.
func TestUpdateNotificationPreferences_UnknownEventType(t *testing.T) {
	s := testServer(t)
	token := registerAndGetAdminToken(t, s)

	body := bytes.NewBufferString(`{"preferences":[{"event_type":"fake.event","enabled":true}]}`)
	req := httptest.NewRequest("PUT", testPrefsPath, body)
	req.Header.Set("Authorization", testBearerPrefix+token)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown event type, got %d: %s", rec.Code, rec.Body.String())
	}
}
