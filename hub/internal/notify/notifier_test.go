package notify

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
)

const (
	testSMTPMailHost    = "mail.example.com"
	testLegacyPlaintext = "legacy-plain"
)

// encrypt is a test helper that encrypts data using AES-256-GCM (mirrors auth.Encrypt).
func encrypt(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func testStoreAndUser(t *testing.T) *store.Store {
	t.Helper()
	// Use a temporary file-based database to avoid WAL + in-memory SQLite
	// connection-pool reuse issues with the modernc driver under -count > 1.
	f, err := os.CreateTemp("", "notifytest-*.db")
	if err != nil {
		t.Fatalf("create temp db file: %v", err)
	}
	dbPath := f.Name()
	f.Close()
	st, err := store.New(dbPath)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	t.Cleanup(func() {
		st.Close()
		os.Remove(dbPath)
	})
	st.CreateUser(&model.User{
		ID: "user1", Username: "admin", Email: "admin@test.com",
		PasswordHash: "$2a$12$dummy", Role: model.RoleAdmin,
		TOTPEnabled: true,
	})
	return st
}

// TestNotifier_NoopWhenDisabled verifies that when SMTP is not configured,
// Notify returns without panicking and no notification log entries are created.
func TestNotifier_NoopWhenDisabled(t *testing.T) {
	st := testStoreAndUser(t)
	n := New(st)
	defer n.Close()

	// SMTP is not configured in the store, so Notify should be a no-op
	n.Notify(model.NotifyAgentOffline, map[string]string{
		"server_name": "test-agent",
	})

	// Allow the worker a moment to process anything that might have been enqueued
	time.Sleep(20 * time.Millisecond)

	// Verify no notification log entries were created
	entries, total, err := st.ListNotificationLog(100, 0)
	if err != nil {
		t.Fatalf("list notification log: %v", err)
	}
	if total != 0 {
		t.Errorf("expected 0 log entries, got %d: %v", total, entries)
	}
}

// TestNotifier_SendsWhenConfigured verifies that when SMTP is fully configured and enabled,
// Notify enqueues a job, the worker sends the email via the mock SMTP server,
// and a "sent" entry appears in the notification log.
func TestNotifier_SendsWhenConfigured(t *testing.T) {
	st := testStoreAndUser(t)

	// Start a mock SMTP server
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("start mock SMTP server: %v", err)
	}
	defer ln.Close()

	received := make(chan string, 1)
	go mockSMTPServer(t, ln, received)

	addr := ln.Addr().(*net.TCPAddr)

	// Configure SMTP in the store
	smtpCfgs := []struct{ k, v string }{
		{"smtp_host", testLocalhost},
		{"smtp_port", strconv.Itoa(addr.Port)},
		{"smtp_from", "noreply@veyport.local"},
		{"smtp_enabled", "true"},
	}
	for _, c := range smtpCfgs {
		if err := st.SetConfig(c.k, c.v); err != nil {
			t.Fatalf("SetConfig %s: %v", c.k, err)
		}
	}

	// Use NotifyLoginFailed (not debounced) so the test doesn't need to wait 60s.
	// Enable it for user1 explicitly since its default is ON.
	n := New(st)
	defer n.Close()

	n.Notify(model.NotifyLoginFailed, map[string]string{
		"username":  "admin",
		"ip":        "1.2.3.4",
		"timestamp": time.Now().UTC().Format(model.NotifyTimestampFormat),
	})

	// Wait for the mock SMTP server to receive the message
	select {
	case data := <-received:
		t.Logf("mock SMTP received: %q", data)
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for mock SMTP server to receive email")
	}

	// Allow the worker goroutine to finish logging
	time.Sleep(50 * time.Millisecond)

	entries, total, err := st.ListNotificationLog(100, 0)
	if err != nil {
		t.Fatalf("ListNotificationLog: %v", err)
	}
	if total == 0 {
		t.Fatal("expected at least one notification log entry, got 0")
	}

	found := false
	for _, e := range entries {
		if e.Status == "sent" && e.EventType == model.NotifyLoginFailed {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected a 'sent' log entry for %s, got: %+v", model.NotifyLoginFailed, entries)
	}
}

// TestNotifier_SendFailure verifies that when SMTP send fails, a "failed" log entry is created.
func TestNotifier_SendFailure(t *testing.T) {
	st := testStoreAndUser(t)

	// Configure SMTP with an unreachable port to force send failure
	smtpCfgs := []struct{ k, v string }{
		{"smtp_host", testLocalhost},
		{"smtp_port", "1"}, // port 1 is unreachable
		{"smtp_from", testFromEmail},
		{"smtp_enabled", "true"},
		{"smtp_tls", "false"},
	}
	for _, c := range smtpCfgs {
		if err := st.SetConfig(c.k, c.v); err != nil {
			t.Fatalf("SetConfig %s: %v", c.k, err)
		}
	}

	n := New(st)
	defer n.Close()

	// Use NotifyLoginFailed (not debounced) so the test doesn't need to wait 60s.
	n.Notify(model.NotifyLoginFailed, map[string]string{
		"username":  "admin",
		"ip":        "1.2.3.4",
		"timestamp": "2026-03-29 12:00:00 UTC",
	})

	// Wait for worker to process and log the failure
	time.Sleep(500 * time.Millisecond)

	entries, total, err := st.ListNotificationLog(50, 0)
	if err != nil {
		t.Fatalf("ListNotificationLog: %v", err)
	}
	if total != 1 {
		t.Fatalf("expected 1 log entry, got %d", total)
	}
	if entries[0].Status != "failed" {
		t.Fatalf("expected 'failed' status, got %q", entries[0].Status)
	}
}

// TestNotifier_DebounceAgentOffline verifies that an agent offline notification
// is cancelled if the agent reconnects within the debounce window.
func TestNotifier_DebounceAgentOffline(t *testing.T) {
	st := testStoreAndUser(t)

	// Set debounce to a short duration for testing
	origDelay := DebounceDelay
	DebounceDelay = 200 * time.Millisecond
	t.Cleanup(func() { DebounceDelay = origDelay })

	// Configure SMTP (even though it won't connect, we need it enabled to pass the check)
	st.SetConfig("smtp_host", testLocalhost)
	st.SetConfig("smtp_port", "1")
	st.SetConfig("smtp_from", testFromEmail)
	st.SetConfig("smtp_enabled", "true")

	n := New(st)
	defer n.Close()

	// Agent goes offline
	n.Notify(model.NotifyAgentOffline, map[string]string{
		"server_name": testServerNameWeb01, "server_id": "srv-1",
		"timestamp": testTimestamp20260330,
	})

	// Agent comes back within debounce window
	time.Sleep(50 * time.Millisecond)
	n.Notify(model.NotifyAgentOnline, map[string]string{
		"server_name": testServerNameWeb01, "server_id": "srv-1",
		"timestamp": "2026-03-30 12:00:01 UTC",
	})

	// Wait past debounce window
	time.Sleep(300 * time.Millisecond)

	// No notification should have been sent (offline was cancelled, online was suppressed)
	_, total, _ := st.ListNotificationLog(50, 0)
	if total != 0 {
		t.Fatalf("expected 0 notifications (debounced), got %d", total)
	}
}

// TestNotifier_DebounceExpires verifies that if the agent stays offline past
// the debounce window, the notification IS sent.
func TestNotifier_DebounceExpires(t *testing.T) {
	st := testStoreAndUser(t)

	origDelay := DebounceDelay
	DebounceDelay = 100 * time.Millisecond
	t.Cleanup(func() { DebounceDelay = origDelay })

	st.SetConfig("smtp_host", testLocalhost)
	st.SetConfig("smtp_port", "1") // will fail to send, but that's fine
	st.SetConfig("smtp_from", testFromEmail)
	st.SetConfig("smtp_enabled", "true")

	n := New(st)
	defer n.Close()

	n.Notify(model.NotifyAgentOffline, map[string]string{
		"server_name": testServerNameWeb01, "server_id": "srv-1",
		"timestamp": testTimestamp20260330,
	})

	// Wait past debounce window + processing time
	time.Sleep(400 * time.Millisecond)

	_, total, _ := st.ListNotificationLog(50, 0)
	if total != 1 {
		t.Fatalf("expected 1 notification after debounce expired, got %d", total)
	}
}

// TestSanitizeErrorForLog verifies that error messages are properly sanitized.
func TestSanitizeErrorForLog(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{
			"two-part error",
			fmt.Errorf("smtp auth: 535 5.7.8 Username and Password not accepted"),
			"smtp auth: 535 5.7.8 Username and Password not accepted",
		},
		{
			"three-part error strips third part",
			fmt.Errorf("smtp tls dial: dial tcp: connect: connection refused"),
			"smtp tls dial: dial tcp",
		},
		{
			"no colon returns generic",
			fmt.Errorf("connection refused"),
			"email delivery failed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeErrorForLog(tt.err)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

// TestEnqueueJob_MainQueue verifies that normal jobs go to the main queue.
func TestEnqueueJob_MainQueue(t *testing.T) {
	st := testStoreAndUser(t)
	n := New(st)
	defer n.Close()

	job := emailJob{
		To: testFromEmail, UserID: "u1",
		EventType: model.NotifyAgentOffline,
		Subject:   "Test", Body: "body",
	}
	if !n.enqueueJob(job) {
		t.Fatal("expected enqueue to succeed")
	}
}

// TestEnqueueJob_PriorityQueueFallback verifies security events fall back to priority queue.
func TestEnqueueJob_PriorityQueueFallback(t *testing.T) {
	st := testStoreAndUser(t)
	n := &Notifier{
		store:         st,
		queue:         make(chan emailJob, 1),
		priorityQueue: make(chan emailJob, 1),
		done:          make(chan struct{}),
		debounce:      make(map[string]*time.Timer),
	}

	// Fill main queue
	n.queue <- emailJob{To: "fill@test.com", EventType: "filler"}

	// Security event should go to priority queue when main is full
	secJob := emailJob{
		To: "security@test.com", UserID: "u1",
		EventType: model.NotifyLoginFailed,
		Subject:   "Login Failed", Body: "body",
	}
	if !n.enqueueJob(secJob) {
		t.Fatal("expected security event to be enqueued via priority queue")
	}

	// Verify it's in the priority queue
	select {
	case got := <-n.priorityQueue:
		if got.EventType != model.NotifyLoginFailed {
			t.Fatalf("expected %s, got %s", model.NotifyLoginFailed, got.EventType)
		}
	default:
		t.Fatal("expected job in priority queue")
	}
}

// TestEnqueueJob_BothQueuesFull verifies that when both queues are full, enqueue returns false.
func TestEnqueueJob_BothQueuesFull(t *testing.T) {
	st := testStoreAndUser(t)
	n := &Notifier{
		store:         st,
		queue:         make(chan emailJob, 1),
		priorityQueue: make(chan emailJob, 1),
		done:          make(chan struct{}),
		debounce:      make(map[string]*time.Timer),
	}

	// Fill both queues
	n.queue <- emailJob{EventType: "filler"}
	n.priorityQueue <- emailJob{EventType: "filler"}

	secJob := emailJob{EventType: model.NotifyLoginFailed}
	if n.enqueueJob(secJob) {
		t.Fatal("expected enqueue to fail when both queues full")
	}
}

// TestEnqueueJob_NonSecurityDropped verifies non-security events are dropped when main queue full.
func TestEnqueueJob_NonSecurityDropped(t *testing.T) {
	st := testStoreAndUser(t)
	n := &Notifier{
		store:         st,
		queue:         make(chan emailJob, 1),
		priorityQueue: make(chan emailJob, 1),
		done:          make(chan struct{}),
		debounce:      make(map[string]*time.Timer),
	}

	// Fill main queue
	n.queue <- emailJob{EventType: "filler"}

	// Non-security event should be dropped
	job := emailJob{EventType: model.NotifyAgentOffline}
	if n.enqueueJob(job) {
		t.Fatal("expected non-security event to be dropped when main queue full")
	}
}

// TestCachedSMTPConfig verifies the SMTP config cache reads from DB on first call
// and returns cached value on subsequent calls.
func TestCachedSMTPConfig(t *testing.T) {
	st := testStoreAndUser(t)
	st.SetConfig("smtp_host", testSMTPMailHost)
	st.SetConfig("smtp_port", "465")
	st.SetConfig("smtp_tls", "true")
	st.SetConfig("smtp_enabled", "true")

	n := New(st)
	defer n.Close()

	cfg := n.cachedSMTPConfig()
	if cfg.Host != testSMTPMailHost {
		t.Fatalf("expected host %q, got %q", testSMTPMailHost, cfg.Host)
	}
	if cfg.Port != 465 {
		t.Fatalf("expected port 465, got %d", cfg.Port)
	}
	if !cfg.TLS {
		t.Fatal("expected TLS=true")
	}
	if !cfg.Enabled {
		t.Fatal("expected Enabled=true")
	}

	// Second call should return cached value
	cfg2 := n.cachedSMTPConfig()
	if cfg2.Host != cfg.Host {
		t.Fatal("expected cached config to match")
	}
}

// TestInvalidateSMTPCache verifies that InvalidateSMTPCache forces a re-read.
func TestInvalidateSMTPCache(t *testing.T) {
	st := testStoreAndUser(t)
	st.SetConfig("smtp_host", "old.example.com")
	st.SetConfig("smtp_enabled", "true")

	n := New(st)
	defer n.Close()

	// Prime the cache
	cfg1 := n.cachedSMTPConfig()
	if cfg1.Host != "old.example.com" {
		t.Fatalf("expected old.example.com, got %s", cfg1.Host)
	}

	// Update the DB and invalidate
	st.SetConfig("smtp_host", "new.example.com")
	n.InvalidateSMTPCache()

	cfg2 := n.cachedSMTPConfig()
	if cfg2.Host != "new.example.com" {
		t.Fatalf("expected new.example.com after invalidation, got %s", cfg2.Host)
	}
}

// TestLoadSMTPConfig_Defaults verifies LoadSMTPConfig returns correct defaults.
func TestLoadSMTPConfig_Defaults(t *testing.T) {
	st := testStoreAndUser(t)

	cfg := LoadSMTPConfig(st)
	if cfg.Host != "" {
		t.Fatalf("expected empty host, got %s", cfg.Host)
	}
	if cfg.Port != 587 {
		t.Fatalf("expected default port 587, got %d", cfg.Port)
	}
	if cfg.TLS {
		t.Fatal("expected TLS=false by default")
	}
	if cfg.Enabled {
		t.Fatal("expected Enabled=false by default")
	}
}

// TestLoadSMTPConfig_InvalidPort verifies LoadSMTPConfig uses default port for invalid port.
func TestLoadSMTPConfig_InvalidPort(t *testing.T) {
	st := testStoreAndUser(t)
	st.SetConfig("smtp_port", "not-a-number")

	cfg := LoadSMTPConfig(st)
	if cfg.Port != 587 {
		t.Fatalf("expected default port 587 for invalid port string, got %d", cfg.Port)
	}
}

// TestLoadSMTPConfig_TLSVariants verifies various truthy values for smtp_tls.
func TestLoadSMTPConfig_TLSVariants(t *testing.T) {
	st := testStoreAndUser(t)

	st.SetConfig("smtp_tls", "1")
	cfg := LoadSMTPConfig(st)
	if !cfg.TLS {
		t.Fatal("expected TLS=true for smtp_tls=1")
	}

	st.SetConfig("smtp_tls", "false")
	cfg = LoadSMTPConfig(st)
	if cfg.TLS {
		t.Fatal("expected TLS=false for smtp_tls=false")
	}
}

// TestNotifier_AgentOnlineWithoutPendingOffline verifies that agent.online sends
// notification when there is no pending offline to cancel.
func TestNotifier_AgentOnlineWithoutPendingOffline(t *testing.T) {
	st := testStoreAndUser(t)

	st.SetConfig("smtp_host", testLocalhost)
	st.SetConfig("smtp_port", "1")
	st.SetConfig("smtp_from", testFromEmail)
	st.SetConfig("smtp_enabled", "true")

	// Enable agent.online for user1
	st.SetNotificationPreference("user1", model.NotifyAgentOnline, true)

	n := New(st)
	defer n.Close()

	// Send agent.online without any prior offline — should enqueue (will fail to send, that's ok)
	n.Notify(model.NotifyAgentOnline, map[string]string{
		"server_name": testServerNameWeb01, "server_id": "srv-1",
		"timestamp": testTimestamp20260330,
	})

	// Wait for worker to process
	time.Sleep(500 * time.Millisecond)

	// Should have a log entry (failed send, but enqueued)
	_, total, _ := st.ListNotificationLog(50, 0)
	if total != 1 {
		t.Fatalf("expected 1 notification log entry, got %d", total)
	}
}

// TestDecryptSMTPPassword_Plaintext verifies that a plaintext password (no "enc:" prefix)
// is returned as-is for backward compatibility.
func TestDecryptSMTPPassword_Plaintext(t *testing.T) {
	result := decryptSMTPPassword("any-secret", "my-plain-password")
	if result != "my-plain-password" {
		t.Fatalf("expected plaintext password returned as-is, got %q", result)
	}
}

// TestDecryptSMTPPassword_Encrypted verifies that an encrypted password with "enc:" prefix
// is decrypted correctly.
func TestDecryptSMTPPassword_Encrypted(t *testing.T) {
	secret := "test-jwt-secret-for-encrypt"
	key := deriveKey(secret)

	// Encrypt a password
	plaintext := "super-secret-smtp-pass"
	ciphertext, err := encrypt([]byte(plaintext), key)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	stored := "enc:" + fmt.Sprintf("%x", ciphertext)

	result := decryptSMTPPassword(secret, stored)
	if result != plaintext {
		t.Fatalf("expected decrypted password %q, got %q", plaintext, result)
	}
}

// TestDecryptSMTPPassword_InvalidHex verifies that an invalid hex value after "enc:" returns empty.
func TestDecryptSMTPPassword_InvalidHex(t *testing.T) {
	result := decryptSMTPPassword("secret", "enc:not-valid-hex!!")
	if result != "" {
		t.Fatalf("expected empty string for invalid hex, got %q", result)
	}
}

// TestDecryptSMTPPassword_WrongKey verifies that decrypting with wrong key returns empty.
func TestDecryptSMTPPassword_WrongKey(t *testing.T) {
	key := deriveKey("correct-secret")
	ciphertext, _ := encrypt([]byte("password"), key)
	stored := "enc:" + fmt.Sprintf("%x", ciphertext)

	result := decryptSMTPPassword("wrong-secret", stored)
	if result != "" {
		t.Fatalf("expected empty string for wrong decryption key, got %q", result)
	}
}

// TestDecryptSMTPPassword_TooShort verifies that a very short ciphertext returns empty.
func TestDecryptSMTPPassword_TooShort(t *testing.T) {
	result := decryptSMTPPassword("secret", "enc:0102")
	if result != "" {
		t.Fatalf("expected empty string for too-short ciphertext, got %q", result)
	}
}

// TestLoadSMTPConfig_WithEncryptedPassword verifies LoadSMTPConfig decrypts passwords.
func TestLoadSMTPConfig_WithEncryptedPassword(t *testing.T) {
	st := testStoreAndUser(t)

	secret := "my-jwt-secret-for-test"
	key := deriveKey(secret)
	plainPassword := "smtp-real-password"
	ciphertext, err := encrypt([]byte(plainPassword), key)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	encryptedStored := "enc:" + fmt.Sprintf("%x", ciphertext)

	st.SetConfig("smtp_password", encryptedStored)
	st.SetConfig("smtp_host", testSMTPMailHost)
	st.SetConfig("smtp_enabled", "true")

	cfg := LoadSMTPConfig(st, secret)
	if cfg.Password != plainPassword {
		t.Fatalf("expected decrypted password %q, got %q", plainPassword, cfg.Password)
	}
}

// TestLoadSMTPConfig_WithPlaintextPassword verifies LoadSMTPConfig handles legacy plaintext.
func TestLoadSMTPConfig_WithPlaintextPassword(t *testing.T) {
	st := testStoreAndUser(t)

	st.SetConfig("smtp_password", testLegacyPlaintext)
	st.SetConfig("smtp_host", testSMTPMailHost)
	st.SetConfig("smtp_enabled", "true")

	cfg := LoadSMTPConfig(st, "any-secret")
	if cfg.Password != testLegacyPlaintext {
		t.Fatalf("expected plaintext password %q, got %q", testLegacyPlaintext, cfg.Password)
	}
}

// TestLoadSMTPConfig_NoSecret verifies LoadSMTPConfig without jwtSecret returns raw password.
func TestLoadSMTPConfig_NoSecret(t *testing.T) {
	st := testStoreAndUser(t)

	st.SetConfig("smtp_password", "enc:deadbeef")

	cfg := LoadSMTPConfig(st)
	if cfg.Password != "enc:deadbeef" {
		t.Fatalf("expected raw password when no secret, got %q", cfg.Password)
	}
}

// TestNotifier_Close verifies that Close() doesn't hang or deadlock.
func TestNotifier_Close(t *testing.T) {
	st := testStoreAndUser(t)
	n := New(st)

	done := make(chan struct{})
	go func() {
		n.Close()
		close(done)
	}()

	select {
	case <-done:
		// success
	case <-time.After(3 * time.Second):
		t.Fatal("Close() timed out — possible deadlock")
	}
}
