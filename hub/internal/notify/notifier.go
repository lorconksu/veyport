package notify

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
)

const queueSize = 100

// securityEvents are notification types that must not be silently dropped
// when the queue is full. They get a dedicated overflow slot.
var securityEvents = map[string]bool{
	model.NotifyLoginFailed:     true,
	model.NotifyUserCreated:     true,
	model.NotifyTOTPChanged:     true,
	model.NotifyPasswordChanged: true,
	model.NotifyAuditDegraded:   true,
	model.NotifyAuditRecovered:  true,
}

type emailJob struct {
	To        string
	UserID    string
	EventType string
	Subject   string
	Body      string
}

// DebounceDelay is how long to wait before sending agent offline notifications.
// If the agent reconnects within this window, the offline notification is cancelled.
var DebounceDelay = 60 * time.Second

// smtpConfigCacheTTL is how long the SMTP config is cached before re-reading from DB.
const smtpConfigCacheTTL = 60 * time.Second

// Notifier dispatches email notifications asynchronously via a background worker.
type Notifier struct {
	store         *store.Store
	jwtSecret     string
	queue         chan emailJob
	priorityQueue chan emailJob // overflow for security-critical notifications
	done          chan struct{}
	wg            sync.WaitGroup
	mu            sync.Mutex
	debounce      map[string]*time.Timer // keyed by "eventType:serverID"

	// SMTP config cache — avoids 7 DB reads per email send
	smtpMu      sync.RWMutex
	smtpCfg     model.SMTPConfig
	smtpCfgTime time.Time
}

// New creates a Notifier and starts the background worker goroutine.
// The jwtSecret is used to decrypt encrypted SMTP passwords stored in the DB.
// If jwtSecret is empty, encrypted passwords cannot be decrypted (backward compatible).
func New(st *store.Store, jwtSecret ...string) *Notifier {
	secret := ""
	if len(jwtSecret) > 0 {
		secret = jwtSecret[0]
	}
	n := &Notifier{
		store:         st,
		jwtSecret:     secret,
		queue:         make(chan emailJob, queueSize),
		priorityQueue: make(chan emailJob, queueSize),
		done:          make(chan struct{}),
		debounce:      make(map[string]*time.Timer),
	}
	n.wg.Add(1)
	go n.worker()
	return n
}

// Close cancels pending debounced notifications, stops the background worker,
// and waits for it to finish.
func (n *Notifier) Close() {
	n.mu.Lock()
	for key, timer := range n.debounce {
		timer.Stop()
		delete(n.debounce, key)
	}
	n.mu.Unlock()
	close(n.queue)
	close(n.priorityQueue)
	n.wg.Wait()
	close(n.done)
}

// enqueueJob attempts to send a job to the main queue. For security-critical
// events, if the main queue is full, it falls back to the priority queue so
// that security notifications are never silently dropped.
func (n *Notifier) enqueueJob(job emailJob) bool {
	select {
	case n.queue <- job:
		return true
	default:
		if securityEvents[job.EventType] {
			select {
			case n.priorityQueue <- job:
				log.Printf("notify: main queue full, security event %s routed to priority queue", job.EventType)
				return true
			default:
				return false
			}
		}
		return false
	}
}

// Notify loads SMTP config, resolves recipients, renders emails, and enqueues jobs.
// Agent offline/online events are debounced: if an agent reconnects within DebounceDelay,
// the offline notification is cancelled and the online notification is suppressed.
func (n *Notifier) Notify(eventType string, context map[string]string) {
	serverID := context["server_id"]

	// Agent online: cancel any pending offline notification for this server.
	// Only suppress the online notification if we actually cancelled a pending offline.
	if eventType == model.NotifyAgentOnline && serverID != "" {
		if n.cancelDebounce(model.NotifyAgentOffline + ":" + serverID) {
			return // Suppress — this was just a brief disconnect/reconnect cycle
		}
		// No pending offline — this is a genuine new connection, send the notification
	}

	// Agent offline: debounce — only send if agent stays offline for DebounceDelay
	if eventType == model.NotifyAgentOffline && serverID != "" {
		n.scheduleDebounced(eventType, context)
		return
	}

	// All other events: send immediately
	n.enqueueNotification(eventType, context)
}

// scheduleDebounced delays sending a notification. If cancelled before the timer
// fires, the notification is never sent.
func (n *Notifier) scheduleDebounced(eventType string, context map[string]string) {
	key := eventType + ":" + context["server_id"]

	n.mu.Lock()
	defer n.mu.Unlock()

	// Cancel any existing timer for this key
	if timer, ok := n.debounce[key]; ok {
		timer.Stop()
	}

	n.debounce[key] = time.AfterFunc(DebounceDelay, func() {
		n.mu.Lock()
		delete(n.debounce, key)
		n.mu.Unlock()
		log.Printf("notify: debounce expired for %s, sending notification", key)
		n.enqueueNotification(eventType, context)
	})
}

// cancelDebounce stops a pending debounced notification.
// Returns true if a pending notification was actually cancelled.
func (n *Notifier) cancelDebounce(key string) bool {
	n.mu.Lock()
	defer n.mu.Unlock()

	if timer, ok := n.debounce[key]; ok {
		timer.Stop()
		delete(n.debounce, key)
		log.Printf("notify: cancelled debounced notification for %s (agent reconnected)", key)
		return true
	}
	return false
}

// enqueueNotification resolves recipients and enqueues email jobs.
func (n *Notifier) enqueueNotification(eventType string, context map[string]string) {
	cfg := LoadSMTPConfig(n.store, n.jwtSecret)
	if !cfg.Enabled || cfg.Host == "" {
		return
	}

	recipients, err := n.store.GetEnabledRecipients(eventType)
	if err != nil {
		log.Printf("notify: get enabled recipients for %q: %v", eventType, err)
		return
	}

	subject, body := RenderEmail(eventType, context)

	for _, r := range recipients {
		if r.Email == "" {
			continue
		}
		job := emailJob{
			To:        r.Email,
			UserID:    r.ID,
			EventType: eventType,
			Subject:   subject,
			Body:      body,
		}
		if !n.enqueueJob(job) {
			log.Printf("notify: queue full, dropping notification for user %s event %s", r.ID, eventType)
		}
	}
}

// drainQueue processes all remaining jobs from a channel until it is closed.
func (n *Notifier) drainQueue(ch <-chan emailJob) {
	for job := range ch {
		n.processJob(job)
	}
}

// worker processes queued email jobs until both queue channels are closed.
// Priority queue is checked first on each iteration to ensure security-critical
// notifications are processed ahead of normal ones.
func (n *Notifier) worker() {
	defer n.wg.Done()

	for {
		var job emailJob
		var ok bool

		// Priority queue takes precedence
		select {
		case job, ok = <-n.priorityQueue:
			if !ok {
				n.drainQueue(n.queue)
				return
			}
		default:
			// No priority jobs — check both queues
			select {
			case job, ok = <-n.priorityQueue:
				if !ok {
					n.drainQueue(n.queue)
					return
				}
			case job, ok = <-n.queue:
				if !ok {
					n.drainQueue(n.priorityQueue)
					return
				}
			}
		}

		n.processJob(job)
	}
}

// sanitizeErrorForLog returns a generic error message for storage in the
// notification log, stripping internal details like hostnames and credentials
// that SMTP servers may include in error responses.
func sanitizeErrorForLog(err error) string {
	msg := err.Error()
	// Keep the high-level error category (e.g., "smtp auth:", "smtp tls dial:")
	// but strip server-specific details after the first colon pair
	if strings.Contains(msg, ": ") {
		parts := strings.SplitN(msg, ": ", 3)
		if len(parts) >= 2 {
			return parts[0] + ": " + parts[1]
		}
	}
	return "email delivery failed"
}

// cachedSMTPConfig returns the SMTP config, re-reading from DB only if the cache is stale.
func (n *Notifier) cachedSMTPConfig() model.SMTPConfig {
	n.smtpMu.RLock()
	if time.Since(n.smtpCfgTime) < smtpConfigCacheTTL {
		cfg := n.smtpCfg
		n.smtpMu.RUnlock()
		return cfg
	}
	n.smtpMu.RUnlock()

	cfg := LoadSMTPConfig(n.store, n.jwtSecret)
	n.smtpMu.Lock()
	n.smtpCfg = cfg
	n.smtpCfgTime = time.Now()
	n.smtpMu.Unlock()
	return cfg
}

// InvalidateSMTPCache forces the next config read to hit the DB.
func (n *Notifier) InvalidateSMTPCache() {
	n.smtpMu.Lock()
	n.smtpCfgTime = time.Time{}
	n.smtpMu.Unlock()
}

func (n *Notifier) processJob(job emailJob) {
	cfg := n.cachedSMTPConfig()

	err := SendEmail(cfg, job.To, job.Subject, job.Body)

	id := uuid.New().String()
	status := "sent"
	var errMsg *string
	if err != nil {
		status = "failed"
		sanitized := sanitizeErrorForLog(err)
		errMsg = &sanitized
		// Full error logged server-side for debugging
		log.Printf("notify: send email to %s failed: %v", job.To, err)
	}

	if logErr := n.store.LogNotification(id, job.UserID, job.EventType, job.Subject, status, errMsg); logErr != nil {
		log.Printf("notify: log notification: %v", logErr)
	}
}

// LoadSMTPConfig reads SMTP settings from the store's _config table.
// If jwtSecret is provided, encrypted passwords (with "enc:" prefix) are decrypted.
// Legacy plaintext passwords are returned as-is for backward compatibility.
func LoadSMTPConfig(st *store.Store, jwtSecret ...string) model.SMTPConfig {
	get := func(key string) string {
		v, _ := st.GetConfig(key)
		return v
	}

	port := 587
	if p := get("smtp_port"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil {
			port = parsed
		}
	}

	tls := false
	if t := get("smtp_tls"); t == "true" || t == "1" {
		tls = true
	}

	enabled := false
	if e := get("smtp_enabled"); e == "true" || e == "1" {
		enabled = true
	}

	password := get("smtp_password")
	if password != "" && len(jwtSecret) > 0 && jwtSecret[0] != "" {
		password = decryptSMTPPassword(jwtSecret[0], password)
	}

	return model.SMTPConfig{
		Host:     get("smtp_host"),
		Port:     port,
		Username: get("smtp_username"),
		Password: password,
		From:     get("smtp_from"),
		TLS:      tls,
		Enabled:  enabled,
	}
}

// decryptSMTPPassword decrypts an SMTP password if it has the "enc:" prefix.
// Returns plaintext as-is for backward compatibility with unencrypted passwords.
func decryptSMTPPassword(jwtSecret, stored string) string {
	if !strings.HasPrefix(stored, "enc:") {
		return stored // legacy plaintext
	}
	data, err := hex.DecodeString(stored[4:])
	if err != nil {
		log.Printf("notify: invalid encrypted SMTP password format: %v", err)
		return "" // return empty rather than corrupted data
	}
	key := deriveKey(jwtSecret)
	decrypted, err := decrypt(data, key)
	if err != nil {
		log.Printf("notify: failed to decrypt SMTP password: %v", err)
		return "" // return empty rather than corrupted data
	}
	return string(decrypted)
}

// deriveKey derives a 256-bit AES key from the given secret using SHA-256.
func deriveKey(secret string) []byte {
	h := sha256.Sum256([]byte(secret))
	return h[:]
}

// decrypt decrypts ciphertext using AES-256-GCM.
func decrypt(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce := ciphertext[:gcm.NonceSize()]
	return gcm.Open(nil, nonce, ciphertext[gcm.NonceSize():], nil)
}
