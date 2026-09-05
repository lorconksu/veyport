package server

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/wyiu/veyport/hub/internal/lockout"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/store"
)

// lockedMessage is the single refusal string used by every sign-in stage. Both
// stages must answer byte-for-byte identically, whether or not the supplied
// credential was correct, so a locked account cannot be used as a credential
// oracle (spec SC-002).
const lockedMessage = "account temporarily locked — try again later"

// lockedDetail is the audit detail recorded for an attempt refused because the
// account was already locked, distinguishing it from a real credential failure.
const lockedDetail = "account locked"

// lockoutPolicy returns the effective account-lockout policy, read fresh from
// the hub's config store on every call (see research.md R8: no caching, so a
// policy change takes effect on the very next login attempt).
func (s *Server) lockoutPolicy() lockout.Policy {
	return lockout.Load(s.store.GetConfig)
}

// refuseLocked answers a sign-in attempt against a locked account.
//
// It deliberately does not touch the failure counter: the attempt never reached
// a credential check, so counting it would both extend the operator's pain and
// destroy the counter's value as evidence that the credential path was skipped.
// The attempt is still recorded in the audit trail (with the "account locked"
// detail) but raises no notification — a locked account under attack would
// otherwise generate one email per attempt.
func (s *Server) refuseLocked(w http.ResponseWriter, r *http.Request, user *model.User) {
	detail := lockedDetail
	s.recordLoginFailure(r, &user.ID, user.Username, &detail, false)
	respondError(w, http.StatusLocked, lockedMessage)
}

// countFailure persists one credential failure and applies the lockout policy.
// A storage error is logged and swallowed: failing the request would turn a
// database hiccup into an authentication outage, and the caller is about to
// refuse the attempt anyway.
func (s *Server) countFailure(user *model.User) store.FailureResult {
	res, err := s.store.RecordLoginFailure(user.ID, s.now(), s.lockoutPolicy())
	if err != nil {
		log.Printf("warning: failed to record login failure for user %s: %v", user.ID, err)
		return store.FailureResult{}
	}
	return res
}

// recordFailureAndMaybeLock records a password-stage credential failure: it
// counts the failure, writes the existing user.login_failed audit entry (and
// notification, when the caller asks for one), and fires the lockout side
// effects if this failure is the one that locked the account.
func (s *Server) recordFailureAndMaybeLock(r *http.Request, user *model.User, detail *string, notify bool) store.FailureResult {
	res := s.countFailure(user)
	s.recordLoginFailure(r, &user.ID, user.Username, detail, notify)
	if res.NewlyLocked {
		s.onAccountLocked(r, user, res)
	}
	return res
}

// recordTOTPFailure is the code-stage counterpart. The one-time-code stage
// keeps its own user.login_totp_failed audit event rather than the generic
// login_failed one, so it cannot reuse recordFailureAndMaybeLock.
func (s *Server) recordTOTPFailure(r *http.Request, user *model.User) store.FailureResult {
	res := s.countFailure(user)
	ip := clientIP(r)
	s.auditLogRequest(r, model.AuditEntry{
		ID:        uuid.NewString(),
		UserID:    &user.ID,
		Action:    model.AuditUserLoginTOTPFailed,
		IPAddress: &ip,
	})
	if res.NewlyLocked {
		s.onAccountLocked(r, user, res)
	}
	return res
}

// onAccountLocked runs the side effects of the unlocked → locked transition:
// the user.locked audit entry and the account-locked notification. The store
// reports NewlyLocked for exactly one caller even under concurrent failures, so
// this runs once per lockout — the notification cannot storm.
//
// The lock is attributed to the system actor with a success outcome: no user
// performed it, and the control working as designed is a success (same shape as
// the system entries written by rotate.go). Neither side effect may fail the
// request; the attempt is refused either way.
func (s *Server) onAccountLocked(r *http.Request, user *model.User, res store.FailureResult) {
	ip := clientIP(r)
	lockedUntil := ""
	if res.LockedUntil != nil {
		lockedUntil = res.LockedUntil.UTC().Format(time.RFC3339)
	}

	detail := lockedAuditDetail(s.lockoutPolicy().Threshold, ip, lockedUntil)
	s.auditLogRequest(r, model.AuditEntry{
		UserID:       &user.ID,
		Action:       model.AuditUserLocked,
		Target:       &user.ID,
		Detail:       &detail,
		IPAddress:    &ip,
		Outcome:      model.AuditOutcomeSuccess,
		ActorType:    model.AuditActorTypeSystem,
		ResourceType: stringPtr("user"),
	})

	if s.notifier == nil {
		return
	}
	s.notifier.Notify(model.NotifyAccountLocked, map[string]string{
		"username":     user.Username,
		"ip":           ip,
		"locked_until": lockExpiryForDisplay(res.LockedUntil),
		"timestamp":    s.now().Format(model.NotifyTimestampFormat),
	})
}

// lockedAuditDetail renders the JSON detail carried by a user.locked entry.
// A marshalling failure falls back to a plain-text detail: an audit entry with
// a degraded detail beats no audit entry at all.
func lockedAuditDetail(threshold int, ip, lockedUntil string) string {
	payload := struct {
		Threshold   int    `json:"threshold"`
		IP          string `json:"ip"`
		LockedUntil string `json:"locked_until"`
	}{Threshold: threshold, IP: ip, LockedUntil: lockedUntil}

	encoded, err := json.Marshal(payload)
	if err != nil {
		log.Printf("warning: failed to encode lock audit detail: %v", err)
		return "account locked after repeated failed sign-in attempts"
	}
	return string(encoded)
}

// lockExpiryForDisplay renders the lock expiry for the notification body. The
// email template does plain {{key}} substitution with no conditionals, so a
// lock that never expires on its own must arrive here already worded.
func lockExpiryForDisplay(lockedUntil *time.Time) string {
	if lockedUntil == nil || lockedUntil.Equal(lockout.NoAutoUnlock) {
		return "until an administrator intervenes"
	}
	return lockedUntil.UTC().Format(model.NotifyTimestampFormat)
}

// recordLoginSuccess clears the failure streak and any lock, and stamps the
// last-login time. Called once sign-in has actually completed — not after the
// password stage alone. As with countFailure, a storage error must never fail a
// sign-in that has already succeeded.
func (s *Server) recordLoginSuccess(user *model.User) {
	if err := s.store.RecordLoginSuccess(user.ID, s.now()); err != nil {
		log.Printf("warning: failed to record login success for user %s: %v", user.ID, err)
	}
}
