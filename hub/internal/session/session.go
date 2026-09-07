// Package session holds the pure decision logic for server-side session
// records: given a session's timestamps, the current time and the policy, is
// the session still usable, and if not, why.
//
// Exactly one verdict applies at any instant, resolved by a fixed precedence:
//
//	ended > absolute expiry > idle expiry > ok
//
// An explicit end (a revoke, a sign-out, an account disable) therefore outranks
// both timers, and the absolute lifetime outranks the idle limit, so a session
// that has run out of time is reported as such rather than as merely idle. The
// precedence is encoded once, in Evaluate, and used by the authentication
// middleware, the token refresh path and the session listing handlers, so all
// three agree by construction.
//
// The package is pure: no database, no clock, no logging, no mutable global
// state. Callers supply now, and pass UTC times because the hub stores UTC.
// Persistence lives in internal/store and enforcement in internal/server.
package session

import (
	"time"

	"github.com/wyiu/veyport/hub/internal/lockout"
	"github.com/wyiu/veyport/hub/internal/model"
)

// Canonical refusal messages. They say only that the session is gone and what
// to do about it: which of the three causes applied is an audit-trail detail,
// not something the refused caller is told, and "expired" covers both timers so
// that a user cannot infer the configured limits from the wording.
const (
	// MsgExpired is returned to a caller whose session ran out of time, on
	// either the idle or the absolute limit.
	MsgExpired = "session expired — sign in again"
	// MsgEnded is returned to a caller whose session was ended deliberately:
	// revoked by an administrator or by the user, or closed by a sign-out or
	// an account disable.
	MsgEnded = "session ended — sign in again"
)

// State is the subset of a session row that determines whether it is usable.
//
// The two nullable times are pointers because each may be absent: a session
// created while the absolute limit was disabled has no ExpiresAt, and a live
// session has no EndedAt. CreatedAt is always present; it is carried for
// callers that render the row, not for the verdict itself.
type State struct {
	// CreatedAt is when the session was established.
	CreatedAt time.Time
	// LastSeenAt is the most recent request made on the session; it starts
	// the idle clock.
	LastSeenAt time.Time
	// ExpiresAt is the absolute expiry stamped at creation; nil means the
	// session has no absolute limit (the policy was 0 when it was created).
	ExpiresAt *time.Time
	// EndedAt is when the session was ended or marked expired; nil while live.
	EndedAt *time.Time
}

// Verdict is the result of evaluating a session.
type Verdict int

// The four possible verdicts, in the precedence order Evaluate applies.
const (
	// VerdictOK means the session is live and within both limits.
	VerdictOK Verdict = iota
	// VerdictEnded means the session was ended deliberately.
	VerdictEnded
	// VerdictExpiredIdle means the session went unused for longer than the
	// idle limit allows.
	VerdictExpiredIdle
	// VerdictExpiredAbsolute means the session reached its absolute expiry.
	VerdictExpiredAbsolute
)

// String returns the verdict's stable name. For the two expiry verdicts it is
// also the end reason persisted on the row and reported in the audit detail,
// so these strings match model.SessionEndExpiredIdle and
// model.SessionEndExpiredAbsolute.
func (v Verdict) String() string {
	switch v {
	case VerdictOK:
		return "ok"
	case VerdictEnded:
		return "ended"
	case VerdictExpiredIdle:
		return model.SessionEndExpiredIdle
	case VerdictExpiredAbsolute:
		return model.SessionEndExpiredAbsolute
	default:
		return "unknown"
	}
}

// Evaluate returns the session's verdict at now under policy p.
//
// The absolute limit uses !now.Before(*ExpiresAt), so a session is expired at
// the instant its expiry is reached. The idle limit uses a strict comparison,
// so a session whose gap is exactly the idle limit is still live and only
// expires an instant later: that is what makes the boundary case in the spec
// work, where the access-token lifetime equals the default idle limit and a
// refresh arriving exactly on the limit must succeed.
//
// A SessionIdle of zero or less disables the idle limit entirely, and a nil
// ExpiresAt disables the absolute one; with both disabled a session stays live
// until something ends it.
func Evaluate(st State, now time.Time, p lockout.Policy) Verdict {
	switch {
	case st.EndedAt != nil:
		return VerdictEnded
	case st.ExpiresAt != nil && !now.Before(*st.ExpiresAt):
		return VerdictExpiredAbsolute
	case p.SessionIdle > 0 && now.Sub(st.LastSeenAt) > p.SessionIdle:
		return VerdictExpiredIdle
	default:
		return VerdictOK
	}
}

// IdleDeadline returns when the session will go idle: its last-seen time plus
// the idle limit. It returns nil when the policy disables the idle limit, in
// which case there is no deadline to show and the field is omitted from the
// API payload.
//
// The value moves every time the session is used, so it is derived on read
// rather than stored.
func IdleDeadline(st State, p lockout.Policy) *time.Time {
	if p.SessionIdle <= 0 {
		return nil
	}
	deadline := st.LastSeenAt.Add(p.SessionIdle)
	return &deadline
}

// Message returns the refusal message for a verdict, or the empty string when
// the verdict does not refuse access. Both expiry causes share MsgExpired.
func Message(v Verdict) string {
	switch v {
	case VerdictEnded:
		return MsgEnded
	case VerdictExpiredIdle, VerdictExpiredAbsolute:
		return MsgExpired
	default:
		return ""
	}
}

// StateFromModel projects a stored session row onto the fields Evaluate needs.
// The pointers are copied as they are, so an absent timestamp stays absent.
// s must not be nil; callers reach this only after a successful store read.
func StateFromModel(s *model.Session) State {
	return State{
		CreatedAt:  s.CreatedAt,
		LastSeenAt: s.LastSeenAt,
		ExpiresAt:  s.ExpiresAt,
		EndedAt:    s.EndedAt,
	}
}
