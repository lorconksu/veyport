// Package account derives an account's lifecycle status from the columns of a
// user row, a policy and a point in time.
//
// Exactly one status applies at any instant, resolved by a fixed precedence:
//
//	disabled > dormant > locked > active
//
// An administrator's explicit disable therefore outranks everything, dormancy
// outranks a lock (a stale account is refused outright rather than told to wait
// out a lock), and a lock outranks the ordinary active state. The precedence is
// encoded once, in Evaluate.
//
// The same function is used by the HTTP handlers (to render the status column
// and to refuse requests), by the authentication middleware (to reject sessions
// and API tokens belonging to disabled or dormant accounts) and by the SSH
// gateway (to refuse certificate issuance and shell establishment), so all
// three paths agree by construction.
//
// The package is pure: no database, no clock, no logging, no mutable global
// state. Callers supply now, and pass UTC times because the hub stores UTC.
// Persistence lives in internal/store and enforcement in internal/server.
package account

import (
	"time"

	"github.com/wyiu/veyport/hub/internal/lockout"
	"github.com/wyiu/veyport/hub/internal/model"
)

// Status is an account's derived lifecycle status. It is computed from stored
// columns rather than persisted, so it can never drift from the underlying data.
type Status string

// The four possible statuses, in ascending order of severity.
const (
	// StatusActive means the account may sign in and use the hub normally.
	StatusActive Status = "active"
	// StatusLocked means consecutive failed sign-ins have locked the account
	// until its lock expiry passes or an administrator unlocks it. A lock is
	// enforced at the sign-in stages only.
	StatusLocked Status = "locked"
	// StatusDisabled means an administrator has disabled the account. It is
	// refused at every access path until an administrator enables it.
	StatusDisabled Status = "disabled"
	// StatusDormant means the account has been inactive for longer than the
	// dormancy policy allows. It is refused at every access path until an
	// administrator reactivates it.
	StatusDormant Status = "dormant"
)

// Canonical refusal messages. They name the account state and nothing else: in
// particular they never reveal whether the supplied credentials were correct.
const (
	// MsgDisabled is returned to a caller whose account has been disabled.
	MsgDisabled = "account disabled — contact an administrator"
	// MsgDormant is returned to a caller whose account has gone dormant.
	MsgDormant = "account dormant — contact an administrator"
)

// Input is the subset of a user row that determines the derived status.
//
// The three activity timestamps are pointers because each may be absent: an
// account that has never been used has no LastActivityAt, one that has never
// been disabled has no ReactivatedAt. CreatedAt is always present and acts as
// the floor of the activity clock.
type Input struct {
	// DisabledAt is when an administrator disabled the account; nil if enabled.
	DisabledAt *time.Time
	// LockedUntil is when the current lock expires; nil if never locked. A
	// non-nil value in the past is a spent lock, not an active one.
	LockedUntil *time.Time
	// LastActivityAt is the most recent interactive sign-in or API-token use;
	// nil if the account has never been used.
	LastActivityAt *time.Time
	// ReactivatedAt is when an administrator last enabled or unlocked the
	// account; nil if that has never happened.
	ReactivatedAt *time.Time
	// CreatedAt is when the account was created; it starts the activity clock
	// for an account that has never signed in.
	CreatedAt time.Time
	// DormancyExempt marks an account that must never be treated as dormant,
	// so a hub always retains an administrative recovery path. It affects
	// dormancy only: an exempt account can still be locked or disabled.
	DormancyExempt bool
}

// LatestActivity returns the most recent point on the account's activity clock:
// the latest of LastActivityAt, ReactivatedAt and CreatedAt, ignoring the nil
// pointers. Because CreatedAt is always present, the result is never zero for a
// real user row.
func LatestActivity(in Input) time.Time {
	latest := in.CreatedAt
	if in.LastActivityAt != nil && in.LastActivityAt.After(latest) {
		latest = *in.LastActivityAt
	}
	if in.ReactivatedAt != nil && in.ReactivatedAt.After(latest) {
		latest = *in.ReactivatedAt
	}
	return latest
}

// IsDormant reports whether the account has been inactive for longer than
// dormantDays at now.
//
// It is false whenever dormancy cannot apply: the account is exempt, or
// dormantDays is zero or negative (dormancy disabled). Otherwise the account is
// dormant once the gap between LatestActivity and now strictly exceeds
// dormantDays whole days, so an account sitting exactly on the boundary is
// still considered active and only becomes dormant an instant later.
func IsDormant(in Input, now time.Time, dormantDays int) bool {
	if in.DormancyExempt || dormantDays <= 0 {
		return false
	}
	return now.Sub(LatestActivity(in)) > time.Duration(dormantDays)*24*time.Hour
}

// Evaluate returns the account's status at now under policy p, applying the
// precedence disabled > dormant > locked > active. Only the policy's
// DormantDays is consulted; the lock decision reads the account's own expiry
// through lockout.IsLocked, so a policy change never rewrites an existing lock.
func Evaluate(in Input, now time.Time, p lockout.Policy) Status {
	switch {
	case in.DisabledAt != nil:
		return StatusDisabled
	case IsDormant(in, now, p.DormantDays):
		return StatusDormant
	case lockout.IsLocked(in.LockedUntil, now):
		return StatusLocked
	default:
		return StatusActive
	}
}

// Refusal maps a status to the message shown when access is refused on that
// account's behalf, and reports whether the status refuses access at all.
//
// Only disabled and dormant refuse here, because they are refused at every
// access path. A lock is enforced at the sign-in stages alone, so StatusLocked
// returns refuse=false and its callers supply their own message; any unknown
// status is treated as non-refusing.
func Refusal(s Status) (msg string, refuse bool) {
	switch s {
	case StatusDisabled:
		return MsgDisabled, true
	case StatusDormant:
		return MsgDormant, true
	default:
		return "", false
	}
}

// InputFromUser projects a user row onto the fields Evaluate needs. The
// pointers are copied as they are, so an absent timestamp stays absent.
func InputFromUser(u *model.User) Input {
	return Input{
		DisabledAt:     u.DisabledAt,
		LockedUntil:    u.LockedUntil,
		LastActivityAt: u.LastActivityAt,
		ReactivatedAt:  u.ReactivatedAt,
		CreatedAt:      u.CreatedAt,
		DormancyExempt: u.DormancyExempt,
	}
}
