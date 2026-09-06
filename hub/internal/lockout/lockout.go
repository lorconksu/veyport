// Package lockout holds the pure decision logic for per-account login lockout.
//
// It is deliberately free of I/O, logging and mutable global state: the whole
// security property ("N consecutive failures inside a window lock the account
// for D minutes") lives in NextState, so it can be reasoned about and tested in
// isolation. Persistence and enforcement live in internal/store and
// internal/server respectively; this package never touches a database, a clock
// or a request.
//
// All times are compared exactly as the caller supplies them. Callers pass UTC
// (the hub stores UTC in the store's second-precision format), so the package
// never converts locations on the caller's behalf.
package lockout

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Configuration keys backing the policy in the hub's config store.
const (
	// KeyThreshold is the number of consecutive failures that trigger a lock.
	KeyThreshold = "account.lockout_threshold"
	// KeyWindowMinutes is the counting window, in whole minutes.
	KeyWindowMinutes = "account.lockout_window_minutes"
	// KeyDurationMinutes is the lock duration, in whole minutes.
	KeyDurationMinutes = "account.lockout_duration_minutes"
	// KeyDormantDays is the number of days of inactivity after which an
	// account is considered dormant.
	KeyDormantDays = "account.dormant_days"
)

// Built-in policy values used whenever a key is unset or unusable.
const (
	// DefaultThreshold is the built-in failure threshold.
	DefaultThreshold = 5
	// DefaultWindow is the built-in counting window.
	DefaultWindow = 15 * time.Minute
	// DefaultDuration is the built-in lock duration.
	DefaultDuration = 15 * time.Minute
	// DefaultDormantDays is the built-in dormancy threshold, in days.
	DefaultDormantDays = 35
)

// NoAutoUnlock is the far-future expiry stamped on an account when the policy
// duration is zero, meaning "no automatic unlock". Using a sentinel instead of
// a NULL-with-a-flag keeps every lock check a single time comparison, and lets
// the admin UI recognise the value and render "no auto-unlock". Until an
// administrator unlock ships, a lock carrying this expiry is effectively
// permanent, which is why a zero duration is accepted but not recommended.
var NoAutoUnlock = time.Date(9999, 12, 31, 0, 0, 0, 0, time.UTC)

// ErrInvalidPolicy is the sentinel wrapped by every error Validate returns.
var ErrInvalidPolicy = errors.New("invalid lockout policy")

// Policy is the administrator-configurable lockout policy.
//
// A Threshold of 0 disables locking entirely: failures are still counted and
// timestamped for visibility, but no account ever locks. A Duration of 0 means
// a lock has no automatic expiry (see NoAutoUnlock). A Window of 0 means no two
// distinct failures ever accumulate: any failure strictly later than the
// previous one restarts the count at 1.
type Policy struct {
	// Threshold is the consecutive-failure count that triggers a lock; 0 disables locking.
	Threshold int
	// Window is how long a failure keeps counting toward the threshold.
	Window time.Duration
	// Duration is how long a lock lasts; 0 means no automatic unlock.
	Duration time.Duration
	// DormantDays is how many days of inactivity mark an account dormant;
	// 0 disables dormancy enforcement entirely.
	DormantDays int
}

// Defaults returns the built-in policy used when nothing is configured.
func Defaults() Policy {
	return Policy{
		Threshold:   DefaultThreshold,
		Window:      DefaultWindow,
		Duration:    DefaultDuration,
		DormantDays: DefaultDormantDays,
	}
}

// Load reads the four policy keys through get and returns the effective
// policy. It is total: it never panics and never returns an error. Each key is
// resolved independently, so one unusable value cannot discard the others.
//
// A key falls back to its default when get reports an error (typically an unset
// key), when the value does not parse as an integer, or when it parses to a
// negative number. This mirrors the tolerance of the store's
// getConfigIntDefault helper, with surrounding whitespace additionally trimmed.
// Window and Duration are stored as whole minutes and converted here.
// DormantDays is stored and read as a whole number of days; 0 is honoured
// (dormancy disabled), not treated as unset.
//
// The returned Policy always satisfies Validate.
func Load(get func(key string) (string, error)) Policy {
	p := Defaults()
	p.Threshold = loadInt(get, KeyThreshold, DefaultThreshold)
	p.Window = time.Duration(loadInt(get, KeyWindowMinutes, int(DefaultWindow/time.Minute))) * time.Minute
	p.Duration = time.Duration(loadInt(get, KeyDurationMinutes, int(DefaultDuration/time.Minute))) * time.Minute
	p.DormantDays = loadInt(get, KeyDormantDays, DefaultDormantDays)
	return p
}

// loadInt reads one key and returns a non-negative integer, falling back to
// def on a read error, an unparsable value, or a negative value.
func loadInt(get func(key string) (string, error), key string, def int) int {
	raw, err := get(key)
	if err != nil {
		return def
	}
	parsed, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || parsed < 0 {
		return def
	}
	return parsed
}

// Validate reports whether the policy is usable. Every field must be
// non-negative; zeros are legal and carry the meanings documented on Policy.
// Errors wrap ErrInvalidPolicy and name the offending field.
func (p Policy) Validate() error {
	if p.Threshold < 0 {
		return fmt.Errorf("%w: threshold must be >= 0, got %d", ErrInvalidPolicy, p.Threshold)
	}
	if p.Window < 0 {
		return fmt.Errorf("%w: window must be >= 0, got %s", ErrInvalidPolicy, p.Window)
	}
	if p.Duration < 0 {
		return fmt.Errorf("%w: duration must be >= 0, got %s", ErrInvalidPolicy, p.Duration)
	}
	if p.DormantDays < 0 {
		return fmt.Errorf("%w: dormant_days must be >= 0, got %d", ErrInvalidPolicy, p.DormantDays)
	}
	return nil
}

// State is the per-account lockout state, mirroring the users-table columns
// failed_login_count, last_failed_login_at and locked_until.
type State struct {
	// Count is the number of consecutive failures inside the current window.
	Count int
	// LastFailedAt is when the most recent failure was recorded; nil if never.
	LastFailedAt *time.Time
	// LockedUntil is when the current lock expires; nil if the account has
	// never been locked. A non-nil value in the past is a spent lock, not an
	// active one: always judge it with IsLocked.
	LockedUntil *time.Time
}

// IsLocked reports whether an account with the given lock expiry is locked at
// now. A nil expiry is never locked, and an expiry exactly equal to now has
// already elapsed, so a lock ends the instant its expiry is reached.
func IsLocked(lockedUntil *time.Time, now time.Time) bool {
	return lockedUntil != nil && now.Before(*lockedUntil)
}

// NextState computes the account state after one failed credential check, and
// reports whether this failure is the one that locked the account.
//
// The transition, in order:
//
//   - Count restarts at 1 when there is no previous failure or the previous
//     failure is strictly older than the policy window; otherwise it is
//     prev.Count + 1. A failure exactly at the window boundary still counts.
//   - LastFailedAt becomes now.
//   - The account locks when the policy has a non-zero threshold, the new count
//     has reached it, and the account is not already locked at now. LockedUntil
//     then becomes now plus the policy duration, or NoAutoUnlock when the
//     duration is zero, and newlyLocked is true.
//   - Otherwise LockedUntil is carried through from prev unchanged, which may
//     be an active lock (an attempt during a lock never extends it) or a spent
//     one from an earlier lockout. newlyLocked is false.
//
// prev is not modified, and neither is the value behind any of its pointers.
// A policy change never rewrites an existing lock: only decisions taken from
// the next failure onward use the new values.
func NextState(prev State, now time.Time, p Policy) (next State, newlyLocked bool) {
	next.Count = 1
	if prev.LastFailedAt != nil && now.Sub(*prev.LastFailedAt) <= p.Window {
		next.Count = prev.Count + 1
	}

	failedAt := now
	next.LastFailedAt = &failedAt

	if p.Threshold > 0 && next.Count >= p.Threshold && !IsLocked(prev.LockedUntil, now) {
		until := now.Add(p.Duration)
		if p.Duration == 0 {
			until = NoAutoUnlock
		}
		next.LockedUntil = &until
		return next, true
	}

	next.LockedUntil = prev.LockedUntil
	return next, false
}
