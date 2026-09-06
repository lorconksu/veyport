package lockout_test

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/lockout"
)

// base is the reference "now" used across the table tests. All lockout times are
// UTC by contract (callers pass UTC), so the fixture is UTC too.
var base = time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)

func tp(t time.Time) *time.Time { return &t }

// mapGetter builds a lockout.Load getter backed by a map. A missing key returns
// an error, mirroring store.GetConfig for an unset key.
func mapGetter(m map[string]string) func(string) (string, error) {
	return func(key string) (string, error) {
		v, ok := m[key]
		if !ok {
			return "", fmt.Errorf("config key %q not found", key)
		}
		return v, nil
	}
}

func TestDefaults(t *testing.T) {
	got := lockout.Defaults()
	want := lockout.Policy{
		Threshold:   5,
		Window:      15 * time.Minute,
		Duration:    15 * time.Minute,
		DormantDays: 35,
	}
	if got != want {
		t.Fatalf("Defaults() = %+v, want %+v", got, want)
	}
	if lockout.DefaultThreshold != 5 {
		t.Errorf("DefaultThreshold = %d, want 5", lockout.DefaultThreshold)
	}
	if lockout.DefaultWindow != 15*time.Minute {
		t.Errorf("DefaultWindow = %v, want 15m", lockout.DefaultWindow)
	}
	if lockout.DefaultDuration != 15*time.Minute {
		t.Errorf("DefaultDuration = %v, want 15m", lockout.DefaultDuration)
	}
	if lockout.DefaultDormantDays != 35 {
		t.Errorf("DefaultDormantDays = %d, want 35", lockout.DefaultDormantDays)
	}
	if got.DormantDays != 35 {
		t.Errorf("Defaults().DormantDays = %d, want 35", got.DormantDays)
	}
	if err := got.Validate(); err != nil {
		t.Errorf("Defaults().Validate() = %v, want nil", err)
	}
}

func TestNoAutoUnlockSentinel(t *testing.T) {
	want := time.Date(9999, 12, 31, 0, 0, 0, 0, time.UTC)
	if !lockout.NoAutoUnlock.Equal(want) {
		t.Fatalf("NoAutoUnlock = %v, want %v", lockout.NoAutoUnlock, want)
	}
	if !lockout.IsLocked(&lockout.NoAutoUnlock, base) {
		t.Error("IsLocked(NoAutoUnlock, base) = false, want true")
	}
}

func TestConfigKeys(t *testing.T) {
	if lockout.KeyThreshold != "account.lockout_threshold" {
		t.Errorf("KeyThreshold = %q", lockout.KeyThreshold)
	}
	if lockout.KeyWindowMinutes != "account.lockout_window_minutes" {
		t.Errorf("KeyWindowMinutes = %q", lockout.KeyWindowMinutes)
	}
	if lockout.KeyDurationMinutes != "account.lockout_duration_minutes" {
		t.Errorf("KeyDurationMinutes = %q", lockout.KeyDurationMinutes)
	}
	if lockout.KeyDormantDays != "account.dormant_days" {
		t.Errorf("KeyDormantDays = %q", lockout.KeyDormantDays)
	}
}

func TestIsLocked(t *testing.T) {
	past := base.Add(-time.Minute)
	future := base.Add(time.Minute)

	tests := []struct {
		name        string
		lockedUntil *time.Time
		now         time.Time
		want        bool
	}{
		{name: "nil is never locked", lockedUntil: nil, now: base, want: false},
		{name: "expiry in the past is not locked", lockedUntil: &past, now: base, want: false},
		{name: "expiry exactly now is not locked", lockedUntil: &base, now: base, want: false},
		{name: "expiry in the future is locked", lockedUntil: &future, now: base, want: true},
		{name: "far-future sentinel is locked", lockedUntil: &lockout.NoAutoUnlock, now: base, want: true},
		{name: "sentinel is still locked far in the future", lockedUntil: &lockout.NoAutoUnlock, now: base.AddDate(1000, 0, 0), want: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := lockout.IsLocked(tc.lockedUntil, tc.now); got != tc.want {
				t.Fatalf("IsLocked() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestNextState(t *testing.T) {
	defaults := lockout.Defaults()

	tests := []struct {
		name            string
		prev            lockout.State
		policy          lockout.Policy
		now             time.Time
		wantCount       int
		wantLockedUntil *time.Time
		wantNewlyLocked bool
	}{
		{
			name:      "fresh failure with no history starts at one",
			prev:      lockout.State{},
			policy:    defaults,
			now:       base,
			wantCount: 1,
		},
		{
			name:      "failure inside the window increments",
			prev:      lockout.State{Count: 2, LastFailedAt: tp(base.Add(-5 * time.Minute))},
			policy:    defaults,
			now:       base,
			wantCount: 3,
		},
		{
			name:      "failure exactly at the window boundary still increments",
			prev:      lockout.State{Count: 1, LastFailedAt: tp(base.Add(-15 * time.Minute))},
			policy:    defaults,
			now:       base,
			wantCount: 2,
		},
		{
			name:      "failure after the window elapsed resets to one",
			prev:      lockout.State{Count: 4, LastFailedAt: tp(base.Add(-16 * time.Minute))},
			policy:    defaults,
			now:       base,
			wantCount: 1,
		},
		{
			name:            "reaching the threshold locks",
			prev:            lockout.State{Count: 4, LastFailedAt: tp(base.Add(-time.Minute))},
			policy:          defaults,
			now:             base,
			wantCount:       5,
			wantLockedUntil: tp(base.Add(15 * time.Minute)),
			wantNewlyLocked: true,
		},
		{
			name:            "threshold of one locks on the very first failure",
			prev:            lockout.State{},
			policy:          lockout.Policy{Threshold: 1, Window: 15 * time.Minute, Duration: 15 * time.Minute},
			now:             base,
			wantCount:       1,
			wantLockedUntil: tp(base.Add(15 * time.Minute)),
			wantNewlyLocked: true,
		},
		{
			name: "already locked does not re-lock and keeps the original expiry",
			prev: lockout.State{
				Count:        5,
				LastFailedAt: tp(base.Add(-time.Minute)),
				LockedUntil:  tp(base.Add(5 * time.Minute)),
			},
			policy:          defaults,
			now:             base,
			wantCount:       6,
			wantLockedUntil: tp(base.Add(5 * time.Minute)),
			wantNewlyLocked: false,
		},
		{
			name: "an expired lock re-locks once the threshold is reached again",
			prev: lockout.State{
				Count:        4,
				LastFailedAt: tp(base.Add(-time.Minute)),
				LockedUntil:  tp(base.Add(-time.Second)),
			},
			policy:          defaults,
			now:             base,
			wantCount:       5,
			wantLockedUntil: tp(base.Add(15 * time.Minute)),
			wantNewlyLocked: true,
		},
		{
			name: "a stale past expiry is carried through below the threshold",
			prev: lockout.State{
				Count:        1,
				LastFailedAt: tp(base.Add(-time.Minute)),
				LockedUntil:  tp(base.Add(-time.Hour)),
			},
			policy:          defaults,
			now:             base,
			wantCount:       2,
			wantLockedUntil: tp(base.Add(-time.Hour)),
			wantNewlyLocked: false,
		},
		{
			name:      "threshold zero counts but never locks",
			prev:      lockout.State{Count: 99, LastFailedAt: tp(base.Add(-time.Minute))},
			policy:    lockout.Policy{Threshold: 0, Window: 15 * time.Minute, Duration: 15 * time.Minute},
			now:       base,
			wantCount: 100,
		},
		{
			name:            "duration zero locks with the far-future sentinel",
			prev:            lockout.State{Count: 1, LastFailedAt: tp(base.Add(-time.Minute))},
			policy:          lockout.Policy{Threshold: 2, Window: 15 * time.Minute, Duration: 0},
			now:             base,
			wantCount:       2,
			wantLockedUntil: &lockout.NoAutoUnlock,
			wantNewlyLocked: true,
		},
		{
			name:      "window zero restarts the count for any earlier failure",
			prev:      lockout.State{Count: 1, LastFailedAt: tp(base.Add(-time.Second))},
			policy:    lockout.Policy{Threshold: 2, Window: 0, Duration: 15 * time.Minute},
			now:       base,
			wantCount: 1,
		},
		{
			name:            "window zero still increments for a failure at the same instant",
			prev:            lockout.State{Count: 1, LastFailedAt: tp(base)},
			policy:          lockout.Policy{Threshold: 2, Window: 0, Duration: 15 * time.Minute},
			now:             base,
			wantCount:       2,
			wantLockedUntil: tp(base.Add(15 * time.Minute)),
			wantNewlyLocked: true,
		},
		{
			name:            "count already above the threshold with no active lock locks again",
			prev:            lockout.State{Count: 9, LastFailedAt: tp(base.Add(-time.Minute))},
			policy:          lockout.Policy{Threshold: 3, Window: 15 * time.Minute, Duration: time.Minute},
			now:             base,
			wantCount:       10,
			wantLockedUntil: tp(base.Add(time.Minute)),
			wantNewlyLocked: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, newlyLocked := lockout.NextState(tc.prev, tc.now, tc.policy)

			if got.Count != tc.wantCount {
				t.Errorf("Count = %d, want %d", got.Count, tc.wantCount)
			}
			if got.LastFailedAt == nil {
				t.Fatal("LastFailedAt = nil, want the supplied now")
			}
			if !got.LastFailedAt.Equal(tc.now) {
				t.Errorf("LastFailedAt = %v, want %v", *got.LastFailedAt, tc.now)
			}
			switch {
			case tc.wantLockedUntil == nil && got.LockedUntil != nil:
				t.Errorf("LockedUntil = %v, want nil", *got.LockedUntil)
			case tc.wantLockedUntil != nil && got.LockedUntil == nil:
				t.Errorf("LockedUntil = nil, want %v", *tc.wantLockedUntil)
			case tc.wantLockedUntil != nil && !got.LockedUntil.Equal(*tc.wantLockedUntil):
				t.Errorf("LockedUntil = %v, want %v", *got.LockedUntil, *tc.wantLockedUntil)
			}
			if newlyLocked != tc.wantNewlyLocked {
				t.Errorf("newlyLocked = %v, want %v", newlyLocked, tc.wantNewlyLocked)
			}
		})
	}
}

// TestNextStateDoesNotMutatePrev guards the purity contract: the caller's state
// (including the values behind its pointers) is untouched.
func TestNextStateDoesNotMutatePrev(t *testing.T) {
	lastFailed := base.Add(-time.Minute)
	lockedUntil := base.Add(5 * time.Minute)
	prev := lockout.State{Count: 2, LastFailedAt: &lastFailed, LockedUntil: &lockedUntil}

	next, _ := lockout.NextState(prev, base, lockout.Defaults())

	if prev.Count != 2 {
		t.Errorf("prev.Count mutated to %d", prev.Count)
	}
	if !lastFailed.Equal(base.Add(-time.Minute)) {
		t.Errorf("prev.LastFailedAt target mutated to %v", lastFailed)
	}
	if !lockedUntil.Equal(base.Add(5 * time.Minute)) {
		t.Errorf("prev.LockedUntil target mutated to %v", lockedUntil)
	}
	if next.LastFailedAt == prev.LastFailedAt {
		t.Error("next.LastFailedAt aliases prev.LastFailedAt")
	}
}

// TestNextStateSequence walks a realistic attack: four failures inside the
// window, the fifth locks, further failures do not re-lock, and after expiry a
// fresh failure both resets the count (window elapsed) and locks nothing.
func TestNextStateSequence(t *testing.T) {
	p := lockout.Defaults()
	state := lockout.State{}
	now := base

	for i := 1; i <= 4; i++ {
		var locked bool
		state, locked = lockout.NextState(state, now, p)
		if locked {
			t.Fatalf("failure %d locked early", i)
		}
		if state.Count != i {
			t.Fatalf("failure %d: Count = %d, want %d", i, state.Count, i)
		}
		now = now.Add(time.Minute)
	}

	state, locked := lockout.NextState(state, now, p)
	if !locked {
		t.Fatal("fifth failure did not lock")
	}
	if !state.LockedUntil.Equal(now.Add(15 * time.Minute)) {
		t.Fatalf("LockedUntil = %v, want %v", *state.LockedUntil, now.Add(15*time.Minute))
	}
	lockExpiry := *state.LockedUntil

	now = now.Add(time.Minute)
	state, locked = lockout.NextState(state, now, p)
	if locked {
		t.Error("a failure during an active lock reported newlyLocked")
	}
	if !state.LockedUntil.Equal(lockExpiry) {
		t.Errorf("an active lock was extended to %v, want %v", *state.LockedUntil, lockExpiry)
	}

	// Well past both the lock expiry and the counting window.
	now = lockExpiry.Add(time.Hour)
	state, locked = lockout.NextState(state, now, p)
	if locked {
		t.Error("the first failure after expiry locked immediately")
	}
	if state.Count != 1 {
		t.Errorf("Count after the window elapsed = %d, want 1", state.Count)
	}
	if !lockout.IsLocked(state.LockedUntil, now) {
		return
	}
	t.Errorf("IsLocked() = true after expiry (LockedUntil = %v, now = %v)", *state.LockedUntil, now)
}

func TestLoad(t *testing.T) {
	defaults := lockout.Defaults()

	tests := []struct {
		name   string
		config map[string]string
		want   lockout.Policy
	}{
		{
			name:   "all keys missing falls back to defaults",
			config: map[string]string{},
			want:   defaults,
		},
		{
			name: "valid overrides are applied",
			config: map[string]string{
				lockout.KeyThreshold:       "3",
				lockout.KeyWindowMinutes:   "30",
				lockout.KeyDurationMinutes: "1",
			},
			want: lockout.Policy{Threshold: 3, Window: 30 * time.Minute, Duration: time.Minute, DormantDays: defaults.DormantDays},
		},
		{
			name: "zeros are honoured, not treated as unset",
			config: map[string]string{
				lockout.KeyThreshold:       "0",
				lockout.KeyWindowMinutes:   "0",
				lockout.KeyDurationMinutes: "0",
				lockout.KeyDormantDays:     "0",
			},
			want: lockout.Policy{Threshold: 0, Window: 0, Duration: 0, DormantDays: 0},
		},
		{
			name: "unparsable values fall back per key",
			config: map[string]string{
				lockout.KeyThreshold:       "abc",
				lockout.KeyWindowMinutes:   "",
				lockout.KeyDurationMinutes: "12.5",
				lockout.KeyDormantDays:     "abc",
			},
			want: defaults,
		},
		{
			name: "negative values fall back per key",
			config: map[string]string{
				lockout.KeyThreshold:       "-1",
				lockout.KeyWindowMinutes:   "-3",
				lockout.KeyDurationMinutes: "-100",
				lockout.KeyDormantDays:     "-1",
			},
			want: defaults,
		},
		{
			name: "one bad key does not disturb the valid ones",
			config: map[string]string{
				lockout.KeyThreshold:     "7",
				lockout.KeyWindowMinutes: "abc",
				// duration and dormant_days missing entirely
			},
			want: lockout.Policy{Threshold: 7, Window: defaults.Window, Duration: defaults.Duration, DormantDays: defaults.DormantDays},
		},
		{
			name: "surrounding whitespace is tolerated",
			config: map[string]string{
				lockout.KeyThreshold:       " 4 ",
				lockout.KeyWindowMinutes:   "\t20\n",
				lockout.KeyDurationMinutes: "2",
				lockout.KeyDormantDays:     " 7 ",
			},
			want: lockout.Policy{Threshold: 4, Window: 20 * time.Minute, Duration: 2 * time.Minute, DormantDays: 7},
		},
		{
			name: "dormant_days valid override is applied and other keys still honoured",
			config: map[string]string{
				lockout.KeyThreshold:   "3",
				lockout.KeyDormantDays: "7",
			},
			want: lockout.Policy{Threshold: 3, Window: defaults.Window, Duration: defaults.Duration, DormantDays: 7},
		},
		{
			name:   "dormant_days zero disables dormancy, not treated as unset",
			config: map[string]string{lockout.KeyDormantDays: "0"},
			want:   lockout.Policy{Threshold: defaults.Threshold, Window: defaults.Window, Duration: defaults.Duration, DormantDays: 0},
		},
		{
			name:   "dormant_days unparsable falls back to default",
			config: map[string]string{lockout.KeyDormantDays: "abc"},
			want:   defaults,
		},
		{
			name:   "dormant_days negative falls back to default",
			config: map[string]string{lockout.KeyDormantDays: "-1"},
			want:   defaults,
		},
		{
			name:   "dormant_days missing (getter error) falls back to default",
			config: map[string]string{},
			want:   defaults,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := lockout.Load(mapGetter(tc.config)); got != tc.want {
				t.Fatalf("Load() = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestLoadGetterErrorsEverywhere(t *testing.T) {
	failing := func(string) (string, error) { return "", errors.New("store unavailable") }
	if got := lockout.Load(failing); got != lockout.Defaults() {
		t.Fatalf("Load() = %+v, want %+v", got, lockout.Defaults())
	}
}

func TestLoadReadsExactlyTheFourKeys(t *testing.T) {
	var seen []string
	get := func(key string) (string, error) {
		seen = append(seen, key)
		return "", errors.New("unset")
	}
	lockout.Load(get)

	sort.Strings(seen)
	want := []string{lockout.KeyDurationMinutes, lockout.KeyThreshold, lockout.KeyWindowMinutes, lockout.KeyDormantDays}
	sort.Strings(want)
	if len(seen) != len(want) {
		t.Fatalf("Load() read %v, want exactly %v", seen, want)
	}
	for i := range want {
		if seen[i] != want[i] {
			t.Fatalf("Load() read %v, want exactly %v", seen, want)
		}
	}
}

func TestLoadResultIsAlwaysValid(t *testing.T) {
	configs := []map[string]string{
		{},
		{lockout.KeyThreshold: "-5", lockout.KeyWindowMinutes: "-5", lockout.KeyDurationMinutes: "-5", lockout.KeyDormantDays: "-5"},
		{lockout.KeyThreshold: "nope"},
		{lockout.KeyThreshold: "0", lockout.KeyWindowMinutes: "0", lockout.KeyDurationMinutes: "0", lockout.KeyDormantDays: "0"},
	}
	for i, config := range configs {
		if err := lockout.Load(mapGetter(config)).Validate(); err != nil {
			t.Errorf("config %d: Load(...).Validate() = %v, want nil", i, err)
		}
	}
}

func TestPolicyValidate(t *testing.T) {
	tests := []struct {
		name      string
		policy    lockout.Policy
		wantErr   bool
		wantField string
	}{
		{name: "defaults are valid", policy: lockout.Defaults()},
		{name: "all zeros are valid", policy: lockout.Policy{}},
		{
			name:   "large values are valid",
			policy: lockout.Policy{Threshold: 1000, Window: 24 * time.Hour, Duration: 24 * time.Hour},
		},
		{
			name:      "negative threshold is rejected",
			policy:    lockout.Policy{Threshold: -1, Window: time.Minute, Duration: time.Minute},
			wantErr:   true,
			wantField: "threshold",
		},
		{
			name:      "negative window is rejected",
			policy:    lockout.Policy{Threshold: 5, Window: -time.Minute, Duration: time.Minute},
			wantErr:   true,
			wantField: "window",
		},
		{
			name:      "negative duration is rejected",
			policy:    lockout.Policy{Threshold: 5, Window: time.Minute, Duration: -time.Minute},
			wantErr:   true,
			wantField: "duration",
		},
		{
			name:      "negative dormant days is rejected",
			policy:    lockout.Policy{Threshold: 5, Window: time.Minute, Duration: time.Minute, DormantDays: -1},
			wantErr:   true,
			wantField: "dormant_days",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.policy.Validate()
			if !tc.wantErr {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatal("Validate() = nil, want an error")
			}
			if !errors.Is(err, lockout.ErrInvalidPolicy) {
				t.Errorf("Validate() error does not wrap ErrInvalidPolicy: %v", err)
			}
			if !strings.Contains(err.Error(), tc.wantField) {
				t.Errorf("Validate() = %q, want it to name the %q field", err, tc.wantField)
			}
		})
	}
}
