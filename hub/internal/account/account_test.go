package account

import (
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/lockout"
	"github.com/wyiu/veyport/hub/internal/model"
)

// now is the fixed evaluation instant every table below is written against.
var now = time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)

// at returns a pointer to now offset by d, for building Input pointer fields.
func at(d time.Duration) *time.Time {
	t := now.Add(d)
	return &t
}

const day = 24 * time.Hour

func TestStatusValues(t *testing.T) {
	cases := []struct {
		status Status
		want   string
	}{
		{StatusActive, "active"},
		{StatusLocked, "locked"},
		{StatusDisabled, "disabled"},
		{StatusDormant, "dormant"},
	}
	for _, tc := range cases {
		if string(tc.status) != tc.want {
			t.Errorf("status %q = %q, want %q", tc.want, string(tc.status), tc.want)
		}
	}
}

func TestRefusalMessages(t *testing.T) {
	if MsgDisabled != "account disabled — contact an administrator" {
		t.Errorf("MsgDisabled = %q", MsgDisabled)
	}
	if MsgDormant != "account dormant — contact an administrator" {
		t.Errorf("MsgDormant = %q", MsgDormant)
	}
}

func TestRefusal(t *testing.T) {
	cases := []struct {
		name       string
		status     Status
		wantMsg    string
		wantRefuse bool
	}{
		{"disabled refuses with its message", StatusDisabled, "account disabled — contact an administrator", true},
		{"dormant refuses with its message", StatusDormant, "account dormant — contact an administrator", true},
		{"locked does not refuse here", StatusLocked, "", false},
		{"active does not refuse", StatusActive, "", false},
		{"unknown status does not refuse", Status("nonsense"), "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg, refuse := Refusal(tc.status)
			if msg != tc.wantMsg || refuse != tc.wantRefuse {
				t.Errorf("Refusal(%q) = (%q, %v), want (%q, %v)", tc.status, msg, refuse, tc.wantMsg, tc.wantRefuse)
			}
		})
	}
}

func TestLatestActivity(t *testing.T) {
	created := now.Add(-100 * day)
	cases := []struct {
		name string
		in   Input
		want time.Time
	}{
		{
			name: "all pointers nil falls back to CreatedAt",
			in:   Input{CreatedAt: created},
			want: created,
		},
		{
			name: "LastActivityAt is the latest",
			in:   Input{CreatedAt: created, LastActivityAt: at(-1 * day), ReactivatedAt: at(-10 * day)},
			want: now.Add(-1 * day),
		},
		{
			name: "ReactivatedAt is the latest",
			in:   Input{CreatedAt: created, LastActivityAt: at(-10 * day), ReactivatedAt: at(-2 * day)},
			want: now.Add(-2 * day),
		},
		{
			name: "CreatedAt is the latest",
			in:   Input{CreatedAt: now.Add(-1 * time.Hour), LastActivityAt: at(-10 * day), ReactivatedAt: at(-20 * day)},
			want: now.Add(-1 * time.Hour),
		},
		{
			name: "only LastActivityAt set",
			in:   Input{CreatedAt: created, LastActivityAt: at(-3 * day)},
			want: now.Add(-3 * day),
		},
		{
			name: "only ReactivatedAt set",
			in:   Input{CreatedAt: created, ReactivatedAt: at(-4 * day)},
			want: now.Add(-4 * day),
		},
		{
			name: "equal timestamps resolve to that instant",
			in:   Input{CreatedAt: created, LastActivityAt: at(-5 * day), ReactivatedAt: at(-5 * day)},
			want: now.Add(-5 * day),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := LatestActivity(tc.in); !got.Equal(tc.want) {
				t.Errorf("LatestActivity() = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestIsDormant(t *testing.T) {
	cases := []struct {
		name        string
		in          Input
		dormantDays int
		want        bool
	}{
		{
			name:        "activity older than the threshold is dormant",
			in:          Input{CreatedAt: now.Add(-100 * day), LastActivityAt: at(-40 * day)},
			dormantDays: 35,
			want:        true,
		},
		{
			name:        "recent activity is not dormant",
			in:          Input{CreatedAt: now.Add(-100 * day), LastActivityAt: at(-1 * day)},
			dormantDays: 35,
			want:        false,
		},
		{
			name:        "exactly at the boundary is not dormant",
			in:          Input{CreatedAt: now.Add(-100 * day), LastActivityAt: at(-35 * day)},
			dormantDays: 35,
			want:        false,
		},
		{
			name:        "one second past the boundary is dormant",
			in:          Input{CreatedAt: now.Add(-100 * day), LastActivityAt: at(-35*day - time.Second)},
			dormantDays: 35,
			want:        true,
		},
		{
			name:        "dormantDays 0 disables dormancy",
			in:          Input{CreatedAt: now.Add(-4000 * day), LastActivityAt: at(-4000 * day)},
			dormantDays: 0,
			want:        false,
		},
		{
			name:        "negative dormantDays disables dormancy",
			in:          Input{CreatedAt: now.Add(-4000 * day)},
			dormantDays: -1,
			want:        false,
		},
		{
			name:        "exempt accounts are never dormant",
			in:          Input{CreatedAt: now.Add(-4000 * day), DormancyExempt: true},
			dormantDays: 35,
			want:        false,
		},
		{
			name:        "reactivation restarts the clock",
			in:          Input{CreatedAt: now.Add(-4000 * day), LastActivityAt: at(-4000 * day), ReactivatedAt: at(-1 * day)},
			dormantDays: 35,
			want:        false,
		},
		{
			name:        "never signed in but freshly created is not dormant",
			in:          Input{CreatedAt: now.Add(-2 * day)},
			dormantDays: 35,
			want:        false,
		},
		{
			name:        "never signed in and created long ago is dormant",
			in:          Input{CreatedAt: now.Add(-90 * day)},
			dormantDays: 35,
			want:        true,
		},
		{
			name:        "activity in the future is not dormant",
			in:          Input{CreatedAt: now.Add(-90 * day), LastActivityAt: at(time.Hour)},
			dormantDays: 35,
			want:        false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsDormant(tc.in, now, tc.dormantDays); got != tc.want {
				t.Errorf("IsDormant() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestEvaluate(t *testing.T) {
	policy := func(dormantDays int) lockout.Policy {
		return lockout.Policy{
			Threshold:   lockout.DefaultThreshold,
			Window:      lockout.DefaultWindow,
			Duration:    lockout.DefaultDuration,
			DormantDays: dormantDays,
		}
	}

	cases := []struct {
		name        string
		in          Input
		dormantDays int
		want        Status
	}{
		{
			name:        "freshly created account is active",
			in:          Input{CreatedAt: now.Add(-time.Hour)},
			dormantDays: 35,
			want:        StatusActive,
		},
		{
			name:        "active lock alone is locked",
			in:          Input{CreatedAt: now.Add(-time.Hour), LockedUntil: at(10 * time.Minute)},
			dormantDays: 35,
			want:        StatusLocked,
		},
		{
			name:        "expired lock is active",
			in:          Input{CreatedAt: now.Add(-time.Hour), LockedUntil: at(-time.Minute)},
			dormantDays: 35,
			want:        StatusActive,
		},
		{
			name:        "lock expiring exactly now is active",
			in:          Input{CreatedAt: now.Add(-time.Hour), LockedUntil: at(0)},
			dormantDays: 35,
			want:        StatusActive,
		},
		{
			name:        "no-auto-unlock sentinel is locked",
			in:          Input{CreatedAt: now.Add(-time.Hour), LockedUntil: &lockout.NoAutoUnlock},
			dormantDays: 35,
			want:        StatusLocked,
		},
		{
			name:        "disabled beats locked",
			in:          Input{CreatedAt: now.Add(-time.Hour), DisabledAt: at(-time.Hour), LockedUntil: at(10 * time.Minute)},
			dormantDays: 35,
			want:        StatusDisabled,
		},
		{
			name:        "disabled beats dormant",
			in:          Input{CreatedAt: now.Add(-500 * day), DisabledAt: at(-time.Hour)},
			dormantDays: 35,
			want:        StatusDisabled,
		},
		{
			name:        "disabled beats dormant and locked together",
			in:          Input{CreatedAt: now.Add(-500 * day), DisabledAt: at(-time.Hour), LockedUntil: at(10 * time.Minute)},
			dormantDays: 35,
			want:        StatusDisabled,
		},
		{
			name:        "dormant beats locked",
			in:          Input{CreatedAt: now.Add(-500 * day), LockedUntil: at(10 * time.Minute)},
			dormantDays: 35,
			want:        StatusDormant,
		},
		{
			name:        "exempt with stale activity and an active lock is locked",
			in:          Input{CreatedAt: now.Add(-500 * day), DormancyExempt: true, LockedUntil: at(10 * time.Minute)},
			dormantDays: 35,
			want:        StatusLocked,
		},
		{
			name:        "exempt with stale activity and no lock is active",
			in:          Input{CreatedAt: now.Add(-500 * day), DormancyExempt: true},
			dormantDays: 35,
			want:        StatusActive,
		},
		{
			name:        "dormancy disabled keeps an ancient account active",
			in:          Input{CreatedAt: now.Add(-4000 * day), LastActivityAt: at(-4000 * day)},
			dormantDays: 0,
			want:        StatusActive,
		},
		{
			name:        "dormancy disabled still reports an active lock",
			in:          Input{CreatedAt: now.Add(-4000 * day), LockedUntil: at(time.Minute)},
			dormantDays: 0,
			want:        StatusLocked,
		},
		{
			name:        "LastActivityAt is the latest and keeps the account active",
			in:          Input{CreatedAt: now.Add(-500 * day), ReactivatedAt: at(-400 * day), LastActivityAt: at(-1 * day)},
			dormantDays: 35,
			want:        StatusActive,
		},
		{
			name:        "ReactivatedAt is the latest and keeps the account active",
			in:          Input{CreatedAt: now.Add(-500 * day), LastActivityAt: at(-400 * day), ReactivatedAt: at(-1 * day)},
			dormantDays: 35,
			want:        StatusActive,
		},
		{
			name:        "CreatedAt is the latest and keeps the account active",
			in:          Input{CreatedAt: now.Add(-1 * day), LastActivityAt: at(-400 * day), ReactivatedAt: at(-500 * day)},
			dormantDays: 35,
			want:        StatusActive,
		},
		{
			name:        "nil LastActivityAt with a recent CreatedAt is active",
			in:          Input{CreatedAt: now.Add(-2 * day)},
			dormantDays: 35,
			want:        StatusActive,
		},
		{
			name:        "exactly at the dormancy boundary is active",
			in:          Input{CreatedAt: now.Add(-500 * day), LastActivityAt: at(-35 * day)},
			dormantDays: 35,
			want:        StatusActive,
		},
		{
			name:        "one second past the dormancy boundary is dormant",
			in:          Input{CreatedAt: now.Add(-500 * day), LastActivityAt: at(-35*day - time.Second)},
			dormantDays: 35,
			want:        StatusDormant,
		},
		{
			name:        "stale activity with an expired lock is dormant",
			in:          Input{CreatedAt: now.Add(-500 * day), LockedUntil: at(-time.Hour)},
			dormantDays: 35,
			want:        StatusDormant,
		},
		{
			name:        "disabled with everything else clear is disabled",
			in:          Input{CreatedAt: now.Add(-time.Hour), DisabledAt: at(-time.Minute)},
			dormantDays: 35,
			want:        StatusDisabled,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Evaluate(tc.in, now, policy(tc.dormantDays)); got != tc.want {
				t.Errorf("Evaluate() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestEvaluateRefusalPairing(t *testing.T) {
	p := lockout.Defaults()
	disabled := Input{CreatedAt: now.Add(-time.Hour), DisabledAt: at(-time.Hour)}
	if msg, refuse := Refusal(Evaluate(disabled, now, p)); !refuse || msg != MsgDisabled {
		t.Errorf("disabled account: got (%q, %v)", msg, refuse)
	}
	dormant := Input{CreatedAt: now.Add(-500 * day)}
	if msg, refuse := Refusal(Evaluate(dormant, now, p)); !refuse || msg != MsgDormant {
		t.Errorf("dormant account: got (%q, %v)", msg, refuse)
	}
	locked := Input{CreatedAt: now.Add(-time.Hour), LockedUntil: at(time.Minute)}
	if msg, refuse := Refusal(Evaluate(locked, now, p)); refuse || msg != "" {
		t.Errorf("locked account: got (%q, %v)", msg, refuse)
	}
}

func TestInputFromUser(t *testing.T) {
	disabledAt := now.Add(-3 * time.Hour)
	lockedUntil := now.Add(5 * time.Minute)
	lastActivity := now.Add(-2 * day)
	reactivated := now.Add(-6 * day)
	created := now.Add(-90 * day)

	u := &model.User{
		ID:             "u-1",
		Username:       "alice",
		DisabledAt:     &disabledAt,
		LockedUntil:    &lockedUntil,
		LastActivityAt: &lastActivity,
		ReactivatedAt:  &reactivated,
		CreatedAt:      created,
		DormancyExempt: true,
	}

	in := InputFromUser(u)
	if in.DisabledAt == nil || !in.DisabledAt.Equal(disabledAt) {
		t.Errorf("DisabledAt = %v, want %s", in.DisabledAt, disabledAt)
	}
	if in.LockedUntil == nil || !in.LockedUntil.Equal(lockedUntil) {
		t.Errorf("LockedUntil = %v, want %s", in.LockedUntil, lockedUntil)
	}
	if in.LastActivityAt == nil || !in.LastActivityAt.Equal(lastActivity) {
		t.Errorf("LastActivityAt = %v, want %s", in.LastActivityAt, lastActivity)
	}
	if in.ReactivatedAt == nil || !in.ReactivatedAt.Equal(reactivated) {
		t.Errorf("ReactivatedAt = %v, want %s", in.ReactivatedAt, reactivated)
	}
	if !in.CreatedAt.Equal(created) {
		t.Errorf("CreatedAt = %s, want %s", in.CreatedAt, created)
	}
	if !in.DormancyExempt {
		t.Error("DormancyExempt = false, want true")
	}
}

func TestInputFromUserNilPointersStayNil(t *testing.T) {
	created := now.Add(-1 * day)
	in := InputFromUser(&model.User{ID: "u-2", CreatedAt: created})

	if in.DisabledAt != nil {
		t.Errorf("DisabledAt = %v, want nil", in.DisabledAt)
	}
	if in.LockedUntil != nil {
		t.Errorf("LockedUntil = %v, want nil", in.LockedUntil)
	}
	if in.LastActivityAt != nil {
		t.Errorf("LastActivityAt = %v, want nil", in.LastActivityAt)
	}
	if in.ReactivatedAt != nil {
		t.Errorf("ReactivatedAt = %v, want nil", in.ReactivatedAt)
	}
	if in.DormancyExempt {
		t.Error("DormancyExempt = true, want false")
	}
	if got := Evaluate(in, now, lockout.Defaults()); got != StatusActive {
		t.Errorf("Evaluate() = %q, want %q", got, StatusActive)
	}
}
