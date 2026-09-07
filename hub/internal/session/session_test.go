package session_test

import (
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/lockout"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/session"
)

// base is the reference instant every case is written around. All times are
// UTC because the hub stores and compares UTC.
var base = time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)

// testPolicy returns a policy with both session limits set, so a case that
// wants to exercise one limit has to opt out of the other explicitly.
func testPolicy() lockout.Policy {
	p := lockout.Defaults()
	p.SessionIdle = 15 * time.Minute
	p.SessionMax = 12 * time.Hour
	return p
}

func at(d time.Duration) *time.Time {
	t := base.Add(d)
	return &t
}

// TestEvaluate covers the whole verdict table: the precedence between the
// three refusal causes and the exact boundary of each limit.
func TestEvaluate(t *testing.T) {
	idleOnly := testPolicy()
	idleOnly.SessionMax = 0

	noIdle := testPolicy()
	noIdle.SessionIdle = 0

	noLimits := lockout.Policy{}

	cases := []struct {
		name   string
		state  session.State
		now    time.Time
		policy lockout.Policy
		want   session.Verdict
	}{
		{
			name:   "live session inside both limits",
			state:  session.State{CreatedAt: base, LastSeenAt: base},
			now:    base.Add(time.Minute),
			policy: testPolicy(),
			want:   session.VerdictOK,
		},
		{
			name: "ended beats absolute and idle",
			state: session.State{
				CreatedAt:  base,
				LastSeenAt: base,
				ExpiresAt:  at(time.Hour),
				EndedAt:    at(30 * time.Minute),
			},
			now:    base.Add(48 * time.Hour),
			policy: testPolicy(),
			want:   session.VerdictEnded,
		},
		{
			name: "ended reported even while otherwise healthy",
			state: session.State{
				CreatedAt:  base,
				LastSeenAt: base,
				ExpiresAt:  at(12 * time.Hour),
				EndedAt:    at(time.Minute),
			},
			now:    base.Add(2 * time.Minute),
			policy: testPolicy(),
			want:   session.VerdictEnded,
		},
		{
			name: "absolute beats idle",
			state: session.State{
				CreatedAt:  base,
				LastSeenAt: base,
				ExpiresAt:  at(time.Hour),
				// Also well past the 15-minute idle limit.
			},
			now:    base.Add(2 * time.Hour),
			policy: testPolicy(),
			want:   session.VerdictExpiredAbsolute,
		},
		{
			name: "absolute exactly at expires_at is expired",
			state: session.State{
				CreatedAt:  base,
				LastSeenAt: base.Add(time.Hour),
				ExpiresAt:  at(time.Hour),
			},
			now:    base.Add(time.Hour),
			policy: testPolicy(),
			want:   session.VerdictExpiredAbsolute,
		},
		{
			name: "absolute one nanosecond early is still live",
			state: session.State{
				CreatedAt:  base,
				LastSeenAt: base.Add(time.Hour),
				ExpiresAt:  at(time.Hour),
			},
			now:    base.Add(time.Hour - time.Nanosecond),
			policy: testPolicy(),
			want:   session.VerdictOK,
		},
		{
			name:   "nil expires_at is never absolute",
			state:  session.State{CreatedAt: base, LastSeenAt: base.Add(48 * time.Hour)},
			now:    base.Add(48 * time.Hour),
			policy: testPolicy(),
			want:   session.VerdictOK,
		},
		{
			name:   "idle exactly at the limit is still live",
			state:  session.State{CreatedAt: base, LastSeenAt: base},
			now:    base.Add(15 * time.Minute),
			policy: idleOnly,
			want:   session.VerdictOK,
		},
		{
			name:   "idle one second past the limit is expired",
			state:  session.State{CreatedAt: base, LastSeenAt: base},
			now:    base.Add(15*time.Minute + time.Second),
			policy: idleOnly,
			want:   session.VerdictExpiredIdle,
		},
		{
			name:   "idle one nanosecond past the limit is expired",
			state:  session.State{CreatedAt: base, LastSeenAt: base},
			now:    base.Add(15*time.Minute + time.Nanosecond),
			policy: idleOnly,
			want:   session.VerdictExpiredIdle,
		},
		{
			name:   "idle policy zero never expires on idle",
			state:  session.State{CreatedAt: base, LastSeenAt: base},
			now:    base.Add(30 * 24 * time.Hour),
			policy: noIdle,
			want:   session.VerdictOK,
		},
		{
			name: "idle applies while the absolute limit is still ahead",
			state: session.State{
				CreatedAt:  base,
				LastSeenAt: base,
				ExpiresAt:  at(12 * time.Hour),
			},
			now:    base.Add(16 * time.Minute),
			policy: testPolicy(),
			want:   session.VerdictExpiredIdle,
		},
		{
			name:   "both limits disabled leaves a session live indefinitely",
			state:  session.State{CreatedAt: base, LastSeenAt: base},
			now:    base.Add(365 * 24 * time.Hour),
			policy: noLimits,
			want:   session.VerdictOK,
		},
		{
			name: "absolute still applies when the idle limit is disabled",
			state: session.State{
				CreatedAt:  base,
				LastSeenAt: base.Add(11 * time.Hour),
				ExpiresAt:  at(12 * time.Hour),
			},
			now:    base.Add(13 * time.Hour),
			policy: noIdle,
			want:   session.VerdictExpiredAbsolute,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := session.Evaluate(tc.state, tc.now, tc.policy); got != tc.want {
				t.Fatalf("Evaluate = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestIdleDeadline covers the derived deadline shown to users: last seen plus
// the idle limit, and nothing at all when idle enforcement is off.
func TestIdleDeadline(t *testing.T) {
	p := testPolicy()
	st := session.State{CreatedAt: base, LastSeenAt: base.Add(3 * time.Minute)}

	got := session.IdleDeadline(st, p)
	if got == nil {
		t.Fatal("expected a deadline, got nil")
	}
	want := base.Add(18 * time.Minute)
	if !got.Equal(want) {
		t.Fatalf("IdleDeadline = %s, want %s", got.Format(time.RFC3339), want.Format(time.RFC3339))
	}

	p.SessionIdle = 0
	if got := session.IdleDeadline(st, p); got != nil {
		t.Fatalf("expected nil deadline when the idle policy is 0, got %s", got.Format(time.RFC3339))
	}

	p.SessionIdle = -time.Minute
	if got := session.IdleDeadline(st, p); got != nil {
		t.Fatalf("expected nil deadline for a negative idle policy, got %s", got.Format(time.RFC3339))
	}
}

// TestMessages pins the two refusal messages, which the API contract, the web
// UI and the CLI all reproduce verbatim.
func TestMessages(t *testing.T) {
	if session.MsgExpired != "session expired — sign in again" {
		t.Fatalf("MsgExpired = %q", session.MsgExpired)
	}
	if session.MsgEnded != "session ended — sign in again" {
		t.Fatalf("MsgEnded = %q", session.MsgEnded)
	}

	cases := []struct {
		verdict session.Verdict
		want    string
	}{
		{session.VerdictOK, ""},
		{session.VerdictEnded, session.MsgEnded},
		{session.VerdictExpiredIdle, session.MsgExpired},
		{session.VerdictExpiredAbsolute, session.MsgExpired},
		{session.Verdict(42), ""},
	}
	for _, tc := range cases {
		if got := session.Message(tc.verdict); got != tc.want {
			t.Fatalf("Message(%v) = %q, want %q", tc.verdict, got, tc.want)
		}
	}
}

// TestVerdictString pins the names used in audit details and end reasons.
func TestVerdictString(t *testing.T) {
	cases := []struct {
		verdict session.Verdict
		want    string
	}{
		{session.VerdictOK, "ok"},
		{session.VerdictEnded, "ended"},
		{session.VerdictExpiredIdle, "expired_idle"},
		{session.VerdictExpiredAbsolute, "expired_absolute"},
		{session.Verdict(42), "unknown"},
	}
	for _, tc := range cases {
		if got := tc.verdict.String(); got != tc.want {
			t.Fatalf("Verdict(%d).String() = %q, want %q", tc.verdict, got, tc.want)
		}
	}
}

// TestStateFromModel checks the projection of a stored row onto the four
// fields the evaluation needs, including the nullable ones.
func TestStateFromModel(t *testing.T) {
	expires := base.Add(12 * time.Hour)
	ended := base.Add(time.Hour)
	m := &model.Session{
		ID:         "sess-1",
		UserID:     "u-1",
		CreatedAt:  base,
		LastSeenAt: base.Add(time.Minute),
		ExpiresAt:  &expires,
		EndedAt:    &ended,
	}

	st := session.StateFromModel(m)
	if !st.CreatedAt.Equal(base) {
		t.Fatalf("CreatedAt = %s", st.CreatedAt.Format(time.RFC3339))
	}
	if !st.LastSeenAt.Equal(base.Add(time.Minute)) {
		t.Fatalf("LastSeenAt = %s", st.LastSeenAt.Format(time.RFC3339))
	}
	if st.ExpiresAt == nil || !st.ExpiresAt.Equal(expires) {
		t.Fatalf("ExpiresAt = %v", st.ExpiresAt)
	}
	if st.EndedAt == nil || !st.EndedAt.Equal(ended) {
		t.Fatalf("EndedAt = %v", st.EndedAt)
	}

	live := &model.Session{ID: "sess-2", UserID: "u-1", CreatedAt: base, LastSeenAt: base}
	st = session.StateFromModel(live)
	if st.ExpiresAt != nil || st.EndedAt != nil {
		t.Fatalf("expected nil nullable times, got expires=%v ended=%v", st.ExpiresAt, st.EndedAt)
	}
	if session.Evaluate(st, base.Add(time.Minute), testPolicy()) != session.VerdictOK {
		t.Fatal("expected a freshly created session to evaluate OK")
	}
}
