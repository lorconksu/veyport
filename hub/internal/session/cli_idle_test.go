package session_test

import (
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/lockout"
	"github.com/wyiu/veyport/hub/internal/model"
	"github.com/wyiu/veyport/hub/internal/session"
)

func TestIdlePolicyUsesStoredKindAndIndependentLimits(t *testing.T) {
	now := time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC)
	defaults := lockout.Defaults()
	webDisabled, cliDisabled, custom := defaults, defaults, defaults
	webDisabled.SessionIdle = 0
	cliDisabled.CLISessionIdle = 0
	custom.SessionIdle, custom.CLISessionIdle = 2*time.Minute, 4*time.Minute
	for _, tc := range []struct {
		name, kind string
		policy     lockout.Policy
		gap, idle  time.Duration
		want       session.Verdict
	}{
		{"cli_default20m", model.SessionKindCLI, defaults, 20 * time.Minute, 45 * time.Minute, session.VerdictOK},
		{"cli_default45m", model.SessionKindCLI, defaults, 45 * time.Minute, 45 * time.Minute, session.VerdictOK},
		{"cli_past45m", model.SessionKindCLI, defaults, 45*time.Minute + time.Nanosecond, 45 * time.Minute, session.VerdictExpiredIdle},
		{"web_default20m", model.SessionKindWeb, defaults, 20 * time.Minute, 15 * time.Minute, session.VerdictExpiredIdle},
		{"unknown_kind", "unknown", defaults, 20 * time.Minute, 15 * time.Minute, session.VerdictExpiredIdle},
		{"missing_kind", "", defaults, 20 * time.Minute, 15 * time.Minute, session.VerdictExpiredIdle},
		{"web_disabled", model.SessionKindWeb, webDisabled, time.Hour, 0, session.VerdictOK},
		{"web_disabled_cli_still_expires", model.SessionKindCLI, webDisabled, time.Hour, 45 * time.Minute, session.VerdictExpiredIdle},
		{"cli_disabled", model.SessionKindCLI, cliDisabled, time.Hour, 0, session.VerdictOK},
		{"cli_disabled_web_still_expires", model.SessionKindWeb, cliDisabled, time.Hour, 15 * time.Minute, session.VerdictExpiredIdle},
		{"custom_cli", model.SessionKindCLI, custom, 3 * time.Minute, 4 * time.Minute, session.VerdictOK},
		{"custom_web", model.SessionKindWeb, custom, 3 * time.Minute, 2 * time.Minute, session.VerdictExpiredIdle},
	} {
		t.Run(tc.name, func(t *testing.T) {
			row := &model.Session{Kind: tc.kind, CreatedAt: now.Add(-time.Hour), LastSeenAt: now.Add(-tc.gap), UserAgent: "vey/spoof"}
			state := session.StateFromModel(row)
			if state.Kind != tc.kind || session.IdleTimeout(state.Kind, tc.policy) != tc.idle {
				t.Fatal("stored kind did not select expected idle limit")
			}
			if got := session.Evaluate(state, now, tc.policy); got != tc.want {
				t.Fatalf("Evaluate=%s, want %s", got, tc.want)
			}
			deadline := session.IdleDeadline(state, tc.policy)
			if tc.idle == 0 {
				if deadline != nil {
					t.Fatalf("disabled deadline=%v", deadline)
				}
			} else if deadline == nil || !deadline.Equal(row.LastSeenAt.Add(tc.idle)) {
				t.Fatalf("deadline=%v, want %s", deadline, row.LastSeenAt.Add(tc.idle))
			}
		})
	}
}

func TestCLIAbsoluteExpiryAndRevocationOutrankIdle(t *testing.T) {
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	state := session.State{Kind: model.SessionKindCLI, CreatedAt: now.Add(-12 * time.Hour), LastSeenAt: now, ExpiresAt: &now}
	if got := session.Evaluate(state, now, lockout.Defaults()); got != session.VerdictExpiredAbsolute {
		t.Fatalf("CLI at12h=%s, want absolute expiry", got)
	}
	state.LastSeenAt = now.Add(-time.Hour)
	if got := session.Evaluate(state, now, lockout.Defaults()); got != session.VerdictExpiredAbsolute {
		t.Fatalf("CLI both timers expired=%s, want absolute expiry", got)
	}
	state.EndedAt = &now
	if got := session.Evaluate(state, now, lockout.Defaults()); got != session.VerdictEnded {
		t.Fatalf("revoked CLI=%s, want ended", got)
	}
}
