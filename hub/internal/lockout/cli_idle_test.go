package lockout_test

import (
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/wyiu/veyport/hub/internal/lockout"
)

func TestCLISessionIdleConfigLoadsIndependently(t *testing.T) {
	if lockout.KeyCLISessionIdleMinutes != "account.cli_session_idle_minutes" || lockout.DefaultCLISessionIdle != 45*time.Minute {
		t.Fatal("CLI config contract differs from default45minutes")
	}
	for _, tc := range []struct {
		raw  string
		want time.Duration
	}{
		{" 2 ", 2 * time.Minute},
		{"0", 0},
		{"-1", 45 * time.Minute},
		{"bad", 45 * time.Minute},
		{strconv.FormatInt(lockout.MaxCLISessionIdleMinutes, 10), time.Duration(lockout.MaxCLISessionIdleMinutes) * time.Minute},
		{strconv.FormatInt(lockout.MaxCLISessionIdleMinutes+1, 10), 45 * time.Minute},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			policy := lockout.Load(mapGetter(map[string]string{lockout.KeyCLISessionIdleMinutes: tc.raw, lockout.KeySessionIdleMinutes: "3"}))
			if policy.CLISessionIdle != tc.want || policy.SessionIdle != 3*time.Minute || policy.SessionMax != 12*time.Hour {
				t.Fatalf("loaded policy=%+v", policy)
			}
		})
	}
	p := lockout.Defaults()
	p.CLISessionIdle = -time.Minute
	if err := p.Validate(); !errors.Is(err, lockout.ErrInvalidPolicy) {
		t.Fatalf("negative CLI idle Validate=%v", err)
	}
}
