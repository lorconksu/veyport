package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/wyiu/veyport/cli/internal/cmdutil"
	"github.com/wyiu/veyport/cli/internal/update"
)

func TestUpdateUsageAndPublicDistributionFailures(t *testing.T) {
	for _, tc := range []struct {
		args                   []string
		hub, version, contains string
		code                   int
	}{
		{[]string{"--help"}, "", "dev", "usage:", 0},
		{[]string{"somewhere"}, "", "dev", "usage:", 2},
		{[]string{"--install-dir", "/tmp"}, "", "dev", "usage:", 2},
		{[]string{"--check"}, "", "dev", "no hub configured", 2},
		{[]string{"--check"}, "https://hub.example", "dev", "current CLI", 1},
		{nil, "https://hub.example", "dev", "current CLI", 1},
		{[]string{"--check"}, "http://localhost:8080", "1.2.3", "require an HTTPS", 1},
	} {
		ctx, out, errOut := newCmdContext(tc.hub, t.TempDir(), false, tc.args)
		ctx.Version = tc.version
		code := RunUpdate(ctx)
		if code != tc.code || !strings.Contains(out.String()+errOut.String(), tc.contains) {
			t.Fatalf("args=%v code=%d out=%q err=%q", tc.args, code, out, errOut)
		}
	}
}

func TestUpdateCommandRoutesCheckAndReportsVerifiedResult(t *testing.T) {
	for _, tc := range []struct {
		name                              string
		check, json, available, installed bool
		contains                          string
	}{
		{"check_available", true, false, true, false, "Update available:"},
		{"check_current", true, false, false, false, "No newer CLI update:"},
		{"installed", false, false, true, true, "Previous executable retained"},
		{"json_check", true, true, true, false, ""},
		{"json_install", false, true, true, true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := []string{}
			if tc.check {
				args = append(args, "--check")
			}
			ctx, out, errOut := newCmdContext("https://hub.example", t.TempDir(), tc.json, args)
			ctx.Version = "1.2.3"
			checkCalls, applyCalls := 0, 0
			result := update.Result{Hub: "https://hub.example", CurrentVersion: "1.2.3", AvailableVersion: "1.2.4", UpdateAvailable: tc.available, Installed: tc.installed, Backup: "/usr/local/bin/.vey-update-safe/previous"}
			check := func(_ context.Context, hub, version string) (update.Result, error) {
				checkCalls++
				if hub != result.Hub || version != result.CurrentVersion {
					t.Fatal("lost effective hub or version")
				}
				return result, nil
			}
			apply := func(c context.Context, hub, version string) (update.Result, error) {
				applyCalls++
				return check(c, hub, version)
			}
			if code := runUpdate(ctx, check, apply); code != 0 {
				t.Fatalf("code=%d error=%s", code, errOut)
			}
			if checkCalls != 1 || applyCalls == 1 && tc.check || applyCalls == 0 && !tc.check {
				t.Fatal("incorrect check/apply routing")
			}
			if errOut.Len() != 0 {
				t.Fatalf("success wrote stderr: %s", errOut)
			}
			if tc.json {
				var got update.Result
				if err := json.Unmarshal(out.Bytes(), &got); err != nil || got.Installed != tc.installed || got.UpdateAvailable != tc.available {
					t.Fatalf("JSON=%s error=%v", out, err)
				}
			} else if !strings.Contains(out.String(), tc.contains) {
				t.Fatalf("output=%s", out)
			}
		})
	}
}

func TestUpdateJSONFailureHasNoPayload(t *testing.T) {
	ctx, out, errOut := newCmdContext("https://hub.example", t.TempDir(), true, []string{"--check"})
	ctx.Version = "1.2.3"
	fail := func(context.Context, string, string) (update.Result, error) {
		return update.Result{}, fmt.Errorf("checksum mismatch")
	}
	if code := runUpdate(ctx, fail, fail); code != cmdutil.ExitError || out.Len() != 0 || !strings.Contains(errOut.String(), `"code":1`) || !strings.Contains(errOut.String(), "checksum mismatch") {
		t.Fatalf("out=%s err=%s", out, errOut)
	}
}
