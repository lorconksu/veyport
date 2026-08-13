package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestNormalizeHubURL(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    string
		wantErr bool
	}{
		{name: "https ok", raw: "https://hub.example.com", want: "https://hub.example.com"},
		{name: "https with port", raw: "https://hub.example.com:8443", want: "https://hub.example.com:8443"},
		{name: "http non-localhost rejected", raw: "http://hub.example.com", wantErr: true},
		{name: "http localhost ok", raw: "http://localhost:3000", want: "http://localhost:3000"},
		{name: "http 127.0.0.1 ok", raw: "http://127.0.0.1:3000", want: "http://127.0.0.1:3000"},
		{name: "http ipv6 loopback ok", raw: "http://[::1]:3000", want: "http://[::1]:3000"},
		{name: "http ipv6 loopback ok no port", raw: "http://[::1]", want: "http://[::1]"},
		{name: "case folding host", raw: "https://HUB.Example.COM", want: "https://hub.example.com"},
		{name: "case folding scheme", raw: "HTTPS://hub.example.com", want: "https://hub.example.com"},
		{name: "trailing slash stripped", raw: "https://hub.example.com/", want: "https://hub.example.com"},
		{name: "path rejected", raw: "https://hub.example.com/api", wantErr: true},
		{name: "query rejected", raw: "https://hub.example.com?x=1", wantErr: true},
		{name: "fragment rejected", raw: "https://hub.example.com#frag", wantErr: true},
		{name: "userinfo rejected", raw: "https://user:pass@hub.example.com", wantErr: true},
		{name: "empty rejected", raw: "", wantErr: true},
		{name: "no scheme rejected", raw: "hub.example.com", wantErr: true},
		{name: "unsupported scheme rejected", raw: "ftp://hub.example.com", wantErr: true},
		{name: "localhost https also ok", raw: "https://localhost:3000", want: "https://localhost:3000"},
		{name: "unparseable URL rejected", raw: "https://hub.example.com/%zz", wantErr: true},
		{name: "empty host rejected", raw: "https://:8443", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeHubURL(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("NormalizeHubURL(%q) = %q, want error", tt.raw, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizeHubURL(%q) unexpected error: %v", tt.raw, err)
			}
			if got != tt.want {
				t.Fatalf("NormalizeHubURL(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

// TestLoad dispatches each scenario to its own named test function rather
// than an inline closure, so each scenario's assertions are counted for
// cognitive complexity independently of the others instead of accumulating
// into one large function body.
func TestLoad(t *testing.T) {
	t.Run("missing file returns zero-value config, no error", testLoadMissingFile)
	t.Run("malformed file returns error", testLoadMalformedFile)
	t.Run("unreadable path (a directory) returns non-not-exist read error", testLoadUnreadablePath)
	t.Run("valid file parses hubs and default_hub", testLoadValidFile)
	t.Run("unknown fields tolerated", testLoadUnknownFieldsTolerated)
}

func testLoadMissingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "does-not-exist.json")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}
	if cfg.DefaultHub != "" || cfg.Hubs != nil {
		t.Fatalf("Load() = %+v, want zero-value Config", cfg)
	}
}

func testLoadMalformedFile(t *testing.T) {
	path := writeConfigFixture(t, "{not valid json")

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load() = nil error, want error for malformed JSON")
	}
}

func testLoadUnreadablePath(t *testing.T) {
	dir := t.TempDir()

	_, err := Load(dir)
	if err == nil {
		t.Fatal("Load() = nil error, want error reading a directory as a file")
	}
	if errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Load() = %v, want an error other than ErrNotExist", err)
	}
}

func testLoadValidFile(t *testing.T) {
	path := writeConfigFixture(t, `{
		"default_hub": "https://hub.example.com",
		"hubs": {
			"https://hub.example.com": {"api_token": "adt_abc123"}
		}
	}`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}
	if cfg.DefaultHub != "https://hub.example.com" {
		t.Fatalf("DefaultHub = %q, want %q", cfg.DefaultHub, "https://hub.example.com")
	}
	profile, ok := cfg.Hubs["https://hub.example.com"]
	if !ok {
		t.Fatalf("Hubs missing entry for hub.example.com: %+v", cfg.Hubs)
	}
	if profile.APIToken != "adt_abc123" {
		t.Fatalf("APIToken = %q, want %q", profile.APIToken, "adt_abc123")
	}
}

func testLoadUnknownFieldsTolerated(t *testing.T) {
	path := writeConfigFixture(t, `{
		"default_hub": "https://hub.example.com",
		"some_future_field": "value",
		"hubs": {
			"https://hub.example.com": {"api_token": "adt_abc123", "future_hub_field": 42}
		}
	}`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() unexpected error with unknown fields: %v", err)
	}
	if cfg.DefaultHub != "https://hub.example.com" {
		t.Fatalf("DefaultHub = %q, want %q", cfg.DefaultHub, "https://hub.example.com")
	}
}

// writeConfigFixture writes content to a fresh config.json under a new
// t.TempDir() and returns its path, failing the test on write error.
func writeConfigFixture(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}
	return path
}

func TestDefaultPath(t *testing.T) {
	t.Run("honors XDG_CONFIG_HOME", func(t *testing.T) {
		t.Setenv("XDG_CONFIG_HOME", "/xdg/custom")

		got, err := DefaultPath()
		if err != nil {
			t.Fatalf("DefaultPath() unexpected error: %v", err)
		}
		want := filepath.Join("/xdg/custom", "vey", "config.json")
		if got != want {
			t.Fatalf("DefaultPath() = %q, want %q", got, want)
		}
	})

	t.Run("falls back to ~/.config when XDG_CONFIG_HOME unset", func(t *testing.T) {
		t.Setenv("XDG_CONFIG_HOME", "")
		home := t.TempDir()
		t.Setenv("HOME", home)

		got, err := DefaultPath()
		if err != nil {
			t.Fatalf("DefaultPath() unexpected error: %v", err)
		}
		want := filepath.Join(home, ".config", "vey", "config.json")
		if got != want {
			t.Fatalf("DefaultPath() = %q, want %q", got, want)
		}
	})

	t.Run("returns error when home directory cannot be resolved", func(t *testing.T) {
		t.Setenv("XDG_CONFIG_HOME", "")
		t.Setenv("HOME", "")

		_, err := DefaultPath()
		if err == nil {
			t.Fatal("DefaultPath() = nil error, want error when $HOME is unset")
		}
	})
}

// effectiveHubCase is a single TestEffectiveHub table entry.
type effectiveHubCase struct {
	name       string
	flagVal    string
	envVal     string
	cfg        Config
	wantURL    string
	wantSource string
	wantErr    error
}

func TestEffectiveHub(t *testing.T) {
	cfg := Config{DefaultHub: "https://config-hub.example.com"}

	tests := []effectiveHubCase{
		{
			name:       "flag wins over env and config",
			flagVal:    "https://flag-hub.example.com",
			envVal:     "https://env-hub.example.com",
			cfg:        cfg,
			wantURL:    "https://flag-hub.example.com",
			wantSource: "flag",
		},
		{
			name:       "env wins over config when flag absent",
			flagVal:    "",
			envVal:     "https://env-hub.example.com",
			cfg:        cfg,
			wantURL:    "https://env-hub.example.com",
			wantSource: "env",
		},
		{
			name:       "config used when flag and env absent",
			flagVal:    "",
			envVal:     "",
			cfg:        cfg,
			wantURL:    "https://config-hub.example.com",
			wantSource: "config",
		},
		{
			name:    "none set returns ErrNoHub",
			flagVal: "",
			envVal:  "",
			cfg:     Config{},
			wantErr: ErrNoHub,
		},
		{
			name:    "flag set but invalid returns error",
			flagVal: "not-a-url",
			envVal:  "",
			cfg:     cfg,
			wantErr: errSentinelInvalid,
		},
		{
			name:       "http localhost flag ok",
			flagVal:    "http://localhost:3000",
			envVal:     "",
			cfg:        Config{},
			wantURL:    "http://localhost:3000",
			wantSource: "flag",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotURL, gotSource, err := EffectiveHub(tt.flagVal, tt.envVal, tt.cfg)
			checkEffectiveHubResult(t, tt, gotURL, gotSource, err)
		})
	}
}

// checkEffectiveHubResult asserts a single TestEffectiveHub case's outcome,
// split out so its branching is counted independently of the table loop.
func checkEffectiveHubResult(t *testing.T, tt effectiveHubCase, gotURL, gotSource string, err error) {
	t.Helper()

	if tt.wantErr != nil {
		checkEffectiveHubWantErr(t, tt.wantErr, err)
		return
	}

	if err != nil {
		t.Fatalf("EffectiveHub() unexpected error: %v", err)
	}
	if gotURL != tt.wantURL {
		t.Fatalf("EffectiveHub() url = %q, want %q", gotURL, tt.wantURL)
	}
	if gotSource != tt.wantSource {
		t.Fatalf("EffectiveHub() source = %q, want %q", gotSource, tt.wantSource)
	}
}

// checkEffectiveHubWantErr asserts the error-case half of
// checkEffectiveHubResult: either exactly ErrNoHub, or (via the
// errSentinelInvalid marker) any non-nil error.
func checkEffectiveHubWantErr(t *testing.T, wantErr, err error) {
	t.Helper()

	if wantErr == ErrNoHub {
		if !errors.Is(err, ErrNoHub) {
			t.Fatalf("EffectiveHub() err = %v, want ErrNoHub", err)
		}
		return
	}
	// errSentinelInvalid is a marker meaning "any non-nil error".
	if err == nil {
		t.Fatalf("EffectiveHub() = nil error, want error for invalid URL")
	}
}

// errSentinelInvalid is a test-local marker distinguishing "expect any
// error" from "expect ErrNoHub specifically" in the EffectiveHub table.
var errSentinelInvalid = errors.New("sentinel: any error expected")

func TestSaveThenLoadRoundTrips(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vey", "config.json")
	cfg := Config{
		DefaultHub: "https://hub.example.com",
		Hubs:       map[string]HubProfile{"https://hub.example.com": {APIToken: "adt_x"}},
	}
	if err := Save(path, cfg); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load after Save: %v", err)
	}
	if got.DefaultHub != cfg.DefaultHub {
		t.Errorf("DefaultHub = %q, want %q", got.DefaultHub, cfg.DefaultHub)
	}
	if got.Hubs["https://hub.example.com"].APIToken != "adt_x" {
		t.Errorf("Hubs not round-tripped: %+v", got.Hubs)
	}
}

func TestSaveCreatesParentDirAndRestrictsPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vey", "config.json")
	if err := Save(path, Config{DefaultHub: "https://h.example.com"}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	di, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("stat parent dir: %v", err)
	}
	if perm := di.Mode().Perm(); perm != 0o700 {
		t.Errorf("parent dir perm = %o, want 700", perm)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat config: %v", err)
	}
	// The config file can carry API tokens (HubProfile.APIToken), so it gets
	// the same 0600 discipline as the credential fallback file.
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("config perm = %o, want 600", perm)
	}
}

func TestSaveOverwritesExistingConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := Save(path, Config{DefaultHub: "https://first.example.com"}); err != nil {
		t.Fatalf("first Save: %v", err)
	}
	if err := Save(path, Config{DefaultHub: "https://second.example.com"}); err != nil {
		t.Fatalf("second Save: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.DefaultHub != "https://second.example.com" {
		t.Errorf("DefaultHub = %q, want the overwritten value", got.DefaultHub)
	}
}
