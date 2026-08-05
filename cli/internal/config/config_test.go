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

func TestLoad(t *testing.T) {
	t.Run("missing file returns zero-value config, no error", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "does-not-exist.json")

		cfg, err := Load(path)
		if err != nil {
			t.Fatalf("Load() unexpected error: %v", err)
		}
		if cfg.DefaultHub != "" || cfg.Hubs != nil {
			t.Fatalf("Load() = %+v, want zero-value Config", cfg)
		}
	})

	t.Run("malformed file returns error", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.json")
		if err := os.WriteFile(path, []byte("{not valid json"), 0o600); err != nil {
			t.Fatalf("failed to write fixture: %v", err)
		}

		_, err := Load(path)
		if err == nil {
			t.Fatal("Load() = nil error, want error for malformed JSON")
		}
	})

	t.Run("valid file parses hubs and default_hub", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.json")
		content := `{
			"default_hub": "https://hub.example.com",
			"hubs": {
				"https://hub.example.com": {"api_token": "adt_abc123"}
			}
		}`
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("failed to write fixture: %v", err)
		}

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
	})

	t.Run("unknown fields tolerated", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.json")
		content := `{
			"default_hub": "https://hub.example.com",
			"some_future_field": "value",
			"hubs": {
				"https://hub.example.com": {"api_token": "adt_abc123", "future_hub_field": 42}
			}
		}`
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("failed to write fixture: %v", err)
		}

		cfg, err := Load(path)
		if err != nil {
			t.Fatalf("Load() unexpected error with unknown fields: %v", err)
		}
		if cfg.DefaultHub != "https://hub.example.com" {
			t.Fatalf("DefaultHub = %q, want %q", cfg.DefaultHub, "https://hub.example.com")
		}
	})
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
}

func TestEffectiveHub(t *testing.T) {
	cfg := Config{DefaultHub: "https://config-hub.example.com"}

	tests := []struct {
		name       string
		flagVal    string
		envVal     string
		cfg        Config
		wantURL    string
		wantSource string
		wantErr    error
	}{
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

			if tt.wantErr != nil {
				if tt.wantErr == ErrNoHub {
					if !errors.Is(err, ErrNoHub) {
						t.Fatalf("EffectiveHub() err = %v, want ErrNoHub", err)
					}
					return
				}
				// errSentinelInvalid is a marker meaning "any non-nil error".
				if err == nil {
					t.Fatalf("EffectiveHub() = nil error, want error for invalid URL")
				}
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
		})
	}
}

// errSentinelInvalid is a test-local marker distinguishing "expect any
// error" from "expect ErrNoHub specifically" in the EffectiveHub table.
var errSentinelInvalid = errors.New("sentinel: any error expected")
