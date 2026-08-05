// Package config resolves vey's configuration from file, environment, and
// flag sources and manages hub profile selection.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// Config is the on-disk shape of ~/.config/vey/config.json.
//
// Unknown JSON fields are tolerated (forward compatibility): encoding/json
// silently ignores fields that don't map to a struct field, which is the
// desired behavior here and requires no extra code.
type Config struct {
	DefaultHub string                `json:"default_hub"`
	Hubs       map[string]HubProfile `json:"hubs"`
}

// HubProfile holds the per-hub settings stored in the config file.
type HubProfile struct {
	APIToken string `json:"api_token"`
}

// ErrNoHub is returned by EffectiveHub when no hub URL could be resolved
// from the flag, environment, or config file. Callers map it to exit code 2
// with usage guidance.
var ErrNoHub = errors.New("no hub configured: pass --hub, set VEYPORT_HUB, or set default_hub in the config file")

// DefaultPath returns the path to vey's config file, honoring
// XDG_CONFIG_HOME when set and falling back to ~/.config otherwise.
func DefaultPath() (string, error) {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("config: resolve home directory: %w", err)
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "vey", "config.json"), nil
}

// Load reads and parses the config file at path.
//
// A missing file is not an error: it yields a zero-value Config, since an
// unconfigured hub/token is a normal, expected state (resolved via flag/env
// or reported as ErrNoHub by EffectiveHub). A malformed file is an error.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Config{}, nil
		}
		return Config{}, fmt.Errorf("config: read %s: %w", path, err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("config: parse %s: %w", path, err)
	}
	return cfg, nil
}

// NormalizeHubURL normalizes a hub base URL into the canonical form used as
// the identity for credential scoping (data-model.md FR-005): lowercase
// host, scheme+host+port only (no trailing slash, path, query, or
// fragment), https required except for localhost/127.0.0.1/[::1], which may
// also use plain http.
func NormalizeHubURL(raw string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("config: hub URL is empty")
	}

	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("config: parse hub URL %q: %w", raw, err)
	}

	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("config: hub URL %q must be an absolute URL with scheme and host", raw)
	}

	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", fmt.Errorf("config: hub URL %q has unsupported scheme %q (must be http or https)", raw, u.Scheme)
	}

	if err := rejectExtraURLParts(u, raw); err != nil {
		return "", err
	}

	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", fmt.Errorf("config: hub URL %q has no host", raw)
	}

	if scheme == "http" && !isLocalHost(host) {
		return "", fmt.Errorf("config: hub URL %q must use https (plain http is only allowed for localhost/127.0.0.1/[::1])", raw)
	}

	return scheme + "://" + normalizedAuthority(u, host), nil
}

// rejectExtraURLParts returns an error if u carries any of the components
// NormalizeHubURL disallows in a hub base URL (path beyond "/", query,
// fragment, or userinfo).
func rejectExtraURLParts(u *url.URL, raw string) error {
	if u.Path != "" && u.Path != "/" {
		return fmt.Errorf("config: hub URL %q must not include a path", raw)
	}
	if u.RawQuery != "" {
		return fmt.Errorf("config: hub URL %q must not include a query", raw)
	}
	if u.Fragment != "" {
		return fmt.Errorf("config: hub URL %q must not include a fragment", raw)
	}
	if u.User != nil {
		return fmt.Errorf("config: hub URL %q must not include userinfo", raw)
	}
	return nil
}

// normalizedAuthority rebuilds the host[:port] authority for the normalized
// URL from u and the already-lowercased host. u.Hostname() strips brackets
// from IPv6 literals, so they are restored here to keep the rebuilt
// authority valid regardless of whether a port is present.
func normalizedAuthority(u *url.URL, host string) string {
	normalizedHost := host
	if strings.Contains(host, ":") {
		normalizedHost = "[" + host + "]"
	}
	if port := u.Port(); port != "" {
		normalizedHost = net.JoinHostPort(strings.Trim(normalizedHost, "[]"), port)
	}
	return normalizedHost
}

// isLocalHost reports whether host (already lowercased, without port) is
// one of the loopback addresses permitted to use plain http.
func isLocalHost(host string) bool {
	switch host {
	case "localhost", "127.0.0.1", "::1":
		return true
	default:
		return false
	}
}

// EffectiveHub resolves the hub URL to use, per precedence flag > env >
// config file (contracts/cli-commands.md Global behavior). It returns the
// normalized URL and the source that provided it ("flag", "env", or
// "config"). If all three are empty, it returns ErrNoHub.
func EffectiveHub(flagVal, envVal string, cfg Config) (hubURL string, source string, err error) {
	switch {
	case strings.TrimSpace(flagVal) != "":
		hubURL, source = flagVal, "flag"
	case strings.TrimSpace(envVal) != "":
		hubURL, source = envVal, "env"
	case strings.TrimSpace(cfg.DefaultHub) != "":
		hubURL, source = cfg.DefaultHub, "config"
	default:
		return "", "", ErrNoHub
	}

	normalized, err := NormalizeHubURL(hubURL)
	if err != nil {
		return "", "", fmt.Errorf("config: invalid hub URL from %s: %w", source, err)
	}
	return normalized, source, nil
}
