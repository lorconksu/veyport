// Package sshconfig resolves the effective configuration for the SSH gateway
// (feature 005-ssh-gateway) from the `_config` table, falling back to the
// hub's CLI flags and hardcoded defaults.
//
// This lives in its own tiny package — rather than as a method on
// *server.Server (the "hub already has it" precedent in
// hub/internal/server/handlers_hub_config.go) or as exported funcs on
// *store.Store — so it can be imported by both hub/cmd/veyport/main.go and
// the future hub/internal/sshgw package without an import cycle: sshgw will
// need to read this config, and server (which registers HTTP routes) will
// eventually need to wire sshgw in, so sshgw must not import server. Putting
// the accessor in server would block that. Store is the right place for raw
// key/value access, but not for flag-fallback/default/validation policy,
// which is specific to this feature; a dedicated package keeps that policy
// out of the generic store layer.
package sshconfig

import (
	"log"
	"strconv"

	"github.com/wyiu/veyport/hub/internal/store"
)

const (
	// DefaultAddr is the SSH gateway listen address used when neither the
	// DB config nor the --ssh-addr flag override it.
	DefaultAddr = ":2222"

	defaultEnabled      = true
	defaultCertTTLHours = 12
)

const (
	keyEnabled    = "ssh_gateway_enabled"
	keyAddr       = "ssh_addr"
	keyCertTTLHrs = "ssh_cert_ttl_hours"
)

// Config is the effective SSH gateway configuration, resolved from the
// `_config` table with CLI-flag and hardcoded-default fallback.
type Config struct {
	// Enabled controls whether the SSH gateway listener starts at all.
	Enabled bool
	// Addr is the listen address for the SSH gateway (host:port form).
	Addr string
	// CertTTLHours is the validity window for issued user SSH certificates.
	CertTTLHours int
}

// Load resolves the SSH gateway configuration. Precedence per key, matching
// the DB-over-flag precedent in handleGetHubConfig
// (hub/internal/server/handlers_hub_config.go:21):
//
//   - ssh_gateway_enabled: DB value > hardcoded default (true)
//   - ssh_addr:            DB value > flagAddr > DefaultAddr
//   - ssh_cert_ttl_hours:  DB value > hardcoded default (12)
//
// An invalid stored value (fails to parse, or out of range) is logged and
// treated as absent, falling back to the next level rather than aborting
// startup.
func Load(st *store.Store, flagAddr string) Config {
	cfg := Config{
		Enabled:      defaultEnabled,
		Addr:         flagAddr,
		CertTTLHours: defaultCertTTLHours,
	}
	if cfg.Addr == "" {
		cfg.Addr = DefaultAddr
	}

	if v, ok, err := st.LookupConfig(keyEnabled); err != nil {
		log.Printf("sshconfig: lookup %s: %v; using default %v", keyEnabled, err, defaultEnabled)
	} else if ok {
		b, perr := strconv.ParseBool(v)
		if perr != nil {
			log.Printf("sshconfig: invalid %s %q; using default %v", keyEnabled, v, defaultEnabled)
		} else {
			cfg.Enabled = b
		}
	}

	if v, ok, err := st.LookupConfig(keyAddr); err != nil {
		log.Printf("sshconfig: lookup %s: %v; using fallback %q", keyAddr, err, cfg.Addr)
	} else if ok {
		if v == "" {
			log.Printf("sshconfig: empty %s; using fallback %q", keyAddr, cfg.Addr)
		} else {
			cfg.Addr = v
		}
	}

	if v, ok, err := st.LookupConfig(keyCertTTLHrs); err != nil {
		log.Printf("sshconfig: lookup %s: %v; using default %d", keyCertTTLHrs, err, defaultCertTTLHours)
	} else if ok {
		n, perr := strconv.Atoi(v)
		if perr != nil || n <= 0 {
			log.Printf("sshconfig: invalid %s %q; using default %d", keyCertTTLHrs, v, defaultCertTTLHours)
		} else {
			cfg.CertTTLHours = n
		}
	}

	return cfg
}
