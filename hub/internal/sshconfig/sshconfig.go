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
	fallbackAddr := flagAddr
	if fallbackAddr == "" {
		fallbackAddr = DefaultAddr
	}

	return Config{
		Enabled:      resolveEnabled(st),
		Addr:         resolveAddr(st, fallbackAddr),
		CertTTLHours: resolveCertTTLHours(st),
	}
}

// resolveEnabled resolves ssh_gateway_enabled: DB value, else the hardcoded
// default (true). An invalid stored value is logged and treated as absent.
// Split out of Load to keep its cognitive complexity down (go:S3776).
func resolveEnabled(st *store.Store) bool {
	v, ok, err := st.LookupConfig(keyEnabled)
	if err != nil {
		log.Printf("sshconfig: lookup %s: %v; using default %v", keyEnabled, err, defaultEnabled)
		return defaultEnabled
	}
	if !ok {
		return defaultEnabled
	}
	b, perr := strconv.ParseBool(v)
	if perr != nil {
		log.Printf("sshconfig: invalid %s %q; using default %v", keyEnabled, v, defaultEnabled)
		return defaultEnabled
	}
	return b
}

// resolveAddr resolves ssh_addr: DB value, else fallback (already resolved
// from --ssh-addr or DefaultAddr by Load). An invalid (empty) stored value is
// logged and treated as absent. Split out of Load to keep its cognitive
// complexity down (go:S3776).
func resolveAddr(st *store.Store, fallback string) string {
	v, ok, err := st.LookupConfig(keyAddr)
	if err != nil {
		log.Printf("sshconfig: lookup %s: %v; using fallback %q", keyAddr, err, fallback)
		return fallback
	}
	if !ok {
		return fallback
	}
	if v == "" {
		log.Printf("sshconfig: empty %s; using fallback %q", keyAddr, fallback)
		return fallback
	}
	return v
}

// resolveCertTTLHours resolves ssh_cert_ttl_hours: DB value, else the
// hardcoded default. An invalid or non-positive stored value is logged and
// treated as absent. Split out of Load to keep its cognitive complexity down
// (go:S3776).
func resolveCertTTLHours(st *store.Store) int {
	v, ok, err := st.LookupConfig(keyCertTTLHrs)
	if err != nil {
		log.Printf("sshconfig: lookup %s: %v; using default %d", keyCertTTLHrs, err, defaultCertTTLHours)
		return defaultCertTTLHours
	}
	if !ok {
		return defaultCertTTLHours
	}
	n, perr := strconv.Atoi(v)
	if perr != nil || n <= 0 {
		log.Printf("sshconfig: invalid %s %q; using default %d", keyCertTTLHrs, v, defaultCertTTLHours)
		return defaultCertTTLHours
	}
	return n
}
