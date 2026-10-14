// Package applicationproxy contains the bounded byte transport and destination
// policy shared by the Hub and enrolled agents. It carries no HTTP credentials.
package applicationproxy

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

var ErrTarget = errors.New("application destination is not permitted")

// Target is an administrator-approved immutable destination. Callers copy
// AllowedCIDRs before retaining it across asynchronous admission.
type Target struct {
	ApplicationID string
	ConfigVersion int64
	NodeID        string
	Scheme        string
	Hostname      string
	Port          uint16
	AllowedCIDRs  []string
}

func (t Target) Copy() Target { t.AllowedCIDRs = append([]string(nil), t.AllowedCIDRs...); return t }

func ValidateTarget(t Target) error {
	if t.ApplicationID == "" || len(t.ApplicationID) > 128 || t.ConfigVersion < 1 || len(t.NodeID) > 128 || (t.Scheme != "http" && t.Scheme != "https") || t.Port == 0 || len(t.Hostname) == 0 || len(t.Hostname) > 253 || len(t.AllowedCIDRs) == 0 || len(t.AllowedCIDRs) > 32 {
		return ErrTarget
	}
	if strings.ContainsAny(t.Hostname, "@/\\?#%\x00\r\n\t ") || strings.ContainsAny(t.ApplicationID+t.NodeID, "\x00\r\n") {
		return ErrTarget
	}
	if ip, err := netip.ParseAddr(t.Hostname); err != nil {
		if strings.Contains(t.Hostname, ":") || strings.HasPrefix(t.Hostname, ".") || strings.HasSuffix(t.Hostname, ".") || strings.ToLower(t.Hostname) != t.Hostname {
			return ErrTarget
		}
		for _, label := range strings.Split(t.Hostname, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return ErrTarget
			}
			for _, r := range label {
				if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
					return ErrTarget
				}
			}
		}
	} else if ip.Zone() != "" {
		return ErrTarget
	}
	for _, raw := range t.AllowedCIDRs {
		p, err := netip.ParsePrefix(raw)
		if err != nil || p.Addr().Zone() != "" || p != p.Masked() {
			return ErrTarget
		}
	}
	return nil
}

// Dialer always resolves before policy evaluation and dials only a checked
// numeric address. No ambient proxy configuration participates in this path.
type Dialer struct {
	Lookup               func(context.Context, string) ([]netip.Addr, error)
	Dial                 func(context.Context, string, string) (net.Conn, error)
	Forbidden            []netip.AddrPort
	ForbiddenAuthorities []string
	Timeout              time.Duration
}

func (d Dialer) DialTarget(ctx context.Context, t Target) (net.Conn, error) {
	if len(d.ForbiddenAuthorities) > 512 || len(d.Forbidden) > 512 {
		return nil, ErrTarget
	}
	if err := ValidateTarget(t); err != nil {
		return nil, err
	}
	timeout := d.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var addresses []netip.Addr
	if ip, err := netip.ParseAddr(t.Hostname); err == nil {
		addresses = []netip.Addr{ip}
	} else {
		lookup := d.Lookup
		if lookup == nil {
			lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
				return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
			}
		}
		var err error
		addresses, err = lookup(ctx, t.Hostname)
		if err != nil {
			return nil, ErrTarget
		}
	}
	if len(addresses) == 0 || len(addresses) > 64 {
		return nil, ErrTarget
	}
	prefixes := make([]netip.Prefix, 0, len(t.AllowedCIDRs))
	for _, raw := range t.AllowedCIDRs {
		p, _ := netip.ParsePrefix(raw)
		prefixes = append(prefixes, p)
	}
	// Reject mixed allowed/forbidden answers rather than letting answer ordering
	// turn a configured origin into a rebinding bypass.
	for _, address := range addresses {
		address = address.Unmap()
		if !permittedAddress(address, prefixes, d.Forbidden, t.Port) {
			return nil, ErrTarget
		}
	}
	// Resolve protected authorities in the same network as the target. Reject
	// failures rather than guessing that a control endpoint moved elsewhere.
	for _, authority := range d.ForbiddenAuthorities {
		host, portText, err := net.SplitHostPort(authority)
		if err != nil {
			return nil, ErrTarget
		}
		port, err := strconv.ParseUint(portText, 10, 16)
		if err != nil {
			return nil, ErrTarget
		}
		if uint16(port) != t.Port {
			continue
		}
		if strings.EqualFold(host, t.Hostname) {
			return nil, ErrTarget
		}
		var protected []netip.Addr
		if ip, err := netip.ParseAddr(host); err == nil {
			protected = []netip.Addr{ip}
		} else {
			lookup := d.Lookup
			if lookup == nil {
				lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
					return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
				}
			}
			protected, err = lookup(ctx, host)
			if err != nil || len(protected) == 0 || len(protected) > 64 {
				return nil, ErrTarget
			}
		}
		for _, candidate := range addresses {
			for _, blocked := range protected {
				if candidate.Unmap() == blocked.Unmap() {
					return nil, ErrTarget
				}
			}
		}
	}
	dial := d.Dial
	if dial == nil {
		dial = (&net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}).DialContext
	}
	for _, address := range addresses {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		conn, err := dial(ctx, "tcp", net.JoinHostPort(address.Unmap().String(), strconv.Itoa(int(t.Port))))
		if err == nil {
			return conn, nil
		}
	}
	return nil, errors.New("application backend connection failed")
}

func permittedAddress(address netip.Addr, prefixes []netip.Prefix, forbidden []netip.AddrPort, port uint16) bool {
	if !address.IsValid() || address.IsUnspecified() || address.IsMulticast() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() || address.Zone() != "" || address == netip.MustParseAddr("100.100.100.200") || address == netip.MustParseAddr("fd00:ec2::254") {
		return false
	}
	for _, endpoint := range forbidden {
		if endpoint.Addr().Unmap() == address && endpoint.Port() == port {
			return false
		}
	}
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}
