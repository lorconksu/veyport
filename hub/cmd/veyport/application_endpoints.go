package main

import (
	"context"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Enumerate concrete local listener IPs so broad private app CIDRs cannot make
// the proxy a path back into the Hub's own HTTP, enrollment or SSH authorities.
func applicationProtectedEndpoints(addresses []string, portalOrigin string) ([]netip.AddrPort, error) {
	local := []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.IPv6Loopback()}
	interfaces, e := net.InterfaceAddrs()
	if e != nil {
		return nil, e
	}
	for _, raw := range interfaces {
		ip, _, e := net.ParseCIDR(raw.String())
		if e != nil {
			continue
		}
		if addr, ok := netip.AddrFromSlice(ip); ok {
			local = append(local, addr.Unmap())
		}
	}
	out := []netip.AddrPort{}
	for _, value := range addresses {
		host, port, e := net.SplitHostPort(value)
		if e != nil {
			continue
		}
		n, e := strconv.ParseUint(port, 10, 16)
		if e != nil {
			continue
		}
		ips := local
		if host != "" && host != "0.0.0.0" && host != "::" {
			if ip, e := netip.ParseAddr(host); e == nil {
				ips = []netip.Addr{ip}
			}
		}
		for _, ip := range ips {
			out = append(out, netip.AddrPortFrom(ip, uint16(n)))
		}
	}
	u, e := url.Parse(portalOrigin)
	if e == nil && u.Host != "" {
		port := uint16(443)
		if raw := u.Port(); raw != "" {
			if n, e := strconv.ParseUint(raw, 10, 16); e == nil {
				port = uint16(n)
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if ips, e := net.DefaultResolver.LookupNetIP(ctx, "ip", strings.Trim(u.Hostname(), "[]")); e == nil {
			for _, ip := range ips {
				out = append(out, netip.AddrPortFrom(ip.Unmap(), port))
			}
		}
	}
	return out, nil
}

func applicationProtectedAuthorities(portalOrigin, grpcExternal, extra string) []string {
	out := []string{}
	if u, e := url.Parse(portalOrigin); e == nil && u.Hostname() != "" {
		port := u.Port()
		if port == "" {
			port = "443"
		}
		out = append(out, net.JoinHostPort(u.Hostname(), port))
	}
	if grpcExternal != "" {
		out = append(out, grpcExternal)
	}
	for _, item := range strings.Split(extra, ",") {
		if v := strings.TrimSpace(item); v != "" {
			out = append(out, v)
		}
	}
	return out
}
