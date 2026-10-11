package auditgate

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"time"
)

// TransportConfig is administrator-managed. DNS names require explicit address
// pins; a DNS answer cannot redirect a trusted name to an arbitrary local service.
type TransportConfig struct {
	Endpoint         string
	AllowedHosts     []string
	AllowedAddresses []string
	TLS              *tls.Config
	Timeout          time.Duration
	Connections      int
}

func NewTLSClient(c TransportConfig) (*http.Client, error) {
	u, err := url.Parse(c.Endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" || c.TLS == nil || c.TLS.InsecureSkipVerify || c.TLS.RootCAs == nil || c.TLS.MinVersion < tls.VersionTLS12 || c.Timeout <= 0 || c.Timeout > 15*time.Second || c.Connections < 1 || c.Connections > 16 {
		return nil, ErrReceipt
	}
	allowed := false
	for _, h := range c.AllowedHosts {
		if h == u.Host {
			allowed = true
		}
	}
	if !allowed {
		return nil, ErrReceipt
	}
	addresses := map[netip.Addr]bool{}
	for _, s := range c.AllowedAddresses {
		ip, e := netip.ParseAddr(s)
		ip = ip.Unmap()
		if e != nil || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
			return nil, ErrReceipt
		}
		addresses[ip.Unmap()] = true
	}
	if ip, e := netip.ParseAddr(u.Hostname()); e == nil && len(addresses) == 0 {
		ip = ip.Unmap()
		if !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast() && !ip.IsMulticast() && !ip.IsUnspecified() {
			addresses[ip] = true
		}
	}
	if len(addresses) == 0 {
		return nil, ErrReceipt
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	dialer := net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		host, p, e := net.SplitHostPort(address)
		if e != nil || host != u.Hostname() || p != port {
			return nil, ErrReceipt
		}
		ips, e := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if e != nil || len(ips) == 0 {
			return nil, ErrReceipt
		}
		for _, ip := range ips {
			if !addresses[ip.Unmap()] {
				return nil, ErrReceipt
			}
		}
		return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
	}
	tlsConfig := c.TLS.Clone()
	if tlsConfig.ServerName != "" && tlsConfig.ServerName != u.Hostname() {
		return nil, ErrReceipt
	}
	tlsConfig.ServerName = u.Hostname()
	transport := &http.Transport{TLSClientConfig: tlsConfig, Proxy: nil, DialContext: dial, TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: c.Timeout, MaxConnsPerHost: c.Connections, MaxIdleConnsPerHost: c.Connections, MaxIdleConns: c.Connections, IdleConnTimeout: 30 * time.Second}
	return &http.Client{Transport: transport, Timeout: c.Timeout, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}, nil
}
