package applicationproxy

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"
)

func testTarget() Target {
	return Target{ApplicationID: "application", ConfigVersion: 1, Scheme: "http", Hostname: "backend.test", Port: 8080, AllowedCIDRs: []string{"127.0.0.0/8"}}
}

func TestTargetRejectsUnscopedAndAmbiguousDestinations(t *testing.T) {
	for _, mutate := range []func(*Target){
		func(t *Target) { t.AllowedCIDRs = nil },
		func(t *Target) { t.AllowedCIDRs = []string{"invalid"} },
		func(t *Target) { t.Hostname = "user@backend.test" },
		func(t *Target) { t.Hostname = "backend.test/path" },
		func(t *Target) { t.Hostname = "fe80::1%eth0" },
		func(t *Target) { t.Port = 0 },
		func(t *Target) { t.Scheme = "file" },
		func(t *Target) { t.ConfigVersion = 0 },
	} {
		target := testTarget()
		mutate(&target)
		if err := ValidateTarget(target); err == nil {
			t.Fatalf("accepted invalid target: %+v", target)
		}
	}
}

func TestDialPinsValidatedIPAndRejectsRebinding(t *testing.T) {
	target := testTarget()
	var dialed string
	d := Dialer{Lookup: func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}, Dial: func(_ context.Context, network, address string) (net.Conn, error) {
		dialed = address
		a, b := net.Pipe()
		b.Close()
		return a, nil
	}}
	conn, err := d.DialTarget(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if dialed != "127.0.0.1:8080" {
		t.Fatalf("DNS hostname was redialed: %q", dialed)
	}
	dialed = ""
	d.Lookup = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("169.254.169.254")}, nil
	}
	if _, err := d.DialTarget(context.Background(), target); err == nil || dialed != "" {
		t.Fatalf("mixed forbidden DNS result dialed: err=%v address=%q", err, dialed)
	}
}

func TestDialBlocksControlPlaneAndMetadataWithinWideScope(t *testing.T) {
	for _, address := range []string{"0.0.0.0", "224.0.0.1", "169.254.169.254", "100.100.100.200", "fd00:ec2::254", "::", "fe80::1"} {
		target := testTarget()
		target.AllowedCIDRs = []string{"0.0.0.0/0", "::/0"}
		target.Hostname = address
		called := false
		d := Dialer{Dial: func(context.Context, string, string) (net.Conn, error) { called = true; return nil, nil }}
		if _, err := d.DialTarget(context.Background(), target); err == nil || called {
			t.Fatalf("forbidden address dialed: %s err=%v", address, err)
		}
	}
	target := testTarget()
	d := Dialer{Lookup: func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}, Forbidden: []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:8080")}}
	if _, err := d.DialTarget(context.Background(), target); err == nil {
		t.Fatal("control listener allowed")
	}
}

func TestDialCancellationReachesResolver(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	d := Dialer{Lookup: func(ctx context.Context, _ string) ([]netip.Addr, error) { <-ctx.Done(); return nil, ctx.Err() }}
	if _, err := d.DialTarget(ctx, testTarget()); err == nil {
		t.Fatal("cancelled resolver allowed")
	}
}

func TestDialRejectsAliasesOfProtectedHubAuthority(t *testing.T) {
	target := testTarget()
	target.Port = 9090
	called := false
	d := Dialer{ForbiddenAuthorities: []string{"hub.test:9090"}, Lookup: func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}, Dial: func(context.Context, string, string) (net.Conn, error) { called = true; return nil, nil }}
	if _, err := d.DialTarget(context.Background(), target); err == nil || called {
		t.Fatal("Hub alias permitted")
	}
}

func TestDialTriesOnlyValidatedNumericFallbacks(t *testing.T) {
	target := testTarget()
	var dialed []string
	d := Dialer{Lookup: func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.2")}, nil
	}, Dial: func(_ context.Context, _ string, address string) (net.Conn, error) {
		dialed = append(dialed, address)
		if len(dialed) == 1 {
			return nil, context.DeadlineExceeded
		}
		a, b := net.Pipe()
		b.Close()
		return a, nil
	}}
	conn, err := d.DialTarget(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if len(dialed) != 2 || dialed[1] != "127.0.0.2:8080" {
		t.Fatalf("unchecked fallback: %v", dialed)
	}
}

func TestRetainedTargetCannotBeChangedThroughAdministratorSlice(t *testing.T) {
	original := testTarget()
	retained := original.Copy()
	original.AllowedCIDRs[0] = "0.0.0.0/0"
	if retained.AllowedCIDRs[0] != "127.0.0.0/8" {
		t.Fatal("asynchronous destination authority changed through aliased slice")
	}
}
