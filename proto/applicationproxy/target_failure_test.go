package applicationproxy

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestDialRejectsNoncanonicalTargetsBeforeNetworkAccess(t *testing.T) {
	for _, host := range []string{"Upper.test", ".backend", "backend.", "bad..test", "-bad.test", "bad-.test", "bad_.test", strings.Repeat("a", 64) + ".test", "bad:host"} {
		t.Run(host, func(t *testing.T) {
			target := testTarget()
			target.Hostname = host
			d := Dialer{Lookup: func(context.Context, string) ([]netip.Addr, error) {
				t.Fatal("invalid target reached DNS")
				return nil, nil
			}, Dial: func(context.Context, string, string) (net.Conn, error) {
				t.Fatal("invalid target reached TCP")
				return nil, nil
			}}
			if _, err := d.DialTarget(context.Background(), target); !errors.Is(err, ErrTarget) {
				t.Fatalf("target was not rejected: %v", err)
			}
		})
	}
	target := testTarget()
	target.AllowedCIDRs = []string{"127.0.0.1/8"}
	if _, err := (Dialer{}).DialTarget(context.Background(), target); !errors.Is(err, ErrTarget) {
		t.Fatalf("noncanonical network accepted: %v", err)
	}
}

func TestDialBoundsResolutionAndFailsClosedOnProtectedAuthorityErrors(t *testing.T) {
	for _, kind := range []string{"empty-answer", "too-many-answers", "outside-scope", "too-many-authorities", "too-many-endpoints", "invalid-authority", "invalid-port", "same-host", "protected-lookup-error", "protected-empty", "protected-too-many", "protected-numeric"} {
		t.Run(kind, func(t *testing.T) {
			target := testTarget()
			d := Dialer{Lookup: func(_ context.Context, host string) ([]netip.Addr, error) {
				if host == "control.test" {
					switch kind {
					case "protected-lookup-error":
						return nil, errors.New("unavailable")
					case "protected-empty":
						return nil, nil
					case "protected-too-many":
						return make([]netip.Addr, 65), nil
					}
				}
				switch kind {
				case "empty-answer":
					return nil, nil
				case "too-many-answers":
					return make([]netip.Addr, 65), nil
				case "outside-scope":
					return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
				}
				return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
			}, Dial: func(context.Context, string, string) (net.Conn, error) {
				t.Fatal("untrusted destination reached TCP")
				return nil, nil
			}}
			switch kind {
			case "too-many-authorities":
				d.ForbiddenAuthorities = make([]string, 513)
			case "too-many-endpoints":
				d.Forbidden = make([]netip.AddrPort, 513)
			case "invalid-authority":
				d.ForbiddenAuthorities = []string{"control.test"}
			case "invalid-port":
				d.ForbiddenAuthorities = []string{"control.test:65536"}
			case "same-host":
				d.ForbiddenAuthorities = []string{"backend.test:8080"}
			case "protected-numeric":
				d.ForbiddenAuthorities = []string{"127.0.0.1:8080"}
			case "protected-lookup-error", "protected-empty", "protected-too-many":
				d.ForbiddenAuthorities = []string{"control.test:8080"}
			}
			if _, err := d.DialTarget(context.Background(), target); !errors.Is(err, ErrTarget) {
				t.Fatalf("policy failure did not deny: %v", err)
			}
		})
	}
}

func TestDialDefaultResolverAndNumericSocketShareProtectedPolicy(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	target := testTarget()
	target.Hostname = "localhost"
	target.Port = uint16(listener.Addr().(*net.TCPAddr).Port)
	target.AllowedCIDRs = []string{"127.0.0.0/8", "::1/128"}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := (Dialer{}).DialTarget(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	peer, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	conn.SetDeadline(time.Now().Add(time.Second))
	peer.SetDeadline(time.Now().Add(time.Second))
	if _, err := conn.Write([]byte("pinned")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 6)
	if _, err := io.ReadFull(peer, got); err != nil || string(got) != "pinned" {
		t.Fatalf("numeric socket byte stream failed: %q %v", got, err)
	}
	target.Hostname = "127.0.0.1"
	d := Dialer{ForbiddenAuthorities: []string{net.JoinHostPort("localhost", strconv.Itoa(int(target.Port)))}, Dial: func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("default protected resolver permitted alias")
		return nil, nil
	}}
	if _, err := d.DialTarget(ctx, target); !errors.Is(err, ErrTarget) {
		t.Fatalf("control alias allowed: %v", err)
	}
}

func TestDialCancellationBeforeSocketAndAllFallbackFailures(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d := Dialer{Lookup: func(context.Context, string) ([]netip.Addr, error) {
		cancel()
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}, Dial: func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("cancelled admission dialed")
		return nil, nil
	}}
	if _, err := d.DialTarget(ctx, testTarget()); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
	count := 0
	d.Lookup = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.2")}, nil
	}
	d.ForbiddenAuthorities = []string{"control.test:9090"}
	d.Dial = func(context.Context, string, string) (net.Conn, error) {
		count++
		return nil, errors.New("private network failure")
	}
	if _, err := d.DialTarget(context.Background(), testTarget()); err == nil || err.Error() != "application backend connection failed" || count != 2 {
		t.Fatalf("fallback outcome: %d %v", count, err)
	}
}
