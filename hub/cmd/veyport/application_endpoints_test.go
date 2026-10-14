package main

import (
	"net/netip"
	"reflect"
	"testing"
)

func TestApplicationProtectedAuthoritiesNormalizePortalAndExplicitMappings(t *testing.T) {
	got := applicationProtectedAuthorities("https://portal.example.test", "hub.example.test:9090", " 10.10.1.96:8081,10.10.1.96:2222 , ")
	want := []string{"portal.example.test:443", "hub.example.test:9090", "10.10.1.96:8081", "10.10.1.96:2222"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("protected authorities%v", got)
	}
	got = applicationProtectedAuthorities("https://127.0.0.1:8443", "", "")
	if !reflect.DeepEqual(got, []string{"127.0.0.1:8443"}) {
		t.Fatal(got)
	}
}
func TestApplicationProtectedEndpointsIncludeBoundListenersAndPortal(t *testing.T) {
	got, e := applicationProtectedEndpoints([]string{":8080", "127.0.0.1:9090", "[::1]:2222", "invalid", "127.0.0.1:bad"}, "https://127.0.0.1:8443")
	if e != nil {
		t.Fatal(e)
	}
	set := map[netip.AddrPort]bool{}
	for _, v := range got {
		set[v] = true
	}
	for _, v := range []string{"127.0.0.1:8080", "127.0.0.1:9090", "[::1]:2222", "127.0.0.1:8443"} {
		if !set[netip.MustParseAddrPort(v)] {
			t.Fatal("missing protected endpoint", v)
		}
	}
}
