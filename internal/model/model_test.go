package model

import (
	"strings"
	"testing"
	"time"
)

func TestDiscoveryClassifiesEvidence(t *testing.T) {
	cases := []struct {
		name string
		r    PingResult
		want string
	}{
		{"direct", PingResult{Endpoint: "203.0.113.8:41641"}, "direct"},
		{"derp", PingResult{DERPRegionID: 1, DERPRegionCode: "example"}, "derp"},
		{"peer relay", PingResult{PeerRelay: "203.0.113.9:40000:vni:5"}, "peer_relay"},
		{"missing", PingResult{}, "unknown"},
		{"invalid relay region", PingResult{DERPRegionID: -1}, "unknown"},
		{"conflicting", PingResult{Endpoint: "203.0.113.8:41641", DERPRegionID: 1}, "unknown"},
		{"malformed", PingResult{Endpoint: "bad:port"}, "unknown"},
		{"zero port", PingResult{Endpoint: "203.0.113.8:0"}, "unknown"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if p := DiscoveryPath(c.r, nil, time.Now()); p.Type != c.want {
				t.Fatalf("got %s, want %s", p.Type, c.want)
			}
		})
	}
}

func TestGlobalIPv6OnLocalPrefixDoesNotProveInternetTraversal(t *testing.T) {
	interfaces := []Interface{{Name: "wifi", Up: true, Prefixes: []string{"2001:db8:1::123/64"}}}
	p := DirectPath("[2001:db8:1::456]:41641", interfaces, time.Now())
	if p.Type != "direct" || p.UnderlayFamily != "ipv6" || p.NetworkScope != "unknown" {
		t.Fatalf("overclaimed path: %+v", p)
	}
	if !strings.Contains(strings.Join(p.Notes, ","), "matches_local_interface_prefix") {
		t.Fatal("missing local-prefix hint")
	}
}

func TestTailnetAndCGNATAddressDoesNotProvePublicTransport(t *testing.T) {
	p := DirectPath("100.100.1.1:40000", nil, time.Now())
	if p.NetworkScope != "unknown" || p.AddressScope != "shared_address_space" {
		t.Fatalf("bad scope: %+v", p)
	}
}

func TestNetworkFingerprintIgnoresEnumerationOrder(t *testing.T) {
	a := []Interface{{Name: "eth", Up: true, Prefixes: []string{"2001:db8::1/64", "192.0.2.1/24"}}, {Name: "wifi", Up: true, Prefixes: []string{"198.51.100.2/24"}}}
	b := []Interface{a[1], {Name: "eth", Up: true, Prefixes: []string{"192.0.2.1/24", "2001:db8::1/64"}}}
	if NetworkGeneration(a) != NetworkGeneration(b) {
		t.Fatal("unstable fingerprint")
	}
	b[1].Prefixes = []string{"192.0.2.5/24"}
	if NetworkGeneration(a) == NetworkGeneration(b) {
		t.Fatal("changed address was not detected")
	}
}
