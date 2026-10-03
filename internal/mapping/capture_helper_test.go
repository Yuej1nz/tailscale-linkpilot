//go:build !windows

package mapping

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestCaptureHelperBoundsAndDiscoveryOnlyFilter(t *testing.T) {
	now := time.Now()
	in := Input{Interface: "en0", Native: netip.MustParseAddrPort("192.168.1.25:41641"), SelfDisco: [32]byte{1}, PeerDisco: [32]byte{2}, Peers: []netip.AddrPort{netip.MustParseAddrPort("203.0.113.8:41641")}}
	req := captureRequest{Input: in, Deadline: now.Add(180 * time.Second)}
	addrs := []netip.Prefix{netip.MustParsePrefix("192.168.1.25/24")}
	filter, err := validateCaptureRequest(req, now, addrs)
	if err != nil {
		t.Fatal(err)
	}
	// Both directions require the disco magic and their exact public key, so
	// unrelated UDP/WireGuard business packets cannot leave the privileged helper.
	if strings.Count(filter, "udp[8:4] = 0x5453f09f") != 2 || !strings.Contains(filter, "0x01000000") || !strings.Contains(filter, "0x02000000") {
		t.Fatal(filter)
	}
	cases := map[string]captureRequest{}
	bad := req
	bad.Deadline = now
	cases["expired"] = bad
	bad = req
	bad.Deadline = now.Add(181 * time.Second)
	cases["unbounded"] = bad
	bad = req
	bad.Input.Interface = "en0 -w /tmp/data"
	cases["interface injection"] = bad
	bad = req
	bad.Input.Native = netip.MustParseAddrPort("192.168.1.26:41641")
	cases["not assigned"] = bad
	bad = req
	bad.Input.Native = netip.MustParseAddrPort("192.168.1.25:0")
	cases["zero port"] = bad
	bad = req
	bad.Input.PeerDisco = [32]byte{}
	cases["wildcard key"] = bad
	bad = req
	bad.Input.Peers = []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:22")}
	cases["loopback"] = bad
	bad = req
	bad.Input.Peers = make([]netip.AddrPort, 13)
	cases["excess peers"] = bad
	for name, r := range cases {
		t.Run(name, func(t *testing.T) {
			if _, e := validateCaptureRequest(r, now, addrs); e == nil {
				t.Fatal("unsafe request accepted")
			}
		})
	}
}
