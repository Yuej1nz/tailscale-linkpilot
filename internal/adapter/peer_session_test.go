package adapter

import (
	"context"
	"net/netip"
	"runtime"
	"testing"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

type whoSessionFixture struct {
	*fakeLocal
	node *tailcfg.Node
}

func (f *whoSessionFixture) WhoIs(context.Context, string) (*apitype.WhoIsResponse, error) {
	return &apitype.WhoIsResponse{Node: f.node}, nil
}
func TestPeerSessionRejectsUnadvertisedIPsAndWrongDiscoKey(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux assistant boundary")
	}
	peer := key.NewDisco().Public()
	api := &whoSessionFixture{fakeLocal: &fakeLocal{}, node: &tailcfg.Node{StableID: "selected", DiscoKey: peer, Endpoints: []netip.AddrPort{netip.MustParseAddrPort("203.0.113.10:41641")}}}
	c := &Client{Local: api}
	for _, mapped := range []string{"203.0.113.11:45678", "127.0.0.1:45678", "100.98.1.2:45678", "0.0.0.0:0"} {
		if _, err := c.PeerSessionInput(context.Background(), "100.98.1.1:12345", "selected", []netip.AddrPort{netip.MustParseAddrPort(mapped)}, [32]byte{1}, peer.Raw32()); err == nil {
			t.Fatal("authorized node could prime an unadvertised IP", mapped)
		}
	}
	if _, err := c.PeerSessionInput(context.Background(), "100.98.1.1:12345", "selected", []netip.AddrPort{netip.MustParseAddrPort("203.0.113.10:45678")}, [32]byte{1}, [32]byte{2}); err == nil {
		t.Fatal("native peer discovery key was ignored")
	}
}
