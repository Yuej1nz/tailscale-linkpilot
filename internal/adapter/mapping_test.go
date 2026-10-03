package adapter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"strings"
	"testing"

	"github.com/Yuej1nz/tailscale-linkpilot/internal/model"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

type metadataAPI struct {
	*fakeLocal
	value any
	err   error
	calls int
}

func (a *metadataAPI) DebugResultJSON(ctx context.Context, action string) (any, error) {
	if action != "current-netmap" {
		return nil, errors.New("unexpected metadata action")
	}
	if _, ok := ctx.Deadline(); !ok {
		return nil, errors.New("unbounded metadata request")
	}
	a.calls++
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return a.value, a.err
}

func TestDiscoveryMetadataBypassesCrashingCLIAndDoesNotCache(t *testing.T) {
	a := &metadataAPI{fakeLocal: &fakeLocal{}, value: map[string]any{"generation": 1}}
	c := &Client{Local: a, CLIPath: "crashing-macos-app", Runner: func(context.Context, string, []string) ([]byte, error) {
		t.Fatal("launched crashing GUI CLI")
		return nil, nil
	}}
	first, err := c.discoveryMetadata(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	a.value = map[string]any{"generation": 2}
	second, err := c.discoveryMetadata(context.Background())
	if err != nil || string(first) == string(second) || a.calls != 2 {
		t.Fatal("metadata reused across network reads", err)
	}
	a.err = errors.New("local API unavailable")
	if _, err := c.discoveryMetadata(context.Background()); err == nil {
		t.Fatal("silently hid API failure")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.discoveryMetadata(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("ignored cancellation", err)
	}
}

func TestMappingCandidatesFollowNativeNetworkAndAuthenticatedPeer(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fixture exercises macOS route/ipconfig commands; Windows route tested separately")
	}
	selfDisco, peerDisco := key.NewDisco().Public(), key.NewDisco().Public()
	api := &fakeLocal{status: &ipnstate.Status{Version: "fixture", BackendState: "Running", Self: &ipnstate.PeerStatus{ID: "self", Addrs: []string{"192.0.2.55:40123"}, Relay: "home"}}}
	selected := &tailcfg.Node{StableID: "peer", DiscoKey: peerDisco, Endpoints: []netip.AddrPort{netip.MustParseAddrPort("203.0.113.8:50123")}}
	self := &tailcfg.Node{StableID: "self", DiscoKey: selfDisco}
	c := &Client{Local: api, CLIPath: "fixture-cli", ReadInterfaces: func() ([]model.Interface, error) {
		return []model.Interface{{Name: "en7", Up: true, Prefixes: []string{"192.0.2.55/24"}}}, nil
	}}
	c.Runner = func(_ context.Context, path string, args []string) ([]byte, error) {
		switch {
		case path == "fixture-cli" && strings.Join(args, " ") == "debug netmap":
			return json.Marshal(struct {
				SelfNode *tailcfg.Node
				Peers    []*tailcfg.Node
			}{self, []*tailcfg.Node{selected, {StableID: "unrelated", DiscoKey: key.NewDisco().Public(), Endpoints: []netip.AddrPort{netip.MustParseAddrPort("203.0.113.99:50123")}}}})
		case path == "fixture-cli" && strings.Join(args, " ") == "debug derp-map":
			return []byte(`{"Regions":{"1":{"RegionCode":"other","Nodes":[{"IPv4":"198.51.100.1"}]},"2":{"RegionCode":"home","Nodes":[{"IPv4":"198.51.100.2","STUNPort":3479}]}}}`), nil
		case path == "/sbin/route":
			return []byte(" interface: en7\n"), nil
		case path == "/usr/sbin/ipconfig":
			return []byte("192.0.2.55\n"), nil
		default:
			return nil, fmt.Errorf("unexpected mapping command %s %v", path, args)
		}
	}
	first, err := c.MappingInput(context.Background(), "peer", []string{"203.0.113.8:50123", "[2001:db8::1]:41641", "100.90.0.1:41641", "not-an-endpoint"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if first.Interface != "en7" || first.Native.String() != "192.0.2.55:40123" || len(first.Peers) != 1 || first.Peers[0].String() != "203.0.113.8:50123" || first.SelfDisco != selfDisco.Raw32() || first.PeerDisco != peerDisco.Raw32() || first.STUN[0].String() != "198.51.100.2:3479" {
		t.Fatalf("incorrect dynamic discovery: %+v", first)
	}
	selected.Endpoints = []netip.AddrPort{netip.MustParseAddrPort("203.0.113.18:50124")}
	api.status.Self.Addrs = []string{"192.0.2.55:40124"}
	second, err := c.MappingInput(context.Background(), "peer", nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if second.Native == first.Native || second.Peers[0] == first.Peers[0] {
		t.Fatal("reused old port or peer candidate after native metadata changed")
	}
	self.StableID = "another-account"
	if _, err := c.MappingInput(context.Background(), "peer", nil, 2); err == nil {
		t.Fatal("discovery metadata survived an identity switch")
	}
}
