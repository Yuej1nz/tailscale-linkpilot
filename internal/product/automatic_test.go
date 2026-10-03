package product

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Yuej1nz/tailscale-linkpilot/internal/adapter"
	"github.com/Yuej1nz/tailscale-linkpilot/internal/model"
	"github.com/Yuej1nz/tailscale-linkpilot/internal/optimize"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

type automaticAPI struct {
	self, peer string
	direct     *atomic.Bool
}

func (f *automaticAPI) Status(context.Context) (*ipnstate.Status, error) {
	endpoint := ""
	if f.direct.Load() {
		endpoint = "203.0.113.22:41641"
	}
	return &ipnstate.Status{Version: "fixture", BackendState: "Running",
		Self: &ipnstate.PeerStatus{ID: tailcfg.StableNodeID(f.self), TailscaleIPs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Addrs: []string{"203.0.113.22:41641"}},
		Peer: map[key.NodePublic]*ipnstate.PeerStatus{key.NewNode().Public(): {ID: tailcfg.StableNodeID(f.peer), HostName: f.peer, TailscaleIPs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Active: true, Online: true, LastWrite: time.Now(), Relay: "fixture", CurAddr: endpoint}},
	}, nil
}
func (f *automaticAPI) Ping(context.Context, netip.Addr, tailcfg.PingType) (*ipnstate.PingResult, error) {
	r := &ipnstate.PingResult{IP: "127.0.0.1", NodeIP: "127.0.0.1", LatencySeconds: .001}
	if f.direct.Load() {
		r.Endpoint = "203.0.113.22:41641"
	} else {
		r.DERPRegionID = 1
		r.DERPRegionCode = "fixture"
	}
	return r, nil
}
func (f *automaticAPI) DebugAction(context.Context, string) error { f.direct.Store(true); return nil }
func (f *automaticAPI) WhoIs(context.Context, string) (*apitype.WhoIsResponse, error) {
	return &apitype.WhoIsResponse{Node: &tailcfg.Node{StableID: tailcfg.StableNodeID(f.peer)}}, nil
}
func automaticClient(self, peer string, d *atomic.Bool) *adapter.Client {
	return &adapter.Client{Local: &automaticAPI{self, peer, d}, CLIPath: "fixture", ReadInterfaces: func() ([]model.Interface, error) { return nil, nil }}
}

// Real TCP, authenticated protocol routing and the complete three-payload
// verifier are exercised. The native client's relay/direct observations are
// synthetic; this does not claim to emulate NAT or prove live hole punching.
func TestAutomaticRelayTriggerRunsFullOptimizerWithoutManualRequest(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	direct := &atomic.Bool{}
	client := automaticClient("client", "server", direct)
	server := automaticClient("server", "client", direct)
	hub, err := optimize.NewHub(ctx, server, "fixture", func(id string) bool { return id == "client" })
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:45829")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go hub.Serve(ctx, l)
	s := Store{t.TempDir()}
	if err = s.Update(func(c *Config) error {
		c.SelfID = "client"
		c.Allow("server")
		c.Targets = []Target{{ID: "server", Name: "server", Enabled: true}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	snap, err := client.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	m := manager{store: s, backend: client, selfID: "client", platform: "darwin", discover: func(context.Context, model.Node) (string, optimize.ProductInfo, error) {
		// The Linux fixture verifies the desktop scheduling path. Native transport
		// observations remain synthetic on every OS.
		return "127.0.0.1:45829", optimize.ProductInfo{Authorized: true, PairedResponder: true}, nil
	}, states: map[string]State{}, renewed: map[string]time.Time{}, policies: map[string]*Policy{
		"server": {Generation: snap.NetworkGeneration, RelaySince: time.Now().Add(-21 * time.Second), RelaySamples: 2},
	}}
	defer m.stopJob()
	if err = m.step(ctx, hub); err != nil {
		t.Fatal(err)
	}
	for m.states["server"].Report == "" && ctx.Err() == nil {
		time.Sleep(50 * time.Millisecond)
		if err = m.step(ctx, hub); err != nil {
			t.Fatal(err)
		}
	}
	st := m.states["server"]
	if st.Path != "direct" || (st.Phase != "direct" && st.Phase != "idle") || st.Requested != 0 || st.Report == "" {
		t.Fatal("automatic relay recovery did not finish", st)
	}
	data, err := os.ReadFile(st.Report)
	if err != nil {
		t.Fatal(err)
	}
	var result optimize.Report
	if err = json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if !result.Optimized || !result.DirectVerified || !result.ApplicationVerified || len(result.Verification) != 3 {
		t.Fatal("automatic run skipped verification", result.Outcome)
	}
	if result.Trials[0].Local.Summary.LastProbePath.Type != "derp" {
		t.Fatal("fixture did not start from relay")
	}
	t.Logf("automatic relay -> %s; three business payloads verified", result.Outcome)
}
