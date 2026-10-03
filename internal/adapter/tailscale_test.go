package adapter

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/Yuej1nz/tailscale-linkpilot/internal/model"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

type fakeLocal struct {
	status *ipnstate.Status
	err    error
	pings  int
}

func (f *fakeLocal) Status(context.Context) (*ipnstate.Status, error) { return f.status, f.err }
func (f *fakeLocal) Ping(context.Context, netip.Addr, tailcfg.PingType) (*ipnstate.PingResult, error) {
	f.pings++
	return nil, errors.New("unexpected active probe")
}

func TestPassiveStatusIsUnverifiedAndHomeDERPDoesNotOverrideDirect(t *testing.T) {
	public := key.NewNode().Public()
	api := &fakeLocal{status: &ipnstate.Status{Version: "1.102.4", BackendState: "Running", Self: &ipnstate.PeerStatus{ID: "test-self"}, Peer: map[key.NodePublic]*ipnstate.PeerStatus{public: {ID: "test-peer", HostName: "example-peer", Active: true, Online: true, LastWrite: time.Now(), CurAddr: "203.0.113.9:41641", Relay: "example-home"}}}}
	c := &Client{Local: api, ReadInterfaces: func() ([]model.Interface, error) { return nil, nil }}
	r, err := c.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if api.pings != 0 {
		t.Fatal("passive command initiated a probe")
	}
	p := r.Peers[0].Path
	if p.Type != "unknown" || p.ReportedType != "direct" || p.Verification != "status_only" {
		t.Fatalf("overclaimed status: %+v", p)
	}
}

func TestCLIFallbackOnlyRunsStatus(t *testing.T) {
	api := &fakeLocal{err: errors.New("LocalAPI unavailable")}
	calls := 0
	c := &Client{Local: api, CLIPath: "fake-tailscale", Socket: "fake.sock", ReadInterfaces: func() ([]model.Interface, error) { return nil, nil }, Runner: func(_ context.Context, _ string, args []string) ([]byte, error) {
		calls++
		if len(args) != 4 || args[0] != "--socket" || args[2] != "status" || args[3] != "--json" {
			t.Fatalf("unexpected command: %v", args)
		}
		return []byte(`{"Version":"1.102.4","BackendState":"Stopped"}`), nil
	}}
	r, err := c.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || r.Client.Transport != "cli_status" || api.pings != 0 {
		t.Fatalf("fallback=%+v calls=%d", r.Client, calls)
	}
}
