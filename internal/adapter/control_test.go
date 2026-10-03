package adapter

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"net/netip"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
)

type controlFake struct{ actions []string }

func (f *controlFake) Status(context.Context) (*ipnstate.Status, error) {
	return nil, errors.New("unused")
}
func (f *controlFake) Ping(context.Context, netip.Addr, tailcfg.PingType) (*ipnstate.PingResult, error) {
	return nil, errors.New("unused")
}
func (f *controlFake) DebugAction(_ context.Context, action string) error {
	f.actions = append(f.actions, action)
	return errors.New("access denied")
}

func TestPrivilegedRefreshIsOneFixedOptInCommand(t *testing.T) {
	f := &controlFake{}
	c := &Client{Local: f}
	calls := 0
	c.Runner = func(_ context.Context, path string, args []string) ([]byte, error) {
		calls++
		if path != "/usr/bin/sudo" || !reflect.DeepEqual(args, []string{"-n", "/usr/bin/tailscale", "debug", "restun"}) {
			t.Fatal("privileged arguments changed", path, args)
		}
		return nil, nil
	}
	if c.DebugAction(context.Background(), "restun") == nil || calls != 0 {
		t.Fatal("privilege used without opt-in")
	}
	c.AllowSudoRestun = true
	if c.DebugAction(context.Background(), "restun") != nil || calls != 1 {
		t.Fatal("fixed refresh was not used")
	}
	if c.DebugAction(context.Background(), "rebind") == nil || calls != 1 {
		t.Fatal("privileged rebind was allowed")
	}
	before := len(f.actions)
	if c.DebugAction(context.Background(), "arbitrary") == nil || len(f.actions) != before || calls != 1 {
		t.Fatal("unlisted action was allowed")
	}
}
