package adapter

import (
	"context"
	"net/netip"
	"testing"
)

func TestWindowsRouteRejectsLoopbackAndCancellation(t *testing.T) {
	c := New("", "")
	if _, _, err := c.physicalRoute(context.Background(), netip.MustParseAddrPort("127.0.0.1:9")); err == nil {
		t.Fatal("loopback selected as physical interface")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := c.physicalRoute(ctx, netip.MustParseAddrPort("192.0.2.1:9")); err == nil {
		t.Fatal("canceled route selection succeeded")
	}
}
