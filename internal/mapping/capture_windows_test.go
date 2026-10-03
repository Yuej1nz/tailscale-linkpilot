package mapping

import (
	"context"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"
)

func TestWindowsRawCaptureSelectedOutbound(t *testing.T) {
	target := os.Getenv("TS_DIRECT_CAPTURE_TEST_TARGET")
	if target == "" {
		t.Skip("explicit live UDP target required")
	}
	remote, err := netip.ParseAddrPort(target)
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(remote))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	in := Input{Native: c.LocalAddr().(*net.UDPAddr).AddrPort(), Peers: []netip.AddrPort{remote}, SelfDisco: [32]byte{1}}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	packets := make(chan Injection, 4)
	stop, err := (NativeCapture{}).Start(ctx, in, func(p Injection) {
		select {
		case packets <- p:
		default:
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	// A different key must not be exposed to the selected session.
	c.Write(discoFixture([32]byte{2}))
	c.Write(discoFixture(in.SelfDisco))
	select {
	case p := <-packets:
		if p.Direction != "out" || p.Peer != remote {
			t.Fatal(p)
		}
	case <-ctx.Done():
		t.Fatal("outgoing discovery packet not captured")
	}
	select {
	case <-packets:
		t.Fatal("foreign key packet captured")
	case <-time.After(100 * time.Millisecond):
	}
}
