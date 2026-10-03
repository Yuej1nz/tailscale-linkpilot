package mapping

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"tailscale.com/net/stun"
)

// These loopback fixtures verify packet handling and same-socket ownership,
// not a NAT success rate or a real native-client integration.
func udpFixture(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func ap(c *net.UDPConn) netip.AddrPort { return c.LocalAddr().(*net.UDPAddr).AddrPort() }

func discoFixture(public [32]byte) []byte {
	b := make([]byte, 6+32+24+16)
	copy(b, discoMagic)
	copy(b[6:38], public[:])
	return b
}

func receive(t *testing.T, c *net.UDPConn) ([]byte, netip.AddrPort) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 65535)
	n, from, err := c.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatal(err)
	}
	return buf[:n], from
}

func TestFreshPortsDoNotRepeatClosedTrials(t *testing.T) {
	var tried []uint16
	for i := 0; i < 12; i++ {
		c, err := freshSocket(netip.MustParseAddr("127.0.0.1"), 41641, tried)
		if err != nil {
			t.Fatal(err)
		}
		port := ap(c).Port()
		for _, previous := range tried {
			if port == previous {
				t.Fatal("reused a released failed port", port)
			}
		}
		tried = append(tried, port)
		c.Close()
	}
}

func TestSameSocketCarriesDiscoveryAndDataOnlyForSelectedPeer(t *testing.T) {
	native, peer, rogue, conn := udpFixture(t), udpFixture(t), udpFixture(t), udpFixture(t)
	in := Input{SelfID: "self", PeerID: "peer", Native: ap(native), SelfDisco: [32]byte{1}, PeerDisco: [32]byte{2}, Peers: []netip.AddrPort{ap(peer)}}
	c := newSocketCarrier(conn, in, "session")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.read(ctx)
	if err := c.inject(Injection{Direction: "out", Peer: ap(rogue), Packet: discoFixture(in.SelfDisco)}); err == nil {
		t.Fatal("copied ciphertext to an unrelated endpoint")
	}
	if err := c.inject(Injection{Direction: "out", Peer: ap(peer), Packet: discoFixture(in.PeerDisco)}); err == nil {
		t.Fatal("accepted the wrong native sender")
	}
	if err := c.inject(Injection{Direction: "out", Peer: ap(peer), Packet: discoFixture(in.SelfDisco)}); err != nil {
		t.Fatal(err)
	}
	packet, wireSource := receive(t, peer)
	if wireSource != ap(conn) || !bytes.Equal(packet, discoFixture(in.SelfDisco)) {
		t.Fatal("bootstrap changed socket or ciphertext")
	}
	peer.WriteToUDPAddrPort(discoFixture(in.PeerDisco), wireSource)
	packet, source := receive(t, native)
	if source != ap(conn) || !bytes.Equal(packet, discoFixture(in.PeerDisco)) {
		t.Fatal("native discovery did not see the carrier endpoint")
	}
	if err := c.activate(ap(peer)); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 1400)
	binary.LittleEndian.PutUint32(data, 4)
	native.WriteToUDPAddrPort(data, ap(conn))
	packet, dataSource := receive(t, peer)
	if dataSource != wireSource || !bytes.Equal(packet, data) {
		t.Fatal("application data changed the primed socket")
	}
	peer.WriteToUDPAddrPort(packet, dataSource)
	packet, source = receive(t, native)
	if source != ap(conn) || !bytes.Equal(packet, data) {
		t.Fatal("return ciphertext was modified")
	}
	// A third socket with the same IP has no permission to inject data or
	// redirect the selected physical endpoint.
	rogue.WriteToUDPAddrPort(discoFixture(in.PeerDisco), ap(conn))
	rogue.WriteToUDPAddrPort(data, ap(conn))
	deadline := time.Now().Add(time.Second)
	for c.snapshot().Counters.Dropped < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	s := c.snapshot()
	if s.Physical != ap(peer) || s.Counters.DataIn != 1400 || s.Counters.DataOut != 1400 || s.Counters.Dropped < 2 {
		t.Fatalf("incorrect transport evidence: %+v", s)
	}
}

func TestSTUNChecksObserverTransactionAndRetainsDestinationProvenance(t *testing.T) {
	observer, rogue, conn := udpFixture(t), udpFixture(t), udpFixture(t)
	c := newSocketCarrier(conn, Input{STUN: []netip.AddrPort{ap(observer)}}, "observed-session")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go c.read(ctx)
	result := make(chan error, 1)
	go func() { result <- c.restun(ctx) }()
	request, source := receive(t, observer)
	id, err := stun.ParseBindingRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	falseMapping := netip.MustParseAddrPort("203.0.113.100:40000")
	trueMapping := netip.MustParseAddrPort("203.0.113.101:40001")
	rogue.WriteToUDPAddrPort(stun.Response(id, falseMapping), source)
	observer.WriteToUDPAddrPort(stun.Response(stun.NewTxID(), falseMapping), source)
	observer.WriteToUDPAddrPort(stun.Response(id, falseMapping)[:22], source)
	observer.WriteToUDPAddrPort(stun.Response(id, trueMapping), source)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	s := c.snapshot()
	if source != s.Local || len(s.Mappings) != 1 || s.Mappings[0].Mapped != trueMapping || s.Mappings[0].Server != ap(observer) || s.Mappings[0].SessionID != "observed-session" {
		t.Fatalf("untrusted or unattributed mapping: %+v", s)
	}
}

func TestBootstrapIsBounded(t *testing.T) {
	peer, conn := udpFixture(t), udpFixture(t)
	in := Input{SelfDisco: [32]byte{1}, Peers: []netip.AddrPort{ap(peer)}}
	c := newSocketCarrier(conn, in, "bounded")
	request := Injection{Direction: "out", Peer: ap(peer), Packet: discoFixture(in.SelfDisco)}
	for i := 0; i < 10; i++ {
		if err := c.inject(request); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.inject(request); err == nil {
		t.Fatal("unbounded packet copying")
	}
}

func TestObservedPeerExtendsCandidatesWithoutActivatingData(t *testing.T) {
	conn := udpFixture(t)
	c := newSocketCarrier(conn, Input{PeerID: "server", Peers: []netip.AddrPort{netip.MustParseAddrPort("203.0.113.10:41641")}}, "local")
	id := "0123456789abcdef0123456789abcdef"
	p := ObservedPeer{PeerID: "server", SessionID: id, Observation: Observation{SessionID: id, At: time.Now(), Server: netip.MustParseAddrPort("198.51.100.20:3478"), Mapped: netip.MustParseAddrPort("198.51.100.30:40519")}}
	if c.addPeer(p.Observation.Mapped) == nil {
		t.Fatal("legacy operation extended unknown IP")
	}
	for name, change := range map[string]func(*ObservedPeer){
		"wrong_node":      func(p *ObservedPeer) { p.PeerID = "other" },
		"wrong_session":   func(p *ObservedPeer) { p.Observation.SessionID = "other" },
		"invalid_session": func(p *ObservedPeer) { p.SessionID = "wrong" },
		"stale":           func(p *ObservedPeer) { p.Observation.At = time.Now().Add(-11 * time.Second) },
		"future":          func(p *ObservedPeer) { p.Observation.At = time.Now().Add(3 * time.Second) },
		"private":         func(p *ObservedPeer) { p.Observation.Mapped = netip.MustParseAddrPort("192.168.1.2:1234") },
		"loopback":        func(p *ObservedPeer) { p.Observation.Mapped = netip.MustParseAddrPort("127.0.0.1:1234") },
		"tailnet":         func(p *ObservedPeer) { p.Observation.Mapped = netip.MustParseAddrPort("100.64.1.2:1234") },
		"observer":        func(p *ObservedPeer) { p.Observation.Server = netip.MustParseAddrPort("127.0.0.1:3478") },
	} {
		t.Run(name, func(t *testing.T) {
			bad := p
			change(&bad)
			if c.addObservedPeer(bad) == nil {
				t.Fatal("accepted invalid observation")
			}
		})
	}
	if err := c.addObservedPeer(p); err != nil {
		t.Fatal(err)
	}
	if !c.allowed(p.Observation.Mapped) || c.snapshot().Activated || c.snapshot().Committed {
		t.Fatal("candidate was lost or activated forwarding")
	}
	for i := 0; i < 5; i++ {
		q := p
		q.Observation.Mapped = netip.AddrPortFrom(p.Observation.Mapped.Addr(), uint16(41000+i))
		if err := c.addObservedPeer(q); err != nil {
			t.Fatal(err)
		}
	}
	q := p
	q.Observation.Mapped = netip.AddrPortFrom(p.Observation.Mapped.Addr(), 42000)
	if c.addObservedPeer(q) == nil {
		t.Fatal("exceeded bounded candidate budget")
	}
	if err := c.addObservedPeer(p); err != nil {
		t.Fatal("duplicate consumes budget", err)
	}
}
