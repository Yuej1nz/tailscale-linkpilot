package mapping

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

// This exercises two real UDP carriers. Native crypto authentication and NAT
// are deliberately outside this loopback packet-forwarding fixture.
func TestPairedSocketsCarryTheSameCiphertextAndClose(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	nativeA, nativeB := udpFixture(t), udpFixture(t)
	a, err := NewEmbedded(ctx, Input{SelfID: "a", PeerID: "b", Native: ap(nativeA), SelfDisco: [32]byte{1}, PeerDisco: [32]byte{2}, Peers: []netip.AddrPort{ap(nativeB)}}, nil, time.Minute, time.Minute, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Stop(context.Background())
	stateA, _ := a.State(ctx)
	b, err := NewEmbedded(ctx, Input{SelfID: "b", PeerID: "a", Native: ap(nativeB), SelfDisco: [32]byte{2}, PeerDisco: [32]byte{1}, Peers: []netip.AddrPort{stateA.Local}}, nil, time.Minute, time.Minute, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Stop(context.Background())
	stateB, _ := b.State(ctx)
	if err := a.c.addPeer(stateB.Local); err != nil {
		t.Fatal(err)
	}
	if err := a.Inject(ctx, Injection{Direction: "out", Peer: stateB.Local, Packet: discoFixture([32]byte{1})}); err != nil {
		t.Fatal(err)
	}
	packet, from := receive(t, nativeB)
	if from != stateB.Local || !bytes.Equal(packet, discoFixture([32]byte{1})) {
		t.Fatal("peer native client did not receive discovery from its own new socket")
	}
	nativeB.WriteToUDPAddrPort(discoFixture([32]byte{2}), stateB.Local)
	packet, from = receive(t, nativeA)
	if from != stateA.Local || !bytes.Equal(packet, discoFixture([32]byte{2})) {
		t.Fatal("return discovery lost socket ownership")
	}
	if err := a.Commit(ctx); err == nil {
		t.Fatal("discovery alone committed a data path")
	}
	if err := a.Activate(ctx, stateB.Local); err != nil {
		t.Fatal(err)
	}
	if err := b.Activate(ctx, stateA.Local); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 1400)
	binary.LittleEndian.PutUint32(data, 4)
	nativeA.WriteToUDPAddrPort(data, stateA.Local)
	packet, from = receive(t, nativeB)
	if from != stateB.Local || !bytes.Equal(packet, data) {
		t.Fatal("outbound data changed")
	}
	nativeB.WriteToUDPAddrPort(packet, stateB.Local)
	packet, from = receive(t, nativeA)
	if from != stateA.Local || !bytes.Equal(packet, data) {
		t.Fatal("return data changed")
	}
	for _, s := range []*Embedded{a, b} {
		state, _ := s.State(ctx)
		if state.Counters.DataIn != 1400 || state.Counters.DataOut != 1400 {
			t.Fatal("missing bilateral encrypted bytes", state)
		}
		if err := s.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		committed, _ := s.State(ctx)
		if err := s.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		repeated, _ := s.State(ctx)
		if !repeated.ExpiresAt.Equal(committed.ExpiresAt) {
			t.Fatal("repeated commits silently extended a one-sided lease")
		}
		if err := s.Stop(ctx); err != nil {
			t.Fatal(err)
		}
		state, _ = s.State(ctx)
		if !state.Stopped {
			t.Fatal("socket retained after stop")
		}
	}
}

func TestEmbeddedPreparationLeaseCannotRetainAnUnverifiedSocket(t *testing.T) {
	ctx := context.Background()
	native := udpFixture(t)
	s, err := NewEmbedded(ctx, Input{Native: ap(native)}, nil, time.Millisecond, time.Minute, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Stop(ctx)
	select {
	case <-s.done:
	case <-time.After(3 * time.Second):
		t.Fatal("uncommitted server socket outlived its preparation lease")
	}
	state, _ := s.State(ctx)
	if !state.Stopped || state.StopReason != "lease_expired" {
		t.Fatal(state)
	}
}

func TestCarrierRenewalRequiresLiveCommittedEncryptedSession(t *testing.T) {
	native, peer := udpFixture(t), udpFixture(t)
	s, err := NewEmbedded(context.Background(), Input{Native: ap(native), Peers: []netip.AddrPort{ap(peer)}}, nil, time.Minute, time.Minute, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Stop(context.Background())
	if err = s.Renew(context.Background()); err == nil {
		t.Fatal("uncommitted carrier renewed")
	}
	s.c.mu.Lock()
	s.c.state.Committed = true
	s.c.state.Activated = true
	s.c.state.Counters.DataIn = 1
	s.c.state.Counters.DataOut = 1
	before := time.Now().Add(5 * time.Second)
	s.c.state.ExpiresAt = before
	s.c.mu.Unlock()
	if err = s.Renew(context.Background()); err != nil {
		t.Fatal(err)
	}
	state, _ := s.State(context.Background())
	if !state.ExpiresAt.After(before) {
		t.Fatal("lease not extended")
	}
	s.c.mu.Lock()
	s.c.state.ExpiresAt = time.Now().Add(-time.Second)
	s.c.mu.Unlock()
	if err = s.Renew(context.Background()); err == nil {
		t.Fatal("expired carrier revived")
	}
}
