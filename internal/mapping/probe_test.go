package mapping

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"tailscale.com/net/stun"
)

func probeConfig() ProbeConfig {
	return ProbeConfig{ID: "0123456789abcdef0123456789abcdef", Key: bytes.Repeat([]byte{0xa7}, 32), LifetimeSeconds: 20, Role: "initiator"}
}

func peerProbePacket(c *socketCarrier, kind byte, nonce [16]byte) []byte {
	p := *c.probe
	p.role = 3 - p.role
	return p.packet(kind, nonce)
}

func runCarrier(t *testing.T, c *socketCarrier) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go c.read(ctx)
}

func awaitProbe(t *testing.T, c *socketCarrier, check func(State) bool) State {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		s := c.snapshot()
		if check(s) {
			return s
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("missing expected socket evidence: %+v", c.snapshot())
	return State{}
}

func TestProbeUsesOwnedSocketAndStillRequiresNativeActivation(t *testing.T) {
	nativeA, nativeB, connA, connB, rogue, observer := udpFixture(t), udpFixture(t), udpFixture(t), udpFixture(t), udpFixture(t), udpFixture(t)
	a := newSocketCarrier(connA, Input{Native: ap(nativeA), SelfDisco: [32]byte{1}, PeerDisco: [32]byte{2}, Peers: []netip.AddrPort{ap(connB), ap(rogue)}, STUN: []netip.AddrPort{ap(observer)}}, "a")
	b := newSocketCarrier(connB, Input{Native: ap(nativeB), SelfDisco: [32]byte{2}, PeerDisco: [32]byte{1}, Peers: []netip.AddrPort{ap(connA)}}, "b")
	runCarrier(t, a)
	runCarrier(t, b)
	ctx := context.Background()
	stunDone := make(chan error, 1)
	go func() { stunDone <- a.restun(ctx) }()
	request, stunSource := receive(t, observer)
	tx, err := stun.ParseBindingRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	observer.WriteToUDPAddrPort(stun.Response(tx, ap(connA)), stunSource)
	if err := <-stunDone; err != nil {
		t.Fatal(err)
	}
	for _, c := range []*socketCarrier{a, b} {
		config := probeConfig()
		if c == b {
			config.Role = "responder"
		}
		if err := c.configureProbe(config); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.sendProbe(ctx, []netip.AddrPort{ap(connB)}); err != nil {
		t.Fatal(err)
	}
	if err := b.sendProbe(ctx, []netip.AddrPort{ap(connA)}); err != nil {
		t.Fatal(err)
	}
	for _, c := range []*socketCarrier{a, b} {
		s := awaitProbe(t, c, func(s State) bool { return s.Prevalidation.RepliesReceived == 1 && s.Prevalidation.RepliesSent == 1 })
		if s.Physical.IsValid() || s.Activated || s.Committed || s.Counters != (Counters{}) {
			t.Fatal("probe changed native transport evidence or enabled data", s)
		}
	}
	result := a.snapshot().Prevalidation.Results[0]
	if result.Target != ap(connB) || result.ReplyFrom != ap(connB) || stunSource != ap(connA) {
		t.Fatal("STUN and prevalidation did not retain the owned sockets", result, stunSource)
	}
	if err := a.selectProbe(ap(connB)); err != nil {
		t.Fatal(err)
	}
	if err := b.selectProbe(ap(connA)); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 100)
	binary.LittleEndian.PutUint32(data, 4)
	nativeA.WriteToUDPAddrPort(data, ap(connA))
	connB.WriteToUDPAddrPort(data, ap(connA))
	rogue.WriteToUDPAddrPort(discoFixture([32]byte{2}), ap(connA))
	s := awaitProbe(t, a, func(s State) bool { return s.Counters.Dropped >= 3 })
	if s.Physical != ap(connB) || s.Counters.DataIn != 0 || s.Counters.DataOut != 0 || s.Activated {
		t.Fatal("prevalidation enabled data or allowed discovery to overwrite selection", s)
	}
	if err := a.inject(Injection{Direction: "out", Peer: ap(connB), Packet: discoFixture([32]byte{1})}); err != nil {
		t.Fatal(err)
	}
	packet, from := receive(t, nativeB)
	if from != ap(connB) || !bytes.Equal(packet, discoFixture([32]byte{1})) {
		t.Fatal("native discovery did not use the prevalidated socket")
	}
	nativeB.WriteToUDPAddrPort(discoFixture([32]byte{2}), ap(connB))
	_, from = receive(t, nativeA)
	if from != stunSource {
		t.Fatal("STUN, prevalidation and native discovery changed source socket")
	}
	if err := a.activate(ap(connB)); err != nil {
		t.Fatal(err)
	}
	if err := b.activate(ap(connA)); err != nil {
		t.Fatal(err)
	}
	nativeA.WriteToUDPAddrPort(data, ap(connA))
	packet, from = receive(t, nativeB)
	if from != ap(connB) || !bytes.Equal(packet, data) {
		t.Fatal("encrypted data did not use selected source")
	}
	nativeB.WriteToUDPAddrPort(data, ap(connB))
	packet, from = receive(t, nativeA)
	if from != stunSource || !bytes.Equal(packet, data) {
		t.Fatal("data return changed owned source socket")
	}
	if a.snapshot().Prevalidation.RepliesReceived != 1 || a.selectProbe(ap(connB)) == nil {
		t.Fatal("native data was counted as probe evidence or active selection changed")
	}
}

func TestProbeKeepsOutboundTargetSeparateFromReplyAlias(t *testing.T) {
	native, conn, target, reply := udpFixture(t), udpFixture(t), udpFixture(t), udpFixture(t)
	c := newSocketCarrier(conn, Input{Native: ap(native), SelfDisco: [32]byte{1}, PeerDisco: [32]byte{2}, Peers: []netip.AddrPort{ap(target), ap(reply)}}, "alias")
	runCarrier(t, c)
	if err := c.configureProbe(probeConfig()); err != nil {
		t.Fatal(err)
	}
	if err := c.sendProbe(context.Background(), []netip.AddrPort{ap(target)}); err != nil {
		t.Fatal(err)
	}
	request, from := receive(t, target)
	var nonce [16]byte
	copy(nonce[:], request[26:42])
	response := peerProbePacket(c, 2, nonce)
	reply.WriteToUDPAddrPort(response, from)
	state := awaitProbe(t, c, func(s State) bool { return len(s.Prevalidation.Results) == 1 })
	if state.Prevalidation.Results[0].Target != ap(target) || state.Prevalidation.Results[0].ReplyFrom != ap(reply) {
		t.Fatal("lost multi-exit destination provenance", state)
	}
	if c.selectProbe(ap(reply)) == nil {
		t.Fatal("selected unproven outbound reply alias")
	}
	if err := c.selectProbe(ap(target)); err != nil {
		t.Fatal(err)
	}
	if c.selectProbe(ap(target)) == nil {
		t.Fatal("selection may be repeated after native validation starts")
	}
	native.WriteToUDPAddrPort(discoFixture([32]byte{1}), ap(conn))
	packet, from := receive(t, target)
	if from != ap(conn) || !bytes.Equal(packet, discoFixture([32]byte{1})) {
		t.Fatal("native output did not retain the proven destination")
	}
	state = c.snapshot()
	if state.Physical != ap(reply) || state.OutboundPhysical != ap(target) || state.Activated {
		t.Fatal("aliased selection conflated incoming and outgoing paths", state)
	}
}

func TestProbeSelectedConfirmationUsesBothProvenDirections(t *testing.T) {
	conn, target, reply, rogue := udpFixture(t), udpFixture(t), udpFixture(t), udpFixture(t)
	c := newSocketCarrier(conn, Input{Peers: []netip.AddrPort{ap(target), ap(reply), ap(rogue)}}, "confirmation")
	if err := c.configureProbe(probeConfig()); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := c.sendProbe(ctx, []netip.AddrPort{ap(target)}); err != nil {
		t.Fatal(err)
	}
	request, _ := receive(t, target)
	var initial [16]byte
	copy(initial[:], request[26:42])
	c.handleProbe(ap(reply), peerProbePacket(c, 2, initial))
	if err := c.sendProbe(ctx, []netip.AddrPort{ap(target)}); err != nil {
		t.Fatal(err)
	}
	oldRequest, _ := receive(t, target)
	var oldNonce [16]byte
	copy(oldNonce[:], oldRequest[26:42])
	if err := c.selectProbe(ap(target)); err != nil {
		t.Fatal(err)
	}
	if len(c.probe.pending) != 0 {
		t.Fatal("selection retained pre-selection in-flight proof")
	}
	c.handleProbe(ap(reply), peerProbePacket(c, 2, oldNonce))
	if c.snapshot().Prevalidation.RepliesReceived != 1 {
		t.Fatal("old reply can satisfy selected-pair confirmation")
	}
	if c.sendProbe(ctx, []netip.AddrPort{ap(rogue)}) == nil {
		t.Fatal("selected probe sends to another target")
	}
	if err := c.sendProbe(ctx, []netip.AddrPort{ap(target)}); err != nil {
		t.Fatal(err)
	}
	request, _ = receive(t, target)
	var nonce [16]byte
	copy(nonce[:], request[26:42])
	c.handleProbe(ap(rogue), peerProbePacket(c, 2, nonce))
	if c.snapshot().Prevalidation.RepliesReceived != 1 {
		t.Fatal("confirmation accepted an unselected receive source")
	}
	c.handleProbe(ap(reply), peerProbePacket(c, 2, nonce))
	if c.snapshot().Prevalidation.RepliesReceived != 2 {
		t.Fatal("selected reply did not complete confirmation")
	}
	c.handleProbe(ap(rogue), peerProbePacket(c, 1, [16]byte{88}))
	if c.snapshot().Prevalidation.RepliesSent != 0 {
		t.Fatal("selected state answered an unrelated receive source")
	}
	c.handleProbe(ap(reply), peerProbePacket(c, 1, [16]byte{89}))
	response, from := receive(t, target)
	if from != ap(conn) || response[8] != 2 || !bytes.Equal(response[26:42], append([]byte{89}, make([]byte, 15)...)) {
		t.Fatal("selected response did not retain the proven outbound target")
	}
	state := c.snapshot()
	if state.Activated || state.Committed || state.Counters != (Counters{}) {
		t.Fatal("confirmation activated data or contaminated native evidence")
	}
}

func TestProbeRejectsWrongSecretAndTwoStepReflection(t *testing.T) {
	conn, peer := udpFixture(t), udpFixture(t)
	c := newSocketCarrier(conn, Input{Peers: []netip.AddrPort{ap(peer)}}, "reflection")
	if err := c.configureProbe(probeConfig()); err != nil {
		t.Fatal(err)
	}
	if err := c.sendProbe(context.Background(), []netip.AddrPort{ap(peer)}); err != nil {
		t.Fatal(err)
	}
	request, _ := receive(t, peer)
	var nonce [16]byte
	copy(nonce[:], request[26:42])
	// Reflecting a request to its sender must not elicit a valid response that
	// can subsequently be reflected to satisfy that sender's pending nonce.
	c.handleProbe(ap(peer), request)
	c.handleProbe(ap(peer), c.probe.packet(2, nonce))
	forged := *c.probe
	forged.role = 3 - forged.role
	forged.key[0] ^= 1
	c.handleProbe(ap(peer), forged.packet(1, [16]byte{1}))
	c.handleProbe(ap(peer), forged.packet(2, nonce))
	state := c.snapshot().Prevalidation
	if state.RepliesSent != 0 || state.RepliesReceived != 0 || len(state.Results) != 0 {
		t.Fatal("reflection or wrong secret manufactured roundtrip proof")
	}
	c.handleProbe(ap(peer), peerProbePacket(c, 2, nonce))
	c.handleProbe(ap(peer), peerProbePacket(c, 2, nonce))
	if c.snapshot().Prevalidation.RepliesReceived != 1 {
		t.Fatal("response replay was counted twice")
	}
}

func TestProbeAuthenticationReplayExpiryAndReflectionBounds(t *testing.T) {
	conn, peer := udpFixture(t), udpFixture(t)
	c := newSocketCarrier(conn, Input{Peers: []netip.AddrPort{ap(peer)}}, "bounds")
	if err := c.configureProbe(probeConfig()); err != nil {
		t.Fatal(err)
	}
	valid := peerProbePacket(c, 1, [16]byte{1})
	bad := append([]byte(nil), valid...)
	bad[len(bad)-1] ^= 1
	c.handleProbe(ap(peer), bad)
	c.handleProbe(ap(peer), valid[:10])
	bad = append([]byte(nil), valid...)
	bad[10] ^= 1
	c.handleProbe(ap(peer), bad)
	if c.snapshot().Prevalidation.RepliesSent != 0 {
		t.Fatal("invalid MAC, ID or length reflected traffic")
	}
	c.handleProbe(ap(peer), valid)
	response, from := receive(t, peer)
	if len(response) != len(valid) || from != ap(conn) || response[8] != 2 {
		t.Fatal("response amplified a request or changed socket")
	}
	c.handleProbe(ap(peer), valid)
	c.handleProbe(ap(peer), response)
	if c.snapshot().Prevalidation.RepliesSent != 1 || c.snapshot().Prevalidation.RepliesReceived != 0 {
		t.Fatal("replay or unsolicited response counted as fresh evidence")
	}
	for i := byte(2); i <= 13; i++ {
		c.handleProbe(ap(peer), peerProbePacket(c, 1, [16]byte{i}))
	}
	if c.snapshot().Prevalidation.RepliesSent != 12 {
		t.Fatal("per-second reflection bound not enforced")
	}
	for i := byte(14); i < 80; i++ {
		c.mu.Lock()
		c.probe.replyTick = time.Now().Add(-time.Second)
		c.mu.Unlock()
		c.handleProbe(ap(peer), peerProbePacket(c, 1, [16]byte{i}))
	}
	if c.snapshot().Prevalidation.RepliesSent != 48 {
		t.Fatal("total reflection bound not enforced")
	}
	c.mu.Lock()
	c.state.Prevalidation.ExpiresAt = time.Now().Add(-time.Millisecond)
	c.mu.Unlock()
	c.handleProbe(ap(peer), peerProbePacket(c, 1, [16]byte{99}))
	if c.snapshot().Prevalidation.RepliesSent != 48 || c.sendProbe(context.Background(), []netip.AddrPort{ap(peer)}) == nil {
		t.Fatal("expired probe can still send")
	}
}

func TestProbeBurstTargetAndFreshnessBounds(t *testing.T) {
	conn := udpFixture(t)
	var peers []netip.AddrPort
	for i := 0; i < 7; i++ {
		peers = append(peers, ap(udpFixture(t)))
	}
	c := newSocketCarrier(conn, Input{Peers: peers}, "bursts")
	if err := c.configureProbe(probeConfig()); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if c.sendProbe(ctx, peers) == nil || c.sendProbe(ctx, []netip.AddrPort{netip.MustParseAddrPort("127.0.0.2:12345")}) == nil {
		t.Fatal("accepted too many or unrelated targets")
	}
	for i := 0; i < 8; i++ {
		if err := c.sendProbe(ctx, peers[:6]); err != nil {
			t.Fatal(err)
		}
		if i == 0 && c.sendProbe(ctx, peers[6:]) == nil {
			t.Fatal("accepted seventh distinct target")
		}
	}
	if c.sendProbe(ctx, peers[:1]) == nil || c.snapshot().Prevalidation.SentRequests != 48 || len(c.probe.pending) != 48 {
		t.Fatal("burst budget not enforced")
	}
	var oldNonce [16]byte
	for nonce, pending := range c.probe.pending {
		oldNonce = nonce
		pending.at = time.Now().Add(-11 * time.Second)
		c.probe.pending[nonce] = pending
		break
	}
	c.handleProbe(peers[0], peerProbePacket(c, 2, oldNonce))
	if c.snapshot().Prevalidation.RepliesReceived != 0 {
		t.Fatal("stale nonce accepted")
	}
	c.state.Prevalidation.Results = []ProbeResult{{Target: peers[0], ReplyFrom: peers[0], At: time.Now().Add(-11 * time.Second)}}
	if c.selectProbe(peers[0]) == nil {
		t.Fatal("selected stale proof")
	}
	c.state.Prevalidation.Results[0].At = time.Now().Add(time.Second)
	if c.selectProbe(peers[0]) == nil {
		t.Fatal("selected future proof")
	}
}

func TestProbeConfigurationIsOneShotAndSecretsNeverEnterState(t *testing.T) {
	c := newSocketCarrier(udpFixture(t), Input{}, "configuration")
	for _, config := range []ProbeConfig{
		{ID: probeConfig().ID, Key: probeConfig().Key, LifetimeSeconds: 0},
		{ID: probeConfig().ID, Key: probeConfig().Key, LifetimeSeconds: 21},
		{ID: "0123456789ABCDEF0123456789ABCDEF", Key: probeConfig().Key, LifetimeSeconds: 20},
		{ID: "invalid", Key: probeConfig().Key, LifetimeSeconds: 20},
		{ID: probeConfig().ID, Key: []byte{1}, LifetimeSeconds: 20},
	} {
		config.Role = "initiator"
		if c.configureProbe(config) == nil {
			t.Fatal("accepted malformed configuration")
		}
	}
	badRole := probeConfig()
	badRole.Role = "both"
	if c.configureProbe(badRole) == nil {
		t.Fatal("accepted undefined probe role")
	}
	config := probeConfig()
	if err := c.configureProbe(config); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(c.snapshot())
	if err != nil || bytes.Contains(encoded, []byte(base64.StdEncoding.EncodeToString(config.Key))) || bytes.Contains(encoded, []byte(`"key"`)) {
		t.Fatal("probe secret leaked into report state", err)
	}
	config.Key[0] = 0
	if c.probe.key[0] != 0xa7 {
		t.Fatal("configuration retained a mutable caller key")
	}
	if c.configureProbe(probeConfig()) == nil {
		t.Fatal("overwrote one-shot probe configuration")
	}
	s := c.snapshot()
	s.Prevalidation.ID = "changed"
	s.Prevalidation.Results = append(s.Prevalidation.Results, ProbeResult{})
	if c.snapshot().Prevalidation.ID != probeConfig().ID || len(c.snapshot().Prevalidation.Results) != 0 {
		t.Fatal("snapshot retained mutable probe state")
	}
	for _, state := range []State{{Activated: true}, {Committed: true}, {Stopped: true}} {
		other := newSocketCarrier(udpFixture(t), Input{}, "not-fresh")
		other.state = state
		if other.configureProbe(probeConfig()) == nil {
			t.Fatal("configured a non-fresh session")
		}
	}
}
