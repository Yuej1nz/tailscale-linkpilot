package mapping

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"tailscale.com/net/stun"
)

var discoMagic = []byte("TS💬")

func discoFrom(packet []byte, public [32]byte) bool {
	return len(packet) >= 6+32+24+16 && len(packet) <= 2048 && bytes.Equal(packet[:6], discoMagic) && bytes.Equal(packet[6:38], public[:])
}

func wireGuard(packet []byte) (valid, data bool) {
	if len(packet) < 4 {
		return false, false
	}
	switch binary.LittleEndian.Uint32(packet[:4]) {
	case 1:
		return len(packet) == 148, false
	case 2:
		return len(packet) == 92, false
	case 3:
		return len(packet) == 64, false
	case 4:
		return len(packet) >= 32, true
	}
	return false, false
}

type pendingSTUN struct {
	server netip.AddrPort
	done   chan Observation
}

type socketCarrier struct {
	conn       *net.UDPConn
	input      Input
	mu         sync.Mutex
	state      State
	pending    map[stun.TxID]pendingSTUN
	extraPeers map[netip.AddrPort]bool
	probe      *probeControl
	// Bootstrap copying is limited independently of native encrypted traffic.
	tokens int
	tick   time.Time
}

func newSocketCarrier(conn *net.UDPConn, input Input, id string) *socketCarrier {
	c := &socketCarrier{conn: conn, input: input, pending: make(map[stun.TxID]pendingSTUN), extraPeers: make(map[netip.AddrPort]bool), tokens: 10, tick: time.Now()}
	c.state = State{SessionID: id, SelfID: input.SelfID, PeerID: input.PeerID, Generation: input.Generation, Local: conn.LocalAddr().(*net.UDPAddr).AddrPort(), Mappings: []Observation{}}
	return c
}

func (c *socketCarrier) snapshot() State {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.state
	s.Mappings = append([]Observation(nil), s.Mappings...)
	if s.Prevalidation != nil {
		p := *s.Prevalidation
		p.Results = append([]ProbeResult(nil), p.Results...)
		s.Prevalidation = &p
	}
	return s
}

func (c *socketCarrier) allowed(ap netip.AddrPort) bool {
	for _, peer := range c.input.Peers {
		if ap == peer {
			return true
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.extraPeers[ap]
}

// Only the owner can add a coordinated source port on an already known IP.
// Packet capture still uses the original exact endpoint list.
func (c *socketCarrier) addPeer(ap netip.AddrPort) error {
	knownIP := false
	for _, peer := range c.input.Peers {
		knownIP = knownIP || peer.Addr() == ap.Addr()
	}
	if !knownIP || !ap.IsValid() || ap.Port() == 0 {
		return errors.New("coordinated endpoint IP is not a known peer")
	}
	return c.storePeer(ap)
}

// ValidateObservedPeer checks the owner-supplied observation before extending
// the endpoint set. Identity authentication is performed by the coordinator RPC;
// accepting this candidate never activates forwarding or commits a session.
func ValidateObservedPeer(p ObservedPeer, peerID string, now time.Time) error {
	id, err := hex.DecodeString(p.SessionID)
	o := p.Observation
	public := func(ap netip.AddrPort) bool {
		a := ap.Addr()
		return ap.Port() != 0 && a.Is4() && a.IsGlobalUnicast() && !a.IsPrivate() && !netip.MustParsePrefix("100.64.0.0/10").Contains(a)
	}
	if peerID == "" || p.PeerID != peerID || err != nil || len(id) != 16 || o.SessionID != p.SessionID || !public(o.Mapped) || !public(o.Server) || now.Sub(o.At) > 10*time.Second || o.At.Sub(now) > 2*time.Second {
		return errors.New("invalid, stale or mismatched coordinated observation")
	}
	return nil
}

func (c *socketCarrier) addObservedPeer(p ObservedPeer) error {
	if err := ValidateObservedPeer(p, c.input.PeerID, time.Now()); err != nil {
		return err
	}
	return c.storePeer(p.Observation.Mapped)
}

func (c *socketCarrier) storePeer(ap netip.AddrPort) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.extraPeers) >= 6 && !c.extraPeers[ap] {
		return errors.New("coordinated endpoint limit reached")
	}
	c.extraPeers[ap] = true
	return nil
}

func (c *socketCarrier) peerDiscovery(ap netip.AddrPort, packet []byte) bool {
	// A public header is a routing hint. The native client must authenticate
	// a fresh roundtrip through this unique socket before data is enabled.
	a := ap.Addr()
	return discoFrom(packet, c.input.PeerDisco) && (c.allowed(ap) || ap.Port() != 0 && a.Is4() && a.IsGlobalUnicast() && !a.IsLoopback() && a != c.input.Native.Addr())
}

func (c *socketCarrier) activate(expected netip.AddrPort) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.state.FrozenPhysical || !expected.IsValid() || expected != c.state.Physical {
		return errors.New("physical route changed or has not answered on the fresh socket")
	}
	c.state.Activated = true
	return nil
}

func (c *socketCarrier) inject(req Injection) error {
	if req.Direction != "out" && req.Direction != "in" || req.Direction == "out" && !c.allowed(req.Peer) || req.Direction == "in" && !c.peerDiscovery(req.Peer, req.Packet) {
		return errors.New("capture endpoint or direction outside selected peer")
	}
	public := c.input.SelfDisco
	target := req.Peer
	if req.Direction == "in" {
		public, target = c.input.PeerDisco, c.input.Native
	}
	if !discoFrom(req.Packet, public) {
		return errors.New("not the selected native discovery sender")
	}
	c.mu.Lock()
	if time.Since(c.tick) >= time.Second {
		c.tokens, c.tick = 10, time.Now()
	}
	if c.tokens == 0 {
		c.state.Counters.Dropped++
		c.mu.Unlock()
		return errors.New("bootstrap rate limit")
	}
	c.tokens--
	if req.Direction == "in" && !c.state.FrozenPhysical {
		c.state.Physical = req.Peer
	}
	c.mu.Unlock()
	if _, err := c.conn.WriteToUDPAddrPort(req.Packet, target); err != nil {
		return err
	}
	c.mu.Lock()
	if req.Direction == "out" {
		c.state.Counters.BootstrapOut++
	} else {
		c.state.Counters.BootstrapIn++
	}
	c.mu.Unlock()
	return nil
}

func (c *socketCarrier) read(ctx context.Context) error {
	buf := make([]byte, 65535)
	for ctx.Err() == nil {
		_ = c.conn.SetReadDeadline(time.Now().Add(time.Second))
		n, from, err := c.conn.ReadFromUDPAddrPort(buf)
		if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
			continue
		}
		if err != nil {
			return err
		}
		packet := buf[:n]
		if c.handleProbe(from, packet) {
			continue
		}
		if stun.Is(packet) {
			id, mapped, parseErr := stun.ParseResponse(packet)
			c.mu.Lock()
			pending, found := c.pending[id]
			if parseErr == nil && found && pending.server == from && mapped.IsValid() && mapped.Port() != 0 {
				o := Observation{Server: from, Mapped: mapped, At: time.Now().UTC(), SessionID: c.state.SessionID}
				if len(c.state.Mappings) >= 64 {
					c.state.Mappings = c.state.Mappings[1:]
				}
				c.state.Mappings = append(c.state.Mappings, o)
				delete(c.pending, id)
				pending.done <- o
			} else {
				c.state.Counters.Dropped++
			}
			c.mu.Unlock()
			continue
		}
		validWG, data := wireGuard(packet)
		peerDiscovery := c.peerDiscovery(from, packet)
		var to netip.AddrPort
		outgoing := false
		c.mu.Lock()
		if from == c.input.Native && (validWG && c.state.Activated || discoFrom(packet, c.input.SelfDisco)) && c.state.Physical.IsValid() {
			to = c.state.Physical
			if c.state.OutboundPhysical.IsValid() {
				to = c.state.OutboundPhysical
			}
			outgoing = true
		} else if peerDiscovery || from == c.state.Physical && validWG && c.state.Activated {
			// A discovery key identifies which native peer should authenticate
			// the ciphertext. Only discovery can choose a physical endpoint;
			// unauthenticated data-shaped UDP cannot redirect the carrier.
			if discoFrom(packet, c.input.PeerDisco) && !c.state.FrozenPhysical {
				c.state.Physical = from
				c.state.FrozenPhysical = true
			}
			if from == c.state.Physical {
				to = c.input.Native
			}
		}
		if !to.IsValid() {
			c.state.Counters.Dropped++
		}
		c.mu.Unlock()
		if to.IsValid() {
			_, err := c.conn.WriteToUDPAddrPort(packet, to)
			c.mu.Lock()
			if err != nil {
				c.state.Counters.Dropped++
			} else if outgoing {
				c.state.Counters.NativeOut++
				if data {
					c.state.Counters.DataOut += uint64(n)
				}
			} else {
				c.state.Counters.PeerIn++
				if data {
					c.state.Counters.DataIn += uint64(n)
				}
			}
			c.mu.Unlock()
		}
	}
	return ctx.Err()
}

func (c *socketCarrier) restun(ctx context.Context) error {
	// This same socket performs STUN, bootstrap, discovery and encrypted data.
	// An observation belongs to its particular STUN destination and session.
	type waiting struct {
		id   stun.TxID
		done chan Observation
	}
	waits := make([]waiting, 0, len(c.input.STUN))
	before := len(c.snapshot().Mappings)
	for _, server := range c.input.STUN {
		id := stun.NewTxID()
		done := make(chan Observation, 1)
		c.mu.Lock()
		c.pending[id] = pendingSTUN{server: server, done: done}
		c.mu.Unlock()
		waits = append(waits, waiting{id, done})
		_, _ = c.conn.WriteToUDPAddrPort(stun.Request(id), server)
	}
	defer func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		for _, w := range waits {
			delete(c.pending, w.id)
		}
	}()
	got := 0
	for _, w := range waits {
		select {
		case <-w.done:
			got++
		case <-ctx.Done():
			if got > 0 || len(c.snapshot().Mappings) > before {
				return nil
			}
			return ctx.Err()
		}
	}
	if got == 0 {
		return errors.New("no STUN response on this session; peer probing may still work")
	}
	return nil
}
