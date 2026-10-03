package mapping

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"time"
)

// Every request and response has exactly the same small size. Kind is covered
// by the MAC, so a request cannot be reflected back as a successful response.
const probePacketSize = 8 + 1 + 1 + 16 + 16 + sha256.Size

var probeMagic = []byte("TSDPROB1")

type probePending struct {
	target netip.AddrPort
	at     time.Time
}

type probeControl struct {
	id        [16]byte
	key       [32]byte
	role      byte
	pending   map[[16]byte]probePending
	received  map[[16]byte]bool
	targets   map[netip.AddrPort]bool
	replyTick time.Time
	replies   int
}

func (c *socketCarrier) configureProbe(config ProbeConfig) error {
	id, err := hex.DecodeString(config.ID)
	if err != nil || len(id) != 16 || hex.EncodeToString(id) != config.ID || len(config.Key) != 32 || config.LifetimeSeconds < 1 || config.LifetimeSeconds > 20 || config.Role != "initiator" && config.Role != "responder" {
		return errors.New("invalid prevalidation configuration")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.probe != nil || c.state.Activated || c.state.Committed || c.state.Stopped {
		return errors.New("prevalidation requires a fresh unconfigured session")
	}
	p := &probeControl{pending: make(map[[16]byte]probePending), received: make(map[[16]byte]bool), targets: make(map[netip.AddrPort]bool)}
	copy(p.id[:], id)
	copy(p.key[:], config.Key)
	p.role = 1
	if config.Role == "responder" {
		p.role = 2
	}
	c.probe = p
	expires := time.Now().Add(time.Duration(config.LifetimeSeconds) * time.Second).UTC()
	if !c.state.ExpiresAt.IsZero() && c.state.ExpiresAt.Before(expires) {
		expires = c.state.ExpiresAt
	}
	c.state.Prevalidation = &ProbeState{ID: config.ID, ExpiresAt: expires, Results: []ProbeResult{}}
	return nil
}

func (p *probeControl) packet(kind byte, nonce [16]byte) []byte {
	packet := make([]byte, probePacketSize)
	copy(packet, probeMagic)
	packet[8] = kind
	packet[9] = p.role
	copy(packet[10:26], p.id[:])
	copy(packet[26:42], nonce[:])
	mac := hmac.New(sha256.New, p.key[:])
	_, _ = mac.Write(packet[:42])
	copy(packet[42:], mac.Sum(nil))
	return packet
}

func (c *socketCarrier) sendProbe(ctx context.Context, endpoints []netip.AddrPort) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if len(endpoints) == 0 || len(endpoints) > 6 {
		return errors.New("prevalidation requires one to six selected endpoints")
	}
	for _, endpoint := range endpoints {
		if !endpoint.IsValid() || !endpoint.Addr().Is4() || endpoint.Port() == 0 || !c.allowed(endpoint) || !c.probeSourceAllowed(endpoint) {
			return errors.New("prevalidation endpoint is outside selected peers")
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	state, p := c.state.Prevalidation, c.probe
	if p == nil || c.state.Activated || c.state.Committed || c.state.Stopped || !time.Now().Before(state.ExpiresAt) {
		return errors.New("prevalidation is not available")
	}
	if state.Bursts >= 8 {
		return errors.New("prevalidation burst limit reached")
	}
	unique := make(map[netip.AddrPort]bool)
	for _, endpoint := range endpoints {
		if state.Selected.IsValid() && endpoint != state.Selected {
			return errors.New("prevalidation route is already selected")
		}
		unique[endpoint] = true
	}
	newTargets := 0
	for endpoint := range unique {
		if !p.targets[endpoint] {
			newTargets++
		}
	}
	if len(p.targets)+newTargets > 6 {
		return errors.New("prevalidation target limit reached")
	}
	// Reserve the bounded burst before writing; a partial send must not allow
	// callers to reset the budget by provoking errors.
	state.Bursts++
	for endpoint := range unique {
		p.targets[endpoint] = true
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return errors.New("prevalidation nonce generation failed")
		}
		p.pending[nonce] = probePending{target: endpoint, at: time.Now()}
		if ctx.Err() != nil {
			delete(p.pending, nonce)
			return ctx.Err()
		}
		if _, err := c.conn.WriteToUDPAddrPort(p.packet(1, nonce), endpoint); err != nil {
			delete(p.pending, nonce)
			return err
		}
		state.SentRequests++
	}
	return nil
}

func (c *socketCarrier) probeSourceAllowed(endpoint netip.AddrPort) bool {
	a := endpoint.Addr()
	if !a.Is4() || endpoint.Port() == 0 || endpoint == c.input.Native {
		return false
	}
	if a.IsGlobalUnicast() && !a.IsPrivate() && !netip.MustParsePrefix("100.64.0.0/10").Contains(a) {
		return true
	}
	// Local network and loopback traffic is accepted only for explicit peer
	// endpoints. This supports local fixtures without opening a UDP reflector.
	return (a.IsLoopback() || a.IsPrivate()) && c.allowed(endpoint)
}

// handleProbe consumes recognizable protocol packets even when invalid, so
// they can never become discovery or encrypted business evidence.
func (c *socketCarrier) handleProbe(from netip.AddrPort, packet []byte) bool {
	if len(packet) < len(probeMagic) || !bytes.Equal(packet[:len(probeMagic)], probeMagic) {
		return false
	}
	sourceAllowed := c.probeSourceAllowed(from)
	c.mu.Lock()
	defer c.mu.Unlock()
	p, state := c.probe, c.state.Prevalidation
	if p == nil {
		return true
	}
	now := time.Now()
	if !sourceAllowed || len(packet) != probePacketSize || !now.Before(state.ExpiresAt) || c.state.Stopped || !bytes.Equal(packet[10:26], p.id[:]) || (packet[8] != 1 && packet[8] != 2) || packet[9] != 3-p.role || state.Selected.IsValid() && from != c.state.Physical {
		state.Dropped++
		return true
	}
	mac := hmac.New(sha256.New, p.key[:])
	_, _ = mac.Write(packet[:42])
	if !hmac.Equal(packet[42:], mac.Sum(nil)) {
		state.Dropped++
		return true
	}
	var nonce [16]byte
	copy(nonce[:], packet[26:42])
	if packet[8] == 1 {
		if now.Sub(p.replyTick) >= time.Second {
			p.replyTick, p.replies = now, 0
		}
		if p.received[nonce] || len(p.received) >= 48 || p.replies >= 12 {
			state.Dropped++
			return true
		}
		p.received[nonce] = true
		p.replies++
		state.RequestsReceived++
		to := from
		if state.Selected.IsValid() {
			to = c.state.OutboundPhysical
		}
		if _, err := c.conn.WriteToUDPAddrPort(p.packet(2, nonce), to); err != nil {
			state.Dropped++
		} else {
			state.RepliesSent++
		}
		return true
	}
	pending, found := p.pending[nonce]
	if !found || now.Sub(pending.at) > 10*time.Second {
		state.Dropped++
		return true
	}
	delete(p.pending, nonce)
	state.RepliesReceived++
	state.Results = append(state.Results, ProbeResult{Target: pending.target, ReplyFrom: from, At: now.UTC(), RTTMS: float64(now.Sub(pending.at)) / float64(time.Millisecond)})
	return true
}

func (c *socketCarrier) selectProbe(endpoint netip.AddrPort) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	p := c.state.Prevalidation
	now := time.Now()
	if p == nil || c.state.Activated || c.state.Committed || c.state.Stopped || !now.Before(p.ExpiresAt) {
		return errors.New("prevalidation route selection is not available")
	}
	if p.Selected.IsValid() {
		return errors.New("prevalidated route is already selected")
	}
	for i := len(p.Results) - 1; i >= 0; i-- {
		result := p.Results[i]
		if endpoint == result.Target && now.Sub(result.At) >= 0 && now.Sub(result.At) <= 10*time.Second {
			p.Selected = endpoint
			c.state.OutboundPhysical = result.Target
			c.state.Physical = result.ReplyFrom
			c.state.FrozenPhysical = true
			clear(c.probe.pending)
			return nil
		}
	}
	return errors.New("endpoint has no fresh authenticated UDP roundtrip")
}
