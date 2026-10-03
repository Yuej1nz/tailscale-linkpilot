package optimize

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/Yuej1nz/tailscale-linkpilot/internal/mapping"
)

type pairedSession struct {
	mapping.Session
	client               *rpc
	remote               sourceReply
	endpoints            []netip.AddrPort
	candidates           []CoordinatedCandidate
	selectedSend         netip.AddrPort
	prevalidationOrder   *PrevalidationOrder
	localBootstrap       *nativeBootstrap
	remoteBootstrap      *NativeBootstrapState
	remoteBootstrapError string
}

func (p *pairedSession) remoteState(ctx context.Context) (mapping.State, error) {
	var s mapping.State
	err := p.client.call(ctx, "/v1/session/state", sourceControl{ID: p.remote.State.SessionID}, &s)
	return s, err
}
func (p *pairedSession) Stop(ctx context.Context) error {
	if p.localBootstrap != nil {
		_ = p.localBootstrap.cancelAndWait(ctx)
	}
	var ack map[string]bool
	remoteCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	_ = p.client.call(remoteCtx, "/v1/session/stop", sourceControl{ID: p.remote.State.SessionID}, &ack)
	cancel()
	p.client.setSource("")
	return p.Session.Stop(ctx)
}

func (p *pairedSession) armNativeBootstrap(ctx context.Context, a Backend, in mapping.Input) error {
	if !p.client.autonomousNativeBootstrap || p.remote.State.Prevalidation == nil || !p.selectedSend.IsValid() {
		return errors.New("assistant lacks autonomous native bootstrap or UDP confirmation is missing")
	}
	var reply sourceBootstrapReply
	req := sourceBootstrapControl{ID: p.remote.State.SessionID, ProbeID: p.remote.State.Prevalidation.ID}
	if err := p.client.call(ctx, "/v1/session/bootstrap/arm", req, &reply); err != nil {
		return err
	}
	lifetime := reply.Bootstrap.ExpiresAt.Sub(reply.Bootstrap.ArmedAt)
	if !bootstrapSocketMatches(reply.State, p.remote.State) || !reply.State.ExpiresAt.Equal(p.remote.State.ExpiresAt) || reply.Bootstrap.SessionID != req.ID || reply.Bootstrap.State != "armed" || reply.Bootstrap.ArmedAt.IsZero() || lifetime <= 0 || lifetime > 30*time.Second || reply.State.Activated || reply.State.Committed || reply.State.Prevalidation == nil || reply.State.Prevalidation.ID != req.ProbeID || reply.State.Prevalidation.Bursts != 8 {
		return errors.New("remote native bootstrap readiness acknowledgement mismatch")
	}
	p.remoteBootstrap = &reply.Bootstrap
	b, err := startNativeBootstrap(ctx, a, p.Session, in)
	if err != nil {
		return err
	}
	p.localBootstrap = b
	return nil
}

func (p *pairedSession) finishNativeBootstrap(ctx context.Context) {
	if p.localBootstrap != nil {
		_ = p.localBootstrap.cancelAndWait(ctx)
	}
	if p.remoteBootstrap != nil {
		var reply sourceBootstrapReply
		req := sourceBootstrapControl{ID: p.remote.State.SessionID, ProbeID: p.remote.State.Prevalidation.ID}
		remoteCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		err := p.client.call(remoteCtx, "/v1/session/bootstrap/cancel", req, &reply)
		cancel()
		if err == nil && reply.Bootstrap.SessionID == req.ID {
			p.remoteBootstrap = &reply.Bootstrap
		} else if err != nil {
			p.remoteBootstrapError = "final native bootstrap state unavailable: " + err.Error()
		} else {
			p.remoteBootstrapError = "final native bootstrap session mismatch"
		}
	}
}

func (p *pairedSession) recordNativeBootstrap(x *SourceTrial) {
	if p.localBootstrap != nil {
		s := p.localBootstrap.snapshot()
		x.NativeBootstrap = &s
	}
	x.RemoteNativeBootstrap = p.remoteBootstrap
	x.RemoteNativeBootstrapError = p.remoteBootstrapError
}
func (p *pairedSession) Commit(ctx context.Context) error {
	var remote mapping.State
	if err := p.client.call(ctx, "/v1/session/commit", sourceControl{ID: p.remote.State.SessionID}, &remote); err != nil {
		return err
	}
	if !remote.Committed || !remote.Activated || remote.SessionID != p.remote.State.SessionID || remote.Counters.DataOut == 0 || remote.Counters.DataIn == 0 {
		return errors.New("remote source session did not carry encrypted data")
	}
	p.remote.State = remote
	return p.Session.Commit(ctx)
}
func (p *pairedSession) seed(ctx context.Context, packet []byte) error {
	var ack map[string]bool
	return p.client.call(ctx, "/v1/session/seed", sourceControl{ID: p.remote.State.SessionID, Packet: packet}, &ack)
}

func preparePaired(ctx context.Context, client *rpc, in mapping.Input, s mapping.Session, lease time.Duration) (*pairedSession, error) {
	local, err := s.State(ctx)
	if err != nil {
		return nil, err
	}
	var mapped []netip.AddrPort
	seen := map[netip.AddrPort]bool{}
	for _, o := range local.Mappings {
		if o.SessionID == local.SessionID && time.Since(o.At) < 10*time.Second && !seen[o.Mapped] {
			seen[o.Mapped] = true
			mapped = append(mapped, o.Mapped)
		}
	}
	if len(mapped) == 0 {
		return nil, errors.New("paired session requires a fresh STUN observation")
	}
	var reply sourceReply
	request := sourcePrepare{ReplaceSessionID: client.previousSource, Mapped: mapped, ServerDisco: in.PeerDisco, ClientDisco: in.SelfDisco, LeaseSeconds: int64(lease / time.Second)}
	if err := client.call(ctx, "/v1/session/prepare", request, &reply); err != nil {
		return nil, err
	}
	client.previousSource = ""
	p := &pairedSession{Session: s, client: client, remote: reply}
	if reply.State.SelfID != in.PeerID || reply.State.PeerID != in.SelfID || reply.State.Local.Addr() != reply.Native.Addr() || reply.State.Local.Port() == reply.Native.Port() || !attemptPattern.MatchString(reply.State.SessionID) {
		_ = p.Stop(context.Background())
		return nil, errors.New("remote source ownership or physical IP mismatch")
	}
	owner, ok := s.(interface {
		AddPeer(context.Context, netip.AddrPort) error
		AddObservedPeer(context.Context, mapping.ObservedPeer) error
	})
	if !ok {
		_ = p.Stop(context.Background())
		return nil, errors.New("local session cannot add a coordinated endpoint")
	}
	p.candidates = coordinatedCandidates(in, reply, time.Now())
	for _, candidate := range p.candidates {
		if !candidate.Selected {
			continue
		}
		if candidate.observation != nil {
			err = owner.AddObservedPeer(ctx, *candidate.observation)
		} else {
			err = owner.AddPeer(ctx, candidate.Endpoint)
		}
		if err != nil {
			_ = p.Stop(context.Background())
			return nil, err
		}
		p.endpoints = append(p.endpoints, candidate.Endpoint)
	}
	if len(p.endpoints) == 0 {
		_ = p.Stop(context.Background())
		return nil, errors.New("server source has no fresh observed or known physical endpoint")
	}
	client.setSource(reply.State.SessionID)
	return p, nil
}

// CoordinatedCandidate makes selection and rejection visible in the report.
// Only authenticated fresh observations may extend the native IP allowlist.
type CoordinatedCandidate struct {
	Endpoint    netip.AddrPort `json:"endpoint"`
	Origin      string         `json:"origin"`
	Selected    bool           `json:"selected"`
	Reason      string         `json:"reason,omitempty"`
	observation *mapping.ObservedPeer
}

func coordinatedCandidates(in mapping.Input, reply sourceReply, now time.Time) []CoordinatedCandidate {
	var result []CoordinatedCandidate
	seen := map[netip.AddrPort]bool{}
	selected := 0
	appendCandidate := func(c CoordinatedCandidate) {
		if c.Reason == "" {
			if seen[c.Endpoint] {
				c.Reason = "duplicate"
			} else if selected >= 6 {
				c.Reason = "candidate_limit"
			} else {
				c.Selected = true
				seen[c.Endpoint] = true
				selected++
			}
		}
		result = append(result, c)
	}
	for _, o := range reply.State.Mappings {
		p := mapping.ObservedPeer{PeerID: reply.State.SelfID, SessionID: reply.State.SessionID, Observation: o}
		c := CoordinatedCandidate{Endpoint: o.Mapped, Origin: "authenticated_session_stun", observation: &p}
		if err := mapping.ValidateObservedPeer(p, in.PeerID, now); err != nil {
			c.Reason = err.Error()
		}
		appendCandidate(c)
	}
	// When this socket has a fresh port-preserving STUN observation, try
	// the same port on the other native-published public IPs. This is a bounded
	// hypothesis: a STUN destination does not identify the peer-facing exit.
	portPreserving := false
	for _, c := range result {
		portPreserving = portPreserving || c.Selected && c.Endpoint.Port() == reply.State.Local.Port()
	}
	if portPreserving {
		for _, old := range in.Peers {
			a := old.Addr()
			if a == reply.State.Local.Addr() || !a.Is4() || !a.IsGlobalUnicast() || a.IsPrivate() || netip.MustParsePrefix("100.64.0.0/10").Contains(a) {
				continue
			}
			appendCandidate(CoordinatedCandidate{Endpoint: netip.AddrPortFrom(a, reply.State.Local.Port()), Origin: "known_peer_ip_port_preserving_hypothesis"})
		}
	}
	c := CoordinatedCandidate{Endpoint: reply.State.Local, Origin: "known_physical_ip"}
	known := false
	for _, ap := range in.Peers {
		known = known || ap.Addr() == c.Endpoint.Addr()
	}
	if !known || !c.Endpoint.IsValid() || c.Endpoint.Port() == 0 {
		c.Reason = "unknown_or_invalid_physical_ip"
	}
	appendCandidate(c)
	return result
}
