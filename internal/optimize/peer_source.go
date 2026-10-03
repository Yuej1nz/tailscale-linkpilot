package optimize

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"time"

	"github.com/Yuej1nz/tailscale-linkpilot/internal/mapping"
	"github.com/Yuej1nz/tailscale-linkpilot/internal/model"
)

type peerSessionBackend interface {
	PeerSessionInput(context.Context, string, string, []netip.AddrPort, [32]byte, [32]byte) (mapping.Input, error)
}
type sourcePrepare struct {
	ReplaceSessionID string           `json:"replace_session_id,omitempty"`
	Mapped           []netip.AddrPort `json:"mapped_endpoints"`
	ServerDisco      [32]byte         `json:"server_disco_public"`
	ClientDisco      [32]byte         `json:"client_disco_public"`
	LeaseSeconds     int64            `json:"lease_seconds"`
}
type sourceReply struct {
	State     mapping.State  `json:"session"`
	Native    netip.AddrPort `json:"native_endpoint"`
	STUNError string         `json:"stun_error,omitempty"`
}
type sourceControl struct {
	ID     string `json:"session_id"`
	Packet []byte `json:"encrypted_discovery,omitempty"`
}

func (a *Assistant) stopSource() {
	a.sourceMu.Lock()
	defer a.sourceMu.Unlock()
	if a.sourceBootstrap != nil {
		a.sourceBootstrap.cancel()
	}
	if a.source != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		_ = a.source.Stop(ctx)
	}
}
func (a *Assistant) prepareSource(w http.ResponseWriter, r *http.Request) {
	var req sourcePrepare
	if !decode(w, r, &req) {
		return
	}
	if len(req.Mapped) == 0 || len(req.Mapped) > 6 || req.LeaseSeconds < 60 || req.LeaseSeconds > 86400 {
		http.Error(w, "invalid source session limits", 400)
		return
	}
	backend, ok := a.Backend.(peerSessionBackend)
	if !ok {
		http.Error(w, "paired sessions unsupported", 501)
		return
	}
	a.sourceMu.Lock()
	defer a.sourceMu.Unlock()
	if a.source != nil {
		state, _ := a.source.State(r.Context())
		if !state.Stopped && (req.ReplaceSessionID == "" || req.ReplaceSessionID != state.SessionID) {
			http.Error(w, "a source session is already active; replacement requires its current authenticated ID", 409)
			return
		}
	}
	in, err := backend.PeerSessionInput(r.Context(), r.RemoteAddr, a.Peer.ID, req.Mapped, req.ServerDisco, req.ClientDisco)
	if err != nil {
		http.Error(w, err.Error(), 409)
		return
	}
	if in.SelfID != a.Self.ID || in.PeerID != a.Peer.ID {
		http.Error(w, "source identity mismatch", 409)
		return
	}
	// Only after authenticating the new native metadata, retire the exact
	// old session named in this owner's hello snapshot. A concurrent replacement
	// changes its ID and is rejected above rather than stopped accidentally.
	if a.sourceBootstrap != nil {
		a.sourceBootstrap.cancel()
		a.sourceBootstrap = nil
	}
	if a.source != nil {
		if err := a.source.Stop(r.Context()); err != nil {
			http.Error(w, "previous source cleanup failed", 409)
			return
		}
	}
	ctx := a.serveContext
	if ctx == nil {
		ctx = context.Background()
	}
	check := func(ctx context.Context, in mapping.Input) error {
		snap, err := a.Backend.Snapshot(ctx)
		if err != nil {
			return err
		}
		if snap.Self.ID != in.SelfID || snap.BackendState != "Running" || snap.NetworkGeneration != in.Generation {
			return errors.New("server identity or network changed")
		}
		addresses, err := a.Backend.NativeEndpoints(ctx)
		if err != nil {
			return err
		}
		for _, v := range addresses {
			if v == in.Native.String() {
				return nil
			}
		}
		return errors.New("native server socket changed")
	}
	s, err := mapping.NewEmbedded(ctx, in, a.sourcePorts, 120*time.Second, time.Duration(req.LeaseSeconds)*time.Second, check)
	if err != nil {
		http.Error(w, err.Error(), 409)
		return
	}
	state, _ := s.State(r.Context())
	a.sourcePorts = append(a.sourcePorts, state.Local.Port())
	if len(a.sourcePorts) > 64 {
		a.sourcePorts = a.sourcePorts[len(a.sourcePorts)-64:]
	}
	a.source = s
	a.sourceInput = in
	stunCtx, done := context.WithTimeout(r.Context(), 1500*time.Millisecond)
	stunError := ""
	if len(in.STUN) == 0 {
		stunError = "native server STUN map unavailable"
	} else if err := s.STUN(stunCtx); err != nil {
		stunError = err.Error()
	}
	done()
	state, _ = s.State(r.Context())
	writeJSON(w, sourceReply{State: state, Native: in.Native, STUNError: stunError})
}
func (a *Assistant) ownedSource(ctx context.Context, id string) (*mapping.Embedded, mapping.Input, error) {
	a.sourceMu.Lock()
	defer a.sourceMu.Unlock()
	if !attemptPattern.MatchString(id) || a.source == nil {
		return nil, mapping.Input{}, errors.New("source session is not owned by this request")
	}
	state, _ := a.source.State(ctx)
	if state.SessionID != id || state.Stopped || time.Now().After(state.ExpiresAt) {
		return nil, mapping.Input{}, errors.New("source session is not active")
	}
	return a.source, a.sourceInput, nil
}
func (a *Assistant) seedSource(w http.ResponseWriter, r *http.Request) {
	var req sourceControl
	if !decode(w, r, &req) {
		return
	}
	s, in, err := a.ownedSource(r.Context(), req.ID)
	if err == nil && (len(req.Packet) < 78 || len(req.Packet) > 2048) {
		err = errors.New("invalid discovery size")
	}
	if err == nil {
		targets := in.Peers
		state, _ := s.State(r.Context())
		if state.OutboundPhysical.IsValid() {
			targets = []netip.AddrPort{state.OutboundPhysical}
		}
		for _, ap := range targets {
			err = s.Inject(r.Context(), mapping.Injection{Direction: "out", Peer: ap, Packet: req.Packet})
			if err != nil {
				break
			}
		}
	}
	if err != nil {
		http.Error(w, err.Error(), 409)
		return
	}
	writeJSON(w, map[string]bool{"sent": true})
}
func (a *Assistant) stateSource(w http.ResponseWriter, r *http.Request) {
	var req sourceControl
	if !decode(w, r, &req) {
		return
	}
	s, _, err := a.ownedSource(r.Context(), req.ID)
	if err != nil {
		http.Error(w, err.Error(), 409)
		return
	}
	state, _ := s.State(r.Context())
	writeJSON(w, state)
}
func (a *Assistant) activateSource(ctx context.Context, id string, report *model.Report) (mapping.State, error) {
	s, in, err := a.ownedSource(ctx, id)
	if err != nil {
		return mapping.State{}, err
	}
	state, _ := s.State(ctx)
	path := lastPath(report)
	if report != nil && report.Self.ID == in.SelfID && report.Target != nil && report.Target.ID == in.PeerID && report.NetworkGeneration == in.Generation && path != nil && path.Type == "direct" && path.Endpoint == state.Local.String() {
		if err = s.Activate(ctx, state.Physical); err != nil {
			return state, err
		}
	}
	state, _ = s.State(ctx)
	return state, nil
}
func (a *Assistant) commitSource(w http.ResponseWriter, r *http.Request) {
	var req sourceControl
	if !decode(w, r, &req) {
		return
	}
	s, _, err := a.ownedSource(r.Context(), req.ID)
	if err == nil {
		err = s.Commit(r.Context())
	}
	if err != nil {
		http.Error(w, err.Error(), 409)
		return
	}
	state, _ := s.State(r.Context())
	writeJSON(w, state)
}
func (a *Assistant) endSource(w http.ResponseWriter, r *http.Request) {
	var req sourceControl
	if !decode(w, r, &req) {
		return
	}
	s, _, err := a.ownedSource(r.Context(), req.ID)
	if err != nil {
		http.Error(w, err.Error(), 409)
		return
	}
	a.sourceMu.Lock()
	if a.sourceBootstrap != nil && a.sourceBootstrap.snapshot().SessionID == req.ID {
		a.sourceBootstrap.cancel()
	}
	a.sourceMu.Unlock()
	// Preserve this response's encrypted path until the acknowledgement drains.
	writeJSON(w, map[string]bool{"stop_requested": true})
	go func() {
		time.Sleep(200 * time.Millisecond)
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		_ = s.Stop(ctx)
	}()
}

func (a *Assistant) renewSource(w http.ResponseWriter, r *http.Request) {
	var req sourceControl
	if !decode(w, r, &req) {
		return
	}
	s, _, err := a.ownedSource(r.Context(), req.ID)
	if err == nil {
		err = s.Renew(r.Context())
	}
	if err != nil {
		http.Error(w, err.Error(), 409)
		return
	}
	state, _ := s.State(r.Context())
	writeJSON(w, state)
}
