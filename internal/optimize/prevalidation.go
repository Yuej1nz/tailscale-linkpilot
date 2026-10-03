package optimize

import (
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"net/netip"
	"time"

	"github.com/Yuej1nz/tailscale-linkpilot/internal/mapping"
)

type sourceProbeConfigure struct {
	ID     string              `json:"session_id"`
	Config mapping.ProbeConfig `json:"config"`
}
type sourceProbeRun struct {
	ID      string `json:"session_id"`
	ProbeID string `json:"probe_id"`
	Phase   string `json:"phase"`
}

const (
	probePrime   = "prime"
	probeSearch  = "search"
	probeConfirm = "confirm"
)

type sourceProbeReply struct {
	State       mapping.State `json:"session"`
	Phase       string        `json:"phase"`
	CompletedAt time.Time     `json:"completed_at"`
}

type sourceProbeSelect struct {
	ID     string         `json:"session_id"`
	Target netip.AddrPort `json:"target"`
}

func (a *Assistant) configureSourceProbe(w http.ResponseWriter, r *http.Request) {
	var req sourceProbeConfigure
	if !decode(w, r, &req) {
		return
	}
	if !a.sourceProbeMu.TryLock() {
		http.Error(w, "another prevalidation phase is active", http.StatusConflict)
		return
	}
	defer a.sourceProbeMu.Unlock()
	s, _, err := a.ownedSource(r.Context(), req.ID)
	if err == nil {
		err = s.ConfigureProbe(r.Context(), req.Config)
	}
	if err != nil {
		http.Error(w, err.Error(), 409)
		return
	}
	state, _ := s.State(r.Context())
	writeJSON(w, state)
}

// Both sides use the same bounded schedule independently of native capture.
// A slow coordinator cannot increase the packet count or the probe lifetime.
func runProbeBursts(ctx context.Context, s mapping.ProbeSession, targets []netip.AddrPort, count int) error {
	if len(targets) < 1 || len(targets) > 6 || count < 1 || count > 7 {
		return errors.New("invalid prevalidation candidate count")
	}
	for i := 0; i < count; i++ {
		if err := s.Probe(ctx, targets); err != nil {
			return err
		}
		if err := sleep(ctx, 650*time.Millisecond); err != nil {
			return err
		}
	}
	return nil
}

func (a *Assistant) runSourceProbe(w http.ResponseWriter, r *http.Request) {
	var req sourceProbeRun
	if !decode(w, r, &req) {
		return
	}
	if !a.sourceProbeMu.TryLock() {
		http.Error(w, "another prevalidation phase is active", http.StatusConflict)
		return
	}
	defer a.sourceProbeMu.Unlock()
	s, in, err := a.ownedSource(r.Context(), req.ID)
	if err == nil {
		state, _ := s.State(r.Context())
		p := state.Prevalidation
		if p == nil || p.ID != req.ProbeID || state.Activated || state.Committed {
			err = errors.New("prevalidation phase identity or state mismatch")
		} else {
			switch req.Phase {
			case probePrime:
				if p.Bursts != 0 || p.Selected.IsValid() || state.OutboundPhysical.IsValid() {
					err = errors.New("prime requires an unstarted prevalidation session")
				} else {
					// Acknowledge the successful socket write, without waiting for
					// receipt or a pacing interval; the first packet may be lost.
					err = s.Probe(r.Context(), in.Peers)
				}
			case probeSearch:
				if p.Bursts != 1 || p.Selected.IsValid() || state.OutboundPhysical.IsValid() {
					err = errors.New("search requires exactly one completed prime burst")
				} else {
					err = runProbeBursts(r.Context(), s, in.Peers, 6)
				}
			case probeConfirm:
				if p.Bursts != 7 || !p.Selected.IsValid() || !state.OutboundPhysical.IsValid() {
					err = errors.New("confirm requires seven bursts and a selected route")
				} else {
					err = runProbeBursts(r.Context(), s, []netip.AddrPort{state.OutboundPhysical}, 1)
				}
			default:
				err = errors.New("unknown prevalidation phase")
			}
		}
	}
	if err != nil {
		http.Error(w, err.Error(), 409)
		return
	}
	state, _ := s.State(r.Context())
	writeJSON(w, sourceProbeReply{State: state, Phase: req.Phase, CompletedAt: time.Now().UTC()})
}

func (a *Assistant) selectSourceProbe(w http.ResponseWriter, r *http.Request) {
	var req sourceProbeSelect
	if !decode(w, r, &req) {
		return
	}
	if !a.sourceProbeMu.TryLock() {
		http.Error(w, "another prevalidation phase is active", http.StatusConflict)
		return
	}
	defer a.sourceProbeMu.Unlock()
	s, _, err := a.ownedSource(r.Context(), req.ID)
	if err == nil {
		state, _ := s.State(r.Context())
		if state.Prevalidation == nil || state.Prevalidation.Bursts != 7 {
			err = errors.New("route selection requires seven completed search bursts")
		} else {
			err = s.SelectProbe(r.Context(), req.Target)
		}
	}
	if err != nil {
		http.Error(w, err.Error(), 409)
		return
	}
	state, _ := s.State(r.Context())
	writeJSON(w, state)
}

func provenTarget(s mapping.State, id string, now time.Time) (netip.AddrPort, error) {
	if s.Prevalidation == nil || s.Prevalidation.ID != id {
		return netip.AddrPort{}, errors.New("same-socket prevalidation state mismatch")
	}
	// Choose a fresh observed roundtrip, retaining separate send and reply APs.
	// The target was actually probed; the reply source need not be a sendable alias.
	var chosen *mapping.ProbeResult
	for i := range s.Prevalidation.Results {
		r := &s.Prevalidation.Results[i]
		if !r.Target.IsValid() || !r.ReplyFrom.IsValid() || now.Sub(r.At) > 10*time.Second || r.At.After(now.Add(2*time.Second)) {
			continue
		}
		if chosen == nil || r.At.After(chosen.At) {
			chosen = r
		}
	}
	if chosen == nil {
		return netip.AddrPort{}, errors.New("no authenticated UDP roundtrip on the owned socket")
	}
	return chosen.Target, nil
}

func (p *pairedSession) prevalidate(ctx context.Context) error {
	if !p.client.orderedPrevalidation {
		return errors.New("assistant lacks ordered same-socket prevalidation")
	}
	s, ok := p.Session.(mapping.ProbeSession)
	if !ok {
		return errors.New("local carrier lacks same-socket prevalidation")
	}
	ctx, cancel := context.WithTimeout(ctx, 16*time.Second)
	defer cancel()
	p.prevalidationOrder = &PrevalidationOrder{PrimeDirection: "assistant_to_client"}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return errors.New("prevalidation randomness unavailable")
	}
	cfg := mapping.ProbeConfig{ID: randomHex(16), Key: secret, LifetimeSeconds: 20, Role: "initiator"}
	if err := s.ConfigureProbe(ctx, cfg); err != nil {
		return err
	}
	var remote mapping.State
	remoteConfig := cfg
	remoteConfig.Role = "responder"
	if err := p.client.call(ctx, "/v1/session/probe/configure", sourceProbeConfigure{ID: p.remote.State.SessionID, Config: remoteConfig}, &remote); err != nil {
		return err
	}
	if err := validateProbeState(remote, p.remote.State, cfg.ID, 0); err != nil {
		return err
	}
	var phaseReply sourceProbeReply
	if err := p.client.call(ctx, "/v1/session/probe/run", sourceProbeRun{ID: p.remote.State.SessionID, ProbeID: cfg.ID, Phase: probePrime}, &phaseReply); err != nil {
		return err
	}
	ackAt := time.Now()
	if err := validateProbeReply(phaseReply, p.remote.State, cfg.ID, probePrime, 1); err != nil {
		return err
	}
	p.remote.State = phaseReply.State
	p.prevalidationOrder.RemotePrimeSentAt = phaseReply.CompletedAt
	p.prevalidationOrder.LocalPrimeACKAt = ackAt.UTC()
	// The remote socket has submitted a peer-directed datagram. Its first
	// packet need not have arrived here; ACK proves ordering, not reachability.
	if err := s.Probe(ctx, p.endpoints); err != nil {
		return err
	}
	firstAt := time.Now()
	p.prevalidationOrder.LocalFirstRequestAt = firstAt.UTC()
	p.prevalidationOrder.LocalFirstRequestAfterACKMS = float64(firstAt.Sub(ackAt)) / float64(time.Millisecond)
	// Preserve the existing inter-burst cadence after the local first burst.
	if err := sleep(ctx, 650*time.Millisecond); err != nil {
		return err
	}
	remoteDone := make(chan error, 1)
	go func() {
		remoteDone <- p.client.call(ctx, "/v1/session/probe/run", sourceProbeRun{ID: p.remote.State.SessionID, ProbeID: cfg.ID, Phase: probeSearch}, &phaseReply)
	}()
	localErr := runProbeBursts(ctx, s, p.endpoints, 6)
	remoteErr := <-remoteDone
	if localErr != nil {
		return localErr
	}
	if remoteErr != nil {
		return remoteErr
	}
	if err := validateProbeReply(phaseReply, p.remote.State, cfg.ID, probeSearch, 7); err != nil {
		return err
	}
	remote = phaseReply.State
	p.remote.State = remote
	local, err := p.Session.State(ctx)
	if err != nil {
		return err
	}
	localTarget, err := provenTarget(local, cfg.ID, time.Now())
	if err != nil {
		return err
	}
	remoteTarget, err := provenTarget(remote, cfg.ID, time.Now())
	if err != nil {
		return err
	}
	if err := p.client.call(ctx, "/v1/session/probe/select", sourceProbeSelect{ID: p.remote.State.SessionID, Target: remoteTarget}, &remote); err != nil {
		return err
	}
	if err := validateProbeState(remote, p.remote.State, cfg.ID, 7); err != nil {
		return err
	}
	if err := s.SelectProbe(ctx, localTarget); err != nil {
		return err
	}
	p.remote.State = remote
	// Independent roundtrips can be incompatible under destination-dependent
	// mappings. Spend the last burst on the selected send/receive pair itself.
	localBefore := latestProbeReply(local, localTarget)
	remoteBefore := latestProbeReply(remote, remoteTarget)
	go func() {
		remoteDone <- p.client.call(ctx, "/v1/session/probe/run", sourceProbeRun{ID: p.remote.State.SessionID, ProbeID: cfg.ID, Phase: probeConfirm}, &phaseReply)
	}()
	localErr = runProbeBursts(ctx, s, []netip.AddrPort{localTarget}, 1)
	remoteErr = <-remoteDone
	if localErr != nil {
		return localErr
	}
	if remoteErr != nil {
		return remoteErr
	}
	if err := validateProbeReply(phaseReply, p.remote.State, cfg.ID, probeConfirm, 8); err != nil {
		return err
	}
	remote = phaseReply.State
	p.remote.State = remote
	local, err = p.Session.State(ctx)
	if err != nil {
		return err
	}
	if !latestProbeReply(local, localTarget).After(localBefore) || !latestProbeReply(remote, remoteTarget).After(remoteBefore) {
		return errors.New("independent UDP roundtrips passed but selected route pair did not confirm")
	}
	p.selectedSend = localTarget
	return nil
}

func validateProbeState(got, expected mapping.State, probeID string, bursts int) error {
	if got.SessionID != expected.SessionID || got.SelfID != expected.SelfID || got.PeerID != expected.PeerID || got.Generation != expected.Generation || got.Local != expected.Local || got.Stopped || got.Activated || got.Committed || got.Prevalidation == nil || got.Prevalidation.ID != probeID || got.Prevalidation.Bursts != bursts || bursts > 0 && got.Prevalidation.SentRequests == 0 {
		return errors.New("prevalidation acknowledgement identity, session or burst mismatch")
	}
	return nil
}

func validateProbeReply(got sourceProbeReply, expected mapping.State, probeID, phase string, bursts int) error {
	if got.Phase != phase || got.CompletedAt.IsZero() {
		return errors.New("prevalidation acknowledgement phase or timestamp mismatch")
	}
	return validateProbeState(got.State, expected, probeID, bursts)
}

func latestProbeReply(s mapping.State, target netip.AddrPort) time.Time {
	var at time.Time
	if s.Prevalidation != nil {
		for _, r := range s.Prevalidation.Results {
			if r.Target == target && r.At.After(at) {
				at = r.At
			}
		}
	}
	return at
}
