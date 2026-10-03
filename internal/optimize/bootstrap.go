package optimize

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/Yuej1nz/tailscale-linkpilot/internal/diagnostic"
	"github.com/Yuej1nz/tailscale-linkpilot/internal/mapping"
	"github.com/Yuej1nz/tailscale-linkpilot/internal/model"
)

// NativeBootstrapState is discovery evidence, not application acceptance.
type NativeBootstrapState struct {
	SessionID  string    `json:"session_id"`
	State      string    `json:"state"`
	ArmedAt    time.Time `json:"armed_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	FinishedAt time.Time `json:"finished_at,omitempty"`
	Attempts   int       `json:"attempts"`
	Endpoint   string    `json:"endpoint,omitempty"`
	Error      string    `json:"error,omitempty"`
}

type nativeBootstrapLimits struct {
	Lease, ProbeTimeout, Interval, PollInterval time.Duration
	Attempts                                    int
}

var defaultNativeBootstrapLimits = nativeBootstrapLimits{30 * time.Second, 2 * time.Second, 500 * time.Millisecond, 100 * time.Millisecond, 8}

type nativeBootstrap struct {
	mu     sync.Mutex
	state  NativeBootstrapState
	cancel context.CancelFunc
	done   chan struct{}
}

func (b *nativeBootstrap) snapshot() NativeBootstrapState {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.state
}

func (b *nativeBootstrap) cancelAndWait(ctx context.Context) error {
	b.cancel()
	select {
	case <-b.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func startNativeBootstrap(ctx context.Context, a Backend, s mapping.Session, in mapping.Input) (*nativeBootstrap, error) {
	return startNativeBootstrapWithLimits(ctx, a, s, in, defaultNativeBootstrapLimits)
}

func startNativeBootstrapWithLimits(ctx context.Context, a Backend, s mapping.Session, in mapping.Input, limits nativeBootstrapLimits) (*nativeBootstrap, error) {
	if limits.Lease <= 0 || limits.Lease > 30*time.Second || limits.ProbeTimeout <= 0 || limits.ProbeTimeout > 2*time.Second || limits.Interval <= 0 || limits.Interval > 500*time.Millisecond || limits.PollInterval <= 0 || limits.PollInterval > 100*time.Millisecond || limits.Attempts < 1 || limits.Attempts > 8 {
		return nil, errors.New("invalid native bootstrap budget")
	}
	state, err := s.State(ctx)
	if err != nil {
		return nil, err
	}
	if state.SessionID == "" || state.SelfID != in.SelfID || state.PeerID != in.PeerID || state.Generation != in.Generation || state.Stopped || state.Activated || state.Committed || !state.Local.IsValid() || !state.FrozenPhysical || !state.Physical.IsValid() || !state.OutboundPhysical.IsValid() || state.Prevalidation == nil || state.Prevalidation.Bursts != 8 || state.Prevalidation.Selected != state.OutboundPhysical || time.Since(latestProbeReply(state, state.OutboundPhysical)) < 0 || time.Since(latestProbeReply(state, state.OutboundPhysical)) > 10*time.Second {
		return nil, errors.New("native bootstrap requires the confirmed owned UDP session")
	}
	checkCtx, cancelCheck := context.WithTimeout(ctx, 2*time.Second)
	_, _, err = bootstrapIdentity(checkCtx, a, in)
	cancelCheck()
	if err != nil {
		return nil, err
	}
	expires := time.Now().Add(limits.Lease)
	if state.ExpiresAt.Before(expires) {
		expires = state.ExpiresAt
	}
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(expires) {
		expires = deadline
	}
	if !expires.After(time.Now()) {
		return nil, errors.New("native bootstrap lease has expired")
	}
	runCtx, cancel := context.WithDeadline(ctx, expires)
	b := &nativeBootstrap{state: NativeBootstrapState{SessionID: state.SessionID, State: "armed", ArmedAt: time.Now().UTC(), ExpiresAt: expires.UTC()}, cancel: cancel, done: make(chan struct{})}
	go b.run(runCtx, a, s, in, state, limits)
	return b, nil
}

func bootstrapIdentity(ctx context.Context, a Backend, in mapping.Input) (*model.Report, *model.Peer, error) {
	r, err := a.Snapshot(ctx)
	if err != nil {
		return nil, nil, err
	}
	if r == nil || r.BackendState != "Running" || r.Self.ID != in.SelfID || r.NetworkGeneration != in.Generation {
		return nil, nil, errors.New("native bootstrap identity or network changed")
	}
	p, err := diagnostic.ResolvePeer(r, in.PeerID)
	if err == nil && p.ID != in.PeerID {
		return nil, nil, errors.New("native bootstrap peer identity changed")
	}
	return r, p, err
}

func bootstrapSocketMatches(current, expected mapping.State) bool {
	return current.SessionID == expected.SessionID && current.SelfID == expected.SelfID && current.PeerID == expected.PeerID && current.Generation == expected.Generation && current.Local == expected.Local && current.Physical == expected.Physical && current.OutboundPhysical == expected.OutboundPhysical && current.FrozenPhysical && !current.Stopped
}

func bootstrapSessionMatches(current, expected mapping.State) bool {
	return bootstrapSocketMatches(current, expected) && time.Now().Before(current.ExpiresAt)
}

func (b *nativeBootstrap) run(ctx context.Context, a Backend, s mapping.Session, in mapping.Input, expected mapping.State, limits nativeBootstrapLimits) {
	var failure error
	defer func() {
		b.cancel()
		if failure != nil {
			b.mu.Lock()
			b.state.State, b.state.Error, b.state.FinishedAt = "failed", failure.Error(), time.Now().UTC()
			b.mu.Unlock()
			// Stop only this task's still-unactivated socket, never a replacement.
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			current, err := s.State(cleanupCtx)
			if err == nil && current.SessionID == expected.SessionID && !current.Activated && !current.Committed {
				_ = s.Stop(cleanupCtx)
			}
			cancel()
		}
		close(b.done)
	}()
	// Until a peer discovery packet has traversed this socket, do not send a
	// native ping: the arm acknowledgement still needs the original TCP path.
	for {
		current, err := s.State(ctx)
		if err != nil || !bootstrapSessionMatches(current, expected) {
			failure = errors.New("native bootstrap session stopped or changed")
			return
		}
		if current.Counters.PeerIn > 0 {
			break
		}
		if err := sleep(ctx, limits.PollInterval); err != nil {
			failure = err
			return
		}
	}
	for attempt := 0; attempt < limits.Attempts; attempt++ {
		probeCtx, cancel := context.WithTimeout(ctx, limits.ProbeTimeout)
		r, peer, err := bootstrapIdentity(probeCtx, a, in)
		var raw model.PingResult
		if err == nil {
			ip, ipErr := diagnostic.TargetIP(peer)
			err = ipErr
			if err == nil {
				b.mu.Lock()
				b.state.Attempts++
				b.mu.Unlock()
				raw, err = a.Ping(probeCtx, ip, "disco")
				if err == nil && (raw.Err != "" || raw.IP != "" && raw.IP != ip.String() || !hasIP(peer.IPs, raw.NodeIP)) {
					err = errors.New("native bootstrap discovery identity mismatch or failed response")
				}
				if err == nil {
					// Recheck identity after the native roundtrip as well.
					r, peer, err = bootstrapIdentity(probeCtx, a, in)
					if err == nil && (!hasIP(peer.IPs, raw.NodeIP) || !hasIP(peer.IPs, ip.String())) {
						err = errors.New("native bootstrap peer address changed")
					}
				}
			}
		}
		if err == nil && probeCtx.Err() != nil {
			err = probeCtx.Err()
		}
		if err == nil {
			path := model.DiscoveryPath(raw, r.Interfaces, time.Now().UTC())
			b.mu.Lock()
			b.state.Endpoint = path.Endpoint
			b.mu.Unlock()
			current, stateErr := s.State(probeCtx)
			if stateErr != nil || !bootstrapSessionMatches(current, expected) {
				err = errors.New("native bootstrap session changed during discovery")
			} else if path.Type != "direct" || path.Endpoint != current.Local.String() {
				err = errors.New("native discovery has not selected this carrier")
			} else {
				err = s.Activate(probeCtx, current.Physical)
				if err == nil {
					failure = nil
					b.mu.Lock()
					b.state.State, b.state.Endpoint, b.state.FinishedAt = "activated", path.Endpoint, time.Now().UTC()
					b.mu.Unlock()
					cancel()
					return
				}
			}
		}
		cancel()
		failure = err
		if attempt+1 < limits.Attempts {
			if err := sleep(ctx, limits.Interval); err != nil {
				failure = err
				return
			}
		}
	}
}

type sourceBootstrapControl struct {
	ID      string `json:"session_id"`
	ProbeID string `json:"probe_id"`
}

type sourceBootstrapReply struct {
	State     mapping.State        `json:"session"`
	Bootstrap NativeBootstrapState `json:"native_bootstrap"`
}

func (a *Assistant) armSourceBootstrap(w http.ResponseWriter, r *http.Request) {
	var req sourceBootstrapControl
	if !decode(w, r, &req) {
		return
	}
	a.sourceMu.Lock()
	defer a.sourceMu.Unlock()
	if a.source == nil || a.sourceBootstrap != nil {
		http.Error(w, "native bootstrap already armed or source unavailable", http.StatusConflict)
		return
	}
	state, _ := a.source.State(r.Context())
	if state.SessionID != req.ID || state.Prevalidation == nil || state.Prevalidation.ID != req.ProbeID {
		http.Error(w, "native bootstrap session or probe mismatch", http.StatusConflict)
		return
	}
	ctx := a.serveContext
	if ctx == nil {
		ctx = context.Background()
	}
	b, err := startNativeBootstrap(ctx, a.Backend, a.source, a.sourceInput)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	a.sourceBootstrap = b
	writeJSON(w, sourceBootstrapReply{State: state, Bootstrap: b.snapshot()})
}

func (a *Assistant) controlSourceBootstrap(w http.ResponseWriter, r *http.Request) {
	var req sourceBootstrapControl
	if !decode(w, r, &req) {
		return
	}
	a.sourceMu.Lock()
	s, b := a.source, a.sourceBootstrap
	a.sourceMu.Unlock()
	if s == nil || b == nil || b.snapshot().SessionID != req.ID {
		http.Error(w, "native bootstrap session unavailable", http.StatusConflict)
		return
	}
	state, _ := s.State(r.Context())
	if state.Prevalidation == nil || state.Prevalidation.ID != req.ProbeID {
		http.Error(w, "native bootstrap probe mismatch", http.StatusConflict)
		return
	}
	if r.URL.Path == "/v1/session/bootstrap/cancel" {
		if err := b.cancelAndWait(r.Context()); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
	}
	state, _ = s.State(r.Context())
	writeJSON(w, sourceBootstrapReply{State: state, Bootstrap: b.snapshot()})
}
