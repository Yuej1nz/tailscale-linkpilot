package optimize

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Yuej1nz/tailscale-linkpilot/internal/mapping"
	"github.com/Yuej1nz/tailscale-linkpilot/internal/model"
)

type mappingBackend interface {
	MappingInput(context.Context, string, []string, int) (mapping.Input, error)
}

func selectedCarrier(t Trial, s mapping.State) bool {
	path := lastPath(t.Local)
	return directBoth(t) && path != nil && path.Endpoint == s.Local.String() && s.Activated && s.FrozenPhysical && s.Physical.IsValid() && s.Counters.NativeOut > 0 && s.Counters.PeerIn > 0
}

func stopSession(s mapping.Session) string {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	if err := s.Stop(ctx); err != nil {
		return "stop_failed: " + err.Error()
	}
	for ctx.Err() == nil {
		if _, err := s.State(ctx); err != nil {
			return "closed_socket_and_controller"
		}
		_ = sleep(ctx, 100*time.Millisecond)
	}
	return "stop_not_confirmed_before_deadline"
}

// searchSource rebuilds candidates on every attempt and rejects every source
// port already used in this run, including ports released after failed trials.
func searchSource(ctx context.Context, a Backend, client *rpc, r *Report, opts Options) mapping.Session {
	backend, ok := a.(mappingBackend)
	if !ok {
		r.SourceTrials = append(r.SourceTrials, SourceTrial{Index: 1, Error: "native mapping discovery unavailable on this backend"})
		return nil
	}
	spawn := opts.SpawnSession
	if spawn == nil {
		spawn = mapping.Spawn
	}
	capture := opts.Capture
	if capture == nil {
		capture = mapping.NativeCapture{}
	}
	tried := make([]uint16, 0, opts.SourceSessions)
	for i := 0; i < opts.SourceSessions && ctx.Err() == nil; i++ {
		remaining := opts.Budget
		if deadline, ok := ctx.Deadline(); ok {
			remaining = time.Until(deadline)
		}
		// Keep time for three actual business checks and the requested hold.
		if remaining < opts.Hold+15*time.Second {
			r.SourceTrials = append(r.SourceTrials, SourceTrial{Index: i + 1, Error: "remaining budget reserved for business verification"})
			break
		}
		x := SourceTrial{Index: i + 1}
		var remoteAddresses []string
		for n := len(r.Trials) - 1; n >= 0; n-- {
			if t := r.Trials[n]; t.Remote != nil && t.Remote.Error == "" {
				remoteAddresses = t.Remote.Endpoints.Addresses
				break
			}
		}
		in, err := backend.MappingInput(ctx, r.Target.ID, remoteAddresses, i)
		if err != nil {
			x.Error = err.Error()
			r.SourceTrials = append(r.SourceTrials, x)
			break
		}
		x.Input = &in
		if in.SelfID != r.Self.ID || in.PeerID != r.Target.ID || in.Generation != r.Trials[0].Local.NetworkGeneration {
			x.Error = "identity or network changed before allocating a source session"
			r.SourceTrials = append(r.SourceTrials, x)
			break
		}
		prepare := remaining
		if prepare > 180*time.Second {
			prepare = 180 * time.Second
		}
		s, err := spawn(ctx, in, tried, prepare, opts.SessionLease)
		if err != nil {
			x.Error = err.Error()
			r.SourceTrials = append(r.SourceTrials, x)
			break
		}
		state, err := s.State(ctx)
		repeated := false
		for _, port := range tried {
			repeated = repeated || port == state.Local.Port()
		}
		if err != nil || repeated || state.SelfID != in.SelfID || state.PeerID != in.PeerID || state.Generation != in.Generation || !state.Local.IsValid() || state.Local.Addr() != in.Native.Addr() || state.Local.Port() == in.Native.Port() {
			x.Error = "source session reused a port or returned mismatched ownership"
			x.Cleanup = stopSession(s)
			r.SourceTrials = append(r.SourceTrials, x)
			break
		}
		tried = append(tried, state.Local.Port())
		r.RuntimeChanges = true
		stunCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		if err := s.STUN(stunCtx); err != nil {
			x.STUNError = err.Error()
		}
		cancel()
		var pair *pairedSession
		if client.paired {
			pair, err = preparePaired(ctx, client, in, s, opts.SessionLease)
			if err != nil {
				x.PairedError = err.Error()
				x.Error = "paired session preparation failed"
				x.Cleanup = stopSession(s)
				r.SourceTrials = append(r.SourceTrials, x)
				continue
			} else {
				s = pair
				remote := pair.remote.State
				x.RemoteState = &remote
				x.CoordinatedCandidates = pair.candidates
			}
		}
		if pair != nil {
			if !client.prevalidation || !client.orderedPrevalidation || !client.autonomousNativeBootstrap {
				err = errors.New("assistant lacks ordered prevalidation or autonomous native bootstrap; update the authorized helper")
			} else {
				err = pair.prevalidate(ctx)
			}
			x.PrevalidationOrder = pair.prevalidationOrder
			localState, stateErr := s.State(ctx)
			if stateErr == nil {
				state = localState
				x.State = &localState
			}
			remoteState, remoteErr := pair.remoteState(ctx)
			if remoteErr == nil {
				x.RemoteState = &remoteState
			}
			if err != nil {
				x.UDPPrevalidation = "failed"
				x.UDPPrevalidationError = err.Error()
				x.Error = "UDP roundtrip not proven; native forwarding was not enabled"
				x.Cleanup = stopSession(s)
				r.SourceTrials = append(r.SourceTrials, x)
				if !client.prevalidation || !client.orderedPrevalidation || !client.autonomousNativeBootstrap {
					break
				}
				continue
			}
			x.UDPPrevalidation = "selected_pair_confirmed"
			// Arm both independent native verifiers while the original control
			// path still works. Neither sends until peer discovery reaches its
			// own confirmed socket after capture begins.
			if err := pair.armNativeBootstrap(ctx, a, in); err != nil {
				x.Error = "native bootstrap readiness failed: " + err.Error()
				x.Cleanup = stopSession(s)
				pair.recordNativeBootstrap(&x)
				r.SourceTrials = append(r.SourceTrials, x)
				continue
			}
		}
		capturedSession := s
		seeder := newDiscoverySeeder(ctx, discoverySeedAge, func(seedCtx context.Context, req mapping.Injection) error {
			if req.Direction == "in" {
				return pair.seed(seedCtx, req.Packet)
			}
			req.Peer = pair.selectedSend
			return capturedSession.Inject(seedCtx, req)
		})
		stopCapture, err := capture.Start(ctx, in, func(req mapping.Injection) {
			if pair != nil {
				seeder.enqueue(req)
				return
			}
			injectCtx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
			defer cancel()
			_ = capturedSession.Inject(injectCtx, req)
		})
		if err != nil {
			seeder.stop()
			if pair != nil {
				finishCtx, done := context.WithTimeout(context.Background(), 4*time.Second)
				pair.finishNativeBootstrap(finishCtx)
				done()
				pair.recordNativeBootstrap(&x)
			}
			x.Error = err.Error()
			x.State = &state
			x.Cleanup = stopSession(s)
			r.SourceTrials = append(r.SourceTrials, x)
			break // A missing capture capability cannot be repaired by more ports.
		}
		chosen := false
		nativeRecovered := false
		for round := 0; round < 2 && ctx.Err() == nil; round++ {
			t := coordinatedWithLocal(ctx, a, client, r.Self, r.Target, fmt.Sprintf("source_session_%d_round_%d", i+1, round+1), 3, true, func(local *model.Report) error {
				path := lastPath(local)
				current, err := s.State(ctx)
				if err != nil {
					return err
				}
				if local.Self.ID == r.Self.ID && local.Target != nil && local.Target.ID == r.Target.ID && local.NetworkGeneration == in.Generation && path != nil && path.Type == "direct" && path.Endpoint == current.Local.String() {
					// The fresh native roundtrip authenticates this frozen route.
					// Activate before the remote HTTP reply, which may use it now.
					return s.Activate(ctx, current.Physical)
				}
				return nil
			})
			r.Trials = append(r.Trials, t)
			if round == 0 && pair != nil {
				if err := seeder.wait(ctx); err != nil {
					x.Error = "aged discovery seed unavailable: " + err.Error()
					break
				}
			}
			currentState, stateErr := s.State(ctx)
			if stateErr != nil {
				err = stateErr
				x.Error = "local source session stopped: " + err.Error()
				break
			}
			state = currentState
			chosen = selectedCarrier(t, state)
			if pair != nil && t.Remote != nil && t.Remote.SourceSession != nil {
				remote := *t.Remote.SourceSession
				x.RemoteState = &remote
			}
			if chosen {
				break
			}
			if directBoth(t) {
				nativeRecovered = true
				break
			}
			if err := sleep(ctx, time.Second); err != nil {
				break
			}
		}
		_ = stopCapture()
		seeder.stop()
		if pair != nil {
			finishCtx, done := context.WithTimeout(context.Background(), 4*time.Second)
			pair.finishNativeBootstrap(finishCtx)
			done()
			pair.recordNativeBootstrap(&x)
		}
		x.State = &state
		if chosen {
			if pair != nil && (x.RemoteState == nil || !x.RemoteState.Activated) {
				// The native server path may have recovered without its carrier.
				var ack map[string]bool
				stopCtx, done := context.WithTimeout(ctx, 3*time.Second)
				_ = client.call(stopCtx, "/v1/session/stop", sourceControl{ID: pair.remote.State.SessionID}, &ack)
				done()
				client.setSource("")
				s = pair.Session
			}
			x.Cleanup = "preparation_lease_pending_business_verification"
			r.SourceTrials = append(r.SourceTrials, x)
			return s
		}
		if x.Error == "" && !nativeRecovered {
			x.Error = "native Tailscale did not select this session bidirectionally"
		}
		x.Cleanup = stopSession(s)
		r.SourceTrials = append(r.SourceTrials, x)
		if nativeRecovered || x.Cleanup != "closed_socket_and_controller" {
			break
		}
		// Native heartbeats must be allowed to abandon the closed candidate.
		// No additional service restart, server rebind or hidden port edit.
		_ = sleep(ctx, 5*time.Second)
	}
	return nil
}

func activeForPeer(ctx context.Context, opts Options, self, peer model.Node, generation string) mapping.Session {
	var s mapping.Session
	var state mapping.State
	var err error
	if opts.ActiveSession != nil {
		s, state, err = opts.ActiveSession(ctx)
	} else {
		s, state, err = mapping.Active(ctx)
	}
	if err != nil || !state.Committed || state.SelfID != self.ID || state.PeerID != peer.ID || state.Generation != generation || state.Stopped || time.Now().After(state.ExpiresAt) {
		return nil
	}
	return s
}

func carrierState(ctx context.Context, s mapping.Session) (mapping.State, error) {
	if s == nil {
		return mapping.State{}, errors.New("no carrier")
	}
	return s.State(ctx)
}
