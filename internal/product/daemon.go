package product

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/Yuej1nz/tailscale-linkpilot/internal/adapter"
	"github.com/Yuej1nz/tailscale-linkpilot/internal/diagnostic"
	"github.com/Yuej1nz/tailscale-linkpilot/internal/mapping"
	"github.com/Yuej1nz/tailscale-linkpilot/internal/model"
	"github.com/Yuej1nz/tailscale-linkpilot/internal/optimize"
)

func Daemon(ctx context.Context, s Store) error {
	if runtime.GOOS == "windows" {
		_ = os.Setenv("TSLINK_MANAGED_WORKER", "1")
	}
	unlock, err := fileLock(filepath.Join(s.Dir, "daemon.lock"))
	if err != nil {
		return err
	}
	defer unlock()
	c, err := s.Config()
	if err != nil {
		return err
	}
	backend := adapter.New("", "")
	backend.AllowSudoRestun = c.SudoRestun
	initial, err := backend.Snapshot(ctx)
	if err != nil {
		return err
	}
	if initial.Self.ID != c.SelfID {
		return errors.New("configured identity differs from active Tailscale account")
	}
	hub, err := optimize.NewHub(ctx, backend, Version, func(id string) bool {
		cfg, e := s.Config()
		return e == nil && cfg.SelfID == c.SelfID && cfg.Authorizes(id)
	})
	if err != nil {
		return err
	}
	address, err := Address(initial.Self)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	defer listener.Close()
	serveErr := make(chan error, 1)
	go func() { serveErr <- hub.Serve(ctx, listener) }()
	defer hub.Close()

	heartbeatCtx, stopHeartbeat := context.WithCancel(ctx)
	defer stopHeartbeat()
	_ = s.Pulse(c.SelfID)
	go func() {
		tick := time.NewTicker(5 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-heartbeatCtx.Done():
				return
			case <-tick.C:
				_ = s.Pulse(c.SelfID)
			}
		}
	}()
	m := manager{store: s, backend: backend, policies: map[string]*Policy{}, states: map[string]State{}, renewed: map[string]time.Time{}, selfID: c.SelfID}
	m.activity.settle(initial.NetworkGeneration, initial.Peers)

	if previous, e := s.Status(); e == nil && previous.SelfID == c.SelfID {
		for _, st := range previous.States {
			m.states[st.ID] = st
			switch st.Phase {
			case "direct", "backoff", "setup_required", "responder_only", "paused", "idle", "observing":
				m.policies[st.ID] = &Policy{LastRequest: st.Requested}
			}
		}
	}
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	fmt.Println(Name + " ready on " + address)
	for {
		if err := m.step(ctx, hub); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		select {
		case <-ctx.Done():
			return nil
		case err := <-serveErr:
			return err
		case <-tick.C:
		}
	}
}

type manager struct {
	store    Store
	backend  *adapter.Client
	policies map[string]*Policy
	states   map[string]State
	renewed  map[string]time.Time
	selfID   string
	activity activityTracker
}

func (m *manager) save() {
	v := Status{Version: Version, SelfID: m.selfID, Updated: time.Now().UTC()}
	c, _ := m.store.Config()
	for _, t := range c.Targets {
		state := m.states[t.ID]
		state.ID = t.ID
		state.Name = t.Name
		v.States = append(v.States, state)
	}
	_ = m.store.SaveStatus(v)
}
func (m *manager) step(ctx context.Context, h *optimize.Hub) error {
	// Reset byte baselines after our own probes/control/business checks so the
	// optimizer cannot mistake its own traffic for continuing user demand.
	didIO := false
	defer func() {
		if didIO && ctx.Err() == nil {
			if end, e := m.backend.Snapshot(ctx); e == nil {
				m.activity.settle(end.NetworkGeneration, end.Peers)
			}
		}
	}()
	c, err := m.store.Config()
	if err != nil {
		return err
	}
	snap, err := m.backend.Snapshot(ctx)
	if err != nil {
		return err
	}
	if snap.Self.ID != m.selfID || c.SelfID != m.selfID {
		for _, t := range c.Targets {
			m.states[t.ID] = State{ID: t.ID, Name: t.Name, Phase: "identity_changed", Error: "Tailscale 身份已变化，自动优化暂停", Updated: time.Now().UTC()}
		}
		h.Close()
		m.save()
		return errors.New("Tailscale identity changed; optimization suspended")
	}
	for id := range m.states {
		t, e := c.Find(id)
		if e != nil || !t.Enabled {
			didIO = true
			m.cleanup(ctx, id)
			delete(m.states, id)
		}
	}
	for _, t := range c.Targets {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		previous := m.states[t.ID]
		st := State{ID: t.ID, Name: t.Name, Updated: time.Now().UTC(), Requested: t.Requested, Report: previous.Report}
		m.states[t.ID] = st
		if !t.Enabled {
			st.Phase = "paused"
			m.states[t.ID] = st
			continue
		}
		peer, e := diagnostic.ResolvePeer(snap, t.ID)
		if e != nil || !peer.Online {
			st.Phase = "offline"
			m.states[t.ID] = st
			continue
		}
		policy := m.policies[t.ID]
		if policy == nil {
			policy = &Policy{}
			m.policies[t.ID] = policy
		}
		manual := t.Requested > policy.LastRequest
		active := m.activity.observe(time.Now(), snap.NetworkGeneration, *peer)
		if !active && !manual {
			policy.Observe(time.Now(), snap.NetworkGeneration, "unknown", false, t.Requested)
			st.Phase = "idle"
			m.states[t.ID] = st
			continue
		}
		probeCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
		didIO = true
		report, e := diagnostic.Diagnose(probeCtx, m.backend, diagnostic.Options{Peer: t.ID, Count: 1, Timeout: 3 * time.Second, Budget: 4 * time.Second, WireGuard: false})
		cancel()
		path := "unknown"
		if e == nil && report.Summary != nil && report.Summary.LastProbePath != nil {
			path = report.Summary.LastProbePath.Type
		}
		st.Path = path
		st.Phase = "observing"
		if report != nil && len(report.Probes) > 0 {
			st.LatencyMS = report.Probes[0].LatencyMS
		}
		if path == "direct" {
			st.Phase = "direct"
			if active && time.Since(m.renewed[t.ID]) > time.Minute {
				if err := m.renew(ctx, peer.Node, report.Summary.LastProbePath.Endpoint); err != nil {
					st.Error = err.Error()
				} else {
					m.renewed[t.ID] = time.Now()
				}
			}
		}
		due := policy.Observe(time.Now(), snap.NetworkGeneration, path, active, t.Requested)
		st.NextTry = policy.NextTry
		if !due && path != "direct" && time.Now().Before(policy.NextTry) {
			st.Phase = "backoff"
			st.Error = previous.Error
		}
		if due {
			if runtime.GOOS == "linux" {
				// Linux is currently the responder. Do not pretend the desktop capture
				// path can optimize two arbitrary Linux or Windows NATs yet.
				st.Phase = "responder_only"
				st.Error = "本版本 Linux 自动新会话优化由桌面端发起"
				policy.Complete(time.Now(), false)
			} else {
				st.Phase = "optimizing"
				m.states[t.ID] = st
				m.save()
				address, info, e := Discover(ctx, peer.Node)
				if e != nil || !info.Authorized {
					st.Phase = "setup_required"
					if e != nil {
						st.Error = e.Error()
					} else {
						st.Error = "对端尚未授权本机；使用 connect --ssh 完成部署或授权"
					}
					policy.Complete(time.Now(), false)
				} else {
					result := m.run(ctx, t, address)
					policy.Complete(time.Now(), result.DirectVerified)
					st.Phase = "backoff"
					st.Error = result.Error
					if st.Error == "" && !result.DirectVerified {
						st.Error = result.Outcome
					}
					if result.DirectVerified {
						st.Phase = "direct"
						st.Path = "direct"
						st.Error = ""
					}
					st.NextTry = policy.NextTry
					st.Report = filepath.Join(m.store.Dir, "reports", fmt.Sprint(time.Now().UnixNano())+".json")
					_ = writeJSONFile(st.Report, result)
				}
			}
		}
		st.Updated = time.Now().UTC()
		m.states[t.ID] = st
		m.save()
	}
	// Removal of local authorization terminates the corresponding server carrier.
	h.Sweep()
	m.save()
	return nil
}
func (m *manager) run(ctx context.Context, t Target, address string) *optimize.Report {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		tick := time.NewTicker(2 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-runCtx.Done():
				return
			case <-tick.C:
				c, e := m.store.Config()
				if e != nil {
					cancel()
					return
				}
				target, e := c.Find(t.ID)
				if e != nil || !target.Enabled || c.SelfID != m.selfID {
					cancel()
					return
				}
			}
		}
	}()
	unlock, err := optimize.Lock()
	if err != nil {
		return &optimize.Report{Error: err.Error(), Outcome: "busy"}
	}
	defer unlock()
	return optimize.Run(runCtx, m.backend, optimize.Options{Peer: t.ID, Coordinator: address, Budget: 180 * time.Second, Hold: 20 * time.Second, Count: 6, AllowRebind: false, SourceSessions: 3, SessionLease: 30 * time.Minute, Version: Version})
}
func (m *manager) cleanup(ctx context.Context, id string) {
	s, state, err := mapping.Active(ctx)
	if err != nil || state.PeerID != id || state.SelfID != m.selfID {
		return
	}
	snap, err := m.backend.Snapshot(ctx)
	if err == nil {
		peer, e := diagnostic.ResolvePeer(snap, id)
		if e == nil {
			if address, _, e := Discover(ctx, peer.Node); e == nil {
				var hello optimize.Hello
				if call(ctx, address, "/v1/hello", nil, &hello) == nil && hello.ExistingSourceSession != "" {
					_ = call(ctx, address, "/v1/session/stop", map[string]string{"session_id": hello.ExistingSourceSession}, nil)
				}
			}
		}
	}
	_ = s.Stop(ctx)
}
func (m *manager) renew(ctx context.Context, peer model.Node, localEndpoint string) error {
	s, local, e := mapping.Active(ctx)
	if e != nil || local.PeerID != peer.ID || local.SelfID != m.selfID || local.Local.String() != localEndpoint {
		return nil
	} // Ordinary native direct needs no carrier lease.
	address, _, e := Discover(ctx, peer)
	if e != nil {
		return e
	}
	var hello optimize.Hello
	if e = call(ctx, address, "/v1/hello", nil, &hello); e != nil {
		return e
	}
	if hello.Self.ID != peer.ID || hello.ExistingSourceSession == "" {
		return errors.New("remote carrier missing")
	}
	var remote mapping.State
	control := map[string]string{"session_id": hello.ExistingSourceSession}
	if e = call(ctx, address, "/v1/session/state", control, &remote); e != nil {
		return e
	}
	if remote.PeerID != m.selfID || remote.SelfID != peer.ID || !remote.Committed || remote.Stopped {
		return errors.New("remote carrier identity or lease mismatch")
	}
	if !local.Committed || local.Stopped {
		return errors.New("local carrier is not committed")
	}
	// Both sides must still verify their native path before extending the lease.
	var round optimize.RoundResponse
	binaryID := fmt.Sprintf("%032x", time.Now().UnixNano())
	if e = call(ctx, address, "/v1/probe", optimize.RoundRequest{AttemptID: binaryID, Count: 1}, &round); e != nil {
		return e
	}
	if round.Error != "" || round.Report == nil || round.Report.Self.ID != peer.ID || round.Report.Target == nil || round.Report.Target.ID != m.selfID || round.Report.NetworkGeneration != remote.Generation || round.Report.Summary == nil || round.Report.Summary.LastProbePath == nil || round.Report.Summary.LastProbePath.Type != "direct" || round.Report.Summary.LastProbePath.Endpoint != remote.Local.String() {
		return errors.New("remote native carrier path not verified")
	}
	if e = call(ctx, address, "/v1/session/renew", control, &remote); e != nil {
		return e
	}
	return s.Renew(ctx)
}

// JSONStatus is kept here so the product never prints tokens or runtime records.
func JSONStatus(s Store) ([]byte, error) {
	v, e := s.Status()
	if e != nil {
		return nil, e
	}
	return json.MarshalIndent(v, "", "  ")
}
