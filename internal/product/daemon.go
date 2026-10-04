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
	heartbeatDone := make(chan struct{})
	defer func() {
		stopHeartbeat()
		<-heartbeatDone
		_ = os.Remove(filepath.Join(s.Dir, "heartbeat.json"))
	}()
	_ = s.Pulse(c.SelfID)
	go func() {
		defer close(heartbeatDone)
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
	defer m.stopJob()
	m.activity.settle(initial.NetworkGeneration, initial.Peers)

	if previous, e := s.Status(); e == nil && previous.SelfID == c.SelfID {
		for _, st := range previous.States {
			m.states[st.ID] = st
			switch st.Phase {
			case "direct", "backoff", "setup_required", "responder_only", "unsupported", "paused", "idle", "observing":
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
	store       Store
	backend     optimize.Backend
	policies    map[string]*Policy
	states      map[string]State
	renewed     map[string]time.Time
	selfID      string
	activity    activityTracker
	job         *optimizationJob
	lastStarted string
	lastProbed  string
	// The scheduler is testable with real protocol IO and synthetic native paths.
	platform string
	discover func(context.Context, model.Node) (string, optimize.ProductInfo, error)
	optimize func(context.Context, Target, string) *optimize.Report
}

type optimizationJob struct {
	target     Target
	generation string
	cancel     context.CancelFunc
	done       chan *optimize.Report
}

type readyTarget struct {
	target Target
	peer   model.Node
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

// Each step monitors a bounded, rotating set of active peers. A single separate
// worker performs long recovery attempts, so observation and lease maintenance
// of other peers continue while a search is in progress.
func (m *manager) step(ctx context.Context, h *optimize.Hub) error {
	c, err := m.store.Config()
	if err != nil {
		return err
	}
	snap, err := m.backend.Snapshot(ctx)
	if err != nil {
		return err
	}
	if snap.Self.ID != m.selfID || c.SelfID != m.selfID || snap.BackendState != "Running" {
		if m.job != nil {
			m.job.cancel()
		}
		for _, t := range c.Targets {
			m.states[t.ID] = State{ID: t.ID, Name: t.Name, Phase: "identity_changed", Error: "Tailscale 身份已变化或未运行，自动优化暂停", Updated: time.Now().UTC()}
		}
		if h != nil {
			h.Close()
		}
		m.save()
		return errors.New("Tailscale identity changed or stopped; optimization suspended")
	}
	// Reconcile under the configuration lock with the latest user choices, rather
	// than overwriting a concurrent pause, disconnect or authorization edit.
	candidate := c
	if candidate.reconcile(snap) {
		err = m.store.Update(func(latest *Config) error {
			if latest.SelfID != m.selfID {
				return errors.New("configuration identity changed")
			}
			latest.reconcile(snap)
			return nil
		})
		if err != nil {
			return err
		}
		c, err = m.store.Config()
		if err != nil {
			return err
		}
	}
	if m.job != nil {
		t, e := c.Find(m.job.target.ID)
		if e != nil || !t.Enabled || c.Paused || m.job.generation != snap.NetworkGeneration {
			m.job.cancel()
		}
	}
	m.collectJob(ctx, c, snap)
	for id := range m.states {
		t, e := c.Find(id)
		if e != nil || !t.Enabled || c.Paused {
			if m.job != nil && m.job.target.ID == id {
				continue
			}
			if m.states[id].Phase != "paused" {
				m.cleanup(ctx, id)
			}
			if e != nil {
				delete(m.states, id)
				delete(m.policies, id)
				delete(m.renewed, id)
			}
		}
	}
	// Capture all external demand before any of our own IO. Only the peer involved
	// in an operation has its baseline settled; unrelated business stays visible.
	demand := map[string]bool{}
	for _, p := range snap.Peers {
		if m.job != nil && m.job.target.ID == p.ID {
			m.activity.settle(snap.NetworkGeneration, []model.Peer{p})
		} else {
			demand[p.ID] = m.activity.observe(time.Now(), snap.NetworkGeneration, p)
		}
	}
	ready := []readyTarget{}
	probes := 0
	for _, t := range rotateTargets(c.Targets, m.lastProbed) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		previous := m.states[t.ID]
		st := State{ID: t.ID, Name: t.Name, Updated: time.Now().UTC(), Requested: t.Requested, Report: previous.Report, Path: previous.Path, LatencyMS: previous.LatencyMS, LastOptimization: previous.LastOptimization}
		if !t.Enabled || c.Paused {
			st.Phase = "paused"
			m.states[t.ID] = st
			continue
		}
		if m.job != nil && m.job.target.ID == t.ID {
			// Keep the in-flight request ID separate from a newer manual request.
			st.Phase, st.Requested = "optimizing", m.job.target.Requested
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
		active := demand[t.ID]
		if !active && !manual {
			policy.Observe(time.Now(), snap.NetworkGeneration, "unknown", false, t.Requested)
			st.Phase = "idle"
			if previous.Phase == "setup_required" || previous.Phase == "unsupported" || previous.Phase == "responder_only" {
				st.Phase, st.Error, st.NextTry = previous.Phase, previous.Error, policy.NextTry
			}
			m.states[t.ID] = st
			continue
		}
		// A busy tailnet cannot produce an unbounded sequence of timed-out probes.
		if probes >= 8 {
			st.Phase = "observing"
			m.states[t.ID] = st
			continue
		}
		probes++
		m.lastProbed = t.ID
		probeCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
		report, e := diagnostic.Diagnose(probeCtx, m.backend, diagnostic.Options{Peer: t.ID, Count: 1, Timeout: 3 * time.Second, Budget: 4 * time.Second, WireGuard: false})
		cancel()
		path := "unknown"
		if e == nil && report != nil && report.Summary != nil && report.Summary.LastProbePath != nil {
			path = report.Summary.LastProbePath.Type
		}
		st.Path, st.Phase = path, "observing"
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
		lastRequest := policy.LastRequest
		due := policy.Observe(time.Now(), snap.NetworkGeneration, path, active, t.Requested)
		// A request is consumed only when selected, not while waiting for another
		// peer's long optimization. Automatic demand is re-evaluated on every step.
		if due {
			policy.LastRequest = lastRequest
		}
		st.NextTry = policy.NextTry
		if !due && path != "direct" && time.Now().Before(policy.NextTry) {
			st.Phase, st.Error = "backoff", previous.Error
			if previous.Phase == "setup_required" || previous.Phase == "unsupported" || previous.Phase == "responder_only" {
				st.Phase = previous.Phase
			}
		}
		if due {
			st.Phase = "queued"
			ready = append(ready, readyTarget{t, peer.Node})
		}
		m.states[t.ID] = st
		m.settlePeer(ctx, t.ID)
	}
	if m.job == nil && len(ready) > 0 && ctx.Err() == nil {
		m.startNext(ctx, ready, snap.NetworkGeneration)
	}
	if h != nil {
		h.Sweep()
	}
	m.save()
	return nil
}

func rotateTargets(targets []Target, after string) []Target {
	start := 0
	for i, t := range targets {
		if t.ID == after {
			start = (i + 1) % len(targets)
			break
		}
	}
	result := make([]Target, 0, len(targets))
	result = append(result, targets[start:]...)
	return append(result, targets[:start]...)
}

func (m *manager) settlePeer(ctx context.Context, id string) {
	if end, e := m.backend.Snapshot(ctx); e == nil {
		for _, p := range end.Peers {
			if p.ID == id {
				m.activity.settle(end.NetworkGeneration, []model.Peer{p})
				break
			}
		}
	}
}

func (m *manager) startNext(ctx context.Context, ready []readyTarget, generation string) {
	// Use configured order, independently of the rotating monitoring order.
	c, err := m.store.Config()
	if err != nil {
		return
	}
	var chosen *readyTarget
	for _, t := range rotateTargets(c.Targets, m.lastStarted) {
		if !t.Enabled || c.Paused {
			continue
		}
		for i := range ready {
			if ready[i].target.ID == t.ID && ready[i].target.Requested == t.Requested {
				chosen = &ready[i]
				break
			}
		}
		if chosen != nil {
			break
		}
	}
	if chosen == nil {
		return
	}
	t := chosen.target
	m.lastStarted = t.ID
	policy := m.policies[t.ID]
	policy.LastRequest = t.Requested
	st := m.states[t.ID]
	platform := m.platform
	if platform == "" {
		platform = runtime.GOOS
	}
	if platform == "linux" {
		st.Phase, st.Error = "responder_only", "本版本 Linux 自动新会话优化由桌面端发起"
		policy.Complete(time.Now(), false)
		st.NextTry = policy.NextTry
		st.LastOptimization = &Completion{Request: t.Requested, Outcome: st.Phase, Error: st.Error}
		m.states[t.ID] = st
		return
	}
	discover := m.discover
	if discover == nil {
		discover = Discover
	}
	discoveryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	address, info, err := discover(discoveryCtx, chosen.peer)
	cancel()
	m.settlePeer(ctx, t.ID)
	if err != nil || !info.Authorized || !info.PairedResponder {
		st.Phase = "setup_required"
		if err != nil {
			st.Error = err.Error()
		} else if !info.PairedResponder {
			st.Phase, st.Error = "unsupported", "对端当前不提供新会话配对响应能力；本版本支持桌面端到公网 IPv4 Linux"
		} else {
			st.Error = "对端尚未授权本机；在对端执行 tslink authorize <本机节点>，或对该节点使用 connect --ssh"
		}
		policy.Complete(time.Now(), false)
		st.NextTry = policy.NextTry
		st.LastOptimization = &Completion{Request: t.Requested, Outcome: st.Phase, Error: st.Error}
		m.states[t.ID] = st
		return
	}
	runCtx, stop := context.WithCancel(ctx)
	job := &optimizationJob{target: t, generation: generation, cancel: stop, done: make(chan *optimize.Report, 1)}
	m.job = job
	st.Phase = "optimizing"
	m.states[t.ID] = st
	m.save()
	runner := m.optimize
	if runner == nil {
		runner = m.run
	}
	go func() { job.done <- runner(runCtx, t, address) }()
}

func (m *manager) collectJob(ctx context.Context, c Config, snap *model.Report) {
	if m.job == nil {
		return
	}
	job := m.job
	select {
	case result := <-job.done:
		job.cancel()
		m.job = nil
		m.settlePeer(ctx, job.target.ID)
		t, err := c.Find(job.target.ID)
		if err != nil || !t.Enabled || c.Paused || snap.NetworkGeneration != job.generation {
			m.cleanup(ctx, job.target.ID)
			return
		}
		if result == nil {
			result = &optimize.Report{Outcome: "failed", Error: "optimizer returned no result"}
		}
		policy := m.policies[job.target.ID]
		policy.Complete(time.Now(), result.DirectVerified)
		st := State{ID: t.ID, Name: t.Name, Requested: job.target.Requested, Updated: time.Now().UTC(), Phase: "backoff", Error: result.Error, NextTry: policy.NextTry}
		if st.Error == "" && !result.DirectVerified {
			st.Error = result.Outcome
		}
		if result.DirectVerified {
			st.Phase, st.Path, st.Error = "direct", "direct", ""
		}
		st.Report = filepath.Join(m.store.Dir, "reports", fmt.Sprint(time.Now().UnixNano())+".json")
		if err := writeJSONFile(st.Report, result); err != nil {
			st.Error = "报告保存失败: " + err.Error()
			st.Report = ""
		}
		st.LastOptimization = &Completion{Request: job.target.Requested, Outcome: result.Outcome, DirectVerified: result.DirectVerified, Error: st.Error, Report: st.Report}
		m.states[t.ID] = st
	default:
	}
}

func (m *manager) stopJob() {
	if m.job == nil {
		return
	}
	m.job.cancel()
	// Let the optimizer close uncommitted sockets and capture before daemon exit.
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	select {
	case <-m.job.done:
	case <-timer.C:
	}
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
				if e != nil || !target.Enabled || c.Paused || c.SelfID != m.selfID {
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
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	s, state, err := mapping.ActiveFor(ctx, m.selfID, id)
	if err != nil || state.PeerID != id || state.SelfID != m.selfID {
		return
	}
	// Local cleanup must not depend on the remote control path recovering.
	_ = s.Stop(ctx)
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
}
func (m *manager) renew(ctx context.Context, peer model.Node, localEndpoint string) error {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	s, local, e := mapping.ActiveFor(ctx, m.selfID, peer.ID)
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
