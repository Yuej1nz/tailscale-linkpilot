package product

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Yuej1nz/tailscale-linkpilot/internal/model"
	"github.com/Yuej1nz/tailscale-linkpilot/internal/optimize"
)

type schedulerBackend struct {
	mu         sync.Mutex
	generation string
	peers      []model.Peer
	pings      map[string]int
}

func (b *schedulerBackend) Snapshot(context.Context) (*model.Report, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return &model.Report{BackendState: "Running", Self: model.Node{ID: "self"}, NetworkGeneration: b.generation, Peers: append([]model.Peer(nil), b.peers...), Client: model.Client{Capabilities: map[string]model.Capability{}}}, nil
}
func (b *schedulerBackend) Ping(_ context.Context, ip netip.Addr, _ string) (model.PingResult, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for i := range b.peers {
		p := &b.peers[i]
		if p.IPs[0] == ip.String() {
			b.pings[p.ID]++
			p.TxBytes += 100 // Our own probes must not create new external demand.
			r := model.PingResult{IP: ip.String(), NodeIP: ip.String(), LatencySeconds: .001}
			if p.Path.Type == "direct" {
				r.Endpoint = "203.0.113.22:41641"
			} else {
				r.DERPRegionID = 1
				r.DERPRegionCode = "fixture"
			}
			return r, nil
		}
	}
	return model.PingResult{}, fmt.Errorf("unknown fixture peer")
}
func (*schedulerBackend) DebugAction(context.Context, string) error         { return nil }
func (*schedulerBackend) WhoIsID(context.Context, string) (string, error)   { return "", nil }
func (*schedulerBackend) NativeEndpoints(context.Context) ([]string, error) { return nil, nil }

func schedulerFixture(t *testing.T, n int, manual bool) (*manager, *schedulerBackend) {
	t.Helper()
	b := &schedulerBackend{generation: "wifi1", pings: map[string]int{}}
	s := Store{t.TempDir()}
	c := Config{Schema: 1, SelfID: "self", AllPeers: true}
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("peer-%02d", i)
		b.peers = append(b.peers, model.Peer{Node: model.Node{ID: id, Name: id, OS: "linux", IPs: []string{fmt.Sprintf("100.64.0.%d", i+1)}}, Online: true})
		request := int64(0)
		if manual {
			request = 1
		}
		c.Targets = append(c.Targets, Target{ID: id, Name: id, Enabled: true, Automatic: true, Requested: request})
	}
	if err := s.Update(func(cfg *Config) error { *cfg = c; return nil }); err != nil {
		t.Fatal(err)
	}
	m := &manager{store: s, backend: b, selfID: "self", platform: "darwin", policies: map[string]*Policy{}, states: map[string]State{}, renewed: map[string]time.Time{}, discover: func(_ context.Context, p model.Node) (string, optimize.ProductInfo, error) {
		return "fixture", optimize.ProductInfo{Authorized: true, PairedResponder: true}, nil
	}}
	m.activity.settle(b.generation, b.peers)
	return m, b
}

func waitJobResult(t *testing.T, m *manager) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for m.job != nil && len(m.job.done) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if m.job == nil || len(m.job.done) == 0 {
		t.Fatal("worker did not finish")
	}
}

func TestSerialRecoveryKeepsMonitoringAndDoesNotLoseQueuedManualRequests(t *testing.T) {
	m, b := schedulerFixture(t, 3, true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer m.stopJob()
	release := make(chan struct{})
	started := make(chan string, 3)
	var active, maximum atomic.Int32
	m.optimize = func(ctx context.Context, target Target, _ string) *optimize.Report {
		n := active.Add(1)
		for old := maximum.Load(); n > old && !maximum.CompareAndSwap(old, n); old = maximum.Load() {
		}
		defer active.Add(-1)
		started <- target.ID
		if target.ID == "peer-00" {
			select {
			case <-release:
			case <-ctx.Done():
			}
		}
		return &optimize.Report{Outcome: "fixture_failure"}
	}
	if err := m.step(ctx, nil); err != nil {
		t.Fatal(err)
	}
	select {
	case id := <-started:
		if id != "peer-00" {
			t.Fatal(id)
		}
	case <-time.After(time.Second):
		t.Fatal("first job missing")
	}
	if err := m.step(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if b.pings["peer-01"] != 2 || b.pings["peer-02"] != 2 || m.states["peer-01"].Phase != "queued" || m.policies["peer-01"].LastRequest != 0 {
		t.Fatal("long recovery blocked observation or consumed a waiting request", m.states)
	}
	close(release)
	waitJobResult(t, m)
	if err := m.step(ctx, nil); err != nil {
		t.Fatal(err)
	}
	select {
	case id := <-started:
		if id != "peer-01" {
			t.Fatal("unfair scheduling", id)
		}
	case <-time.After(time.Second):
		t.Fatal("waiting request was lost")
	}
	waitJobResult(t, m)
	if err := m.step(ctx, nil); err != nil {
		t.Fatal(err)
	}
	select {
	case id := <-started:
		if id != "peer-02" {
			t.Fatal(id)
		}
	case <-time.After(time.Second):
		t.Fatal("third request was lost")
	}
	if maximum.Load() != 1 {
		t.Fatal("overlapping recovery workers", maximum.Load())
	}
	if m.states["peer-00"].Report == "" {
		t.Fatal("finished recovery report missing")
	}
}

func TestAllPeerIdleSelectionDoesNotProbeOrStartRecovery(t *testing.T) {
	m, b := schedulerFixture(t, 3, false)
	m.optimize = func(context.Context, Target, string) *optimize.Report {
		t.Error("idle target started optimization")
		return nil
	}
	for i := 0; i < 4; i++ {
		if err := m.step(context.Background(), nil); err != nil {
			t.Fatal(err)
		}
	}
	if len(b.pings) != 0 || m.job != nil {
		t.Fatal("bulk selection generated unsolicited traffic")
	}
	for _, st := range m.states {
		if st.Phase != "idle" {
			t.Fatal(st)
		}
	}
}

func TestGlobalPauseCancelsRecoveryAndPausesNewlyDiscoveredPeers(t *testing.T) {
	m, b := schedulerFixture(t, 1, true)
	canceled := make(chan struct{})
	m.optimize = func(ctx context.Context, _ Target, _ string) *optimize.Report {
		<-ctx.Done()
		close(canceled)
		return &optimize.Report{Outcome: "cancelled"}
	}
	defer m.stopJob()
	if err := m.step(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if err := m.store.Update(func(c *Config) error { c.Paused = true; return nil }); err != nil {
		t.Fatal(err)
	}
	b.peers = append(b.peers, model.Peer{Node: model.Node{ID: "new", Name: "new", IPs: []string{"100.64.0.2"}}, Online: true})
	if err := m.step(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("pause did not cancel active work")
	}
	if m.states["new"].Phase != "paused" || b.pings["new"] != 0 {
		t.Fatal("discovery bypassed global pause")
	}
	waitJobResult(t, m)
	if err := m.step(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if m.job != nil {
		t.Fatal("paused job was restarted")
	}
}

func TestPeerCapabilityAndAuthorizationGateBeforeRecovery(t *testing.T) {
	m, _ := schedulerFixture(t, 2, true)
	m.discover = func(_ context.Context, p model.Node) (string, optimize.ProductInfo, error) {
		return "fixture", optimize.ProductInfo{Authorized: p.ID != "peer-00", PairedResponder: p.ID == "peer-00"}, nil
	}
	m.optimize = func(context.Context, Target, string) *optimize.Report {
		t.Error("unsupported or unauthorized search ran")
		return nil
	}
	if err := m.step(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if m.states["peer-00"].Phase != "setup_required" {
		t.Fatal(m.states)
	}
	if err := m.step(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if m.states["peer-01"].Phase != "unsupported" || m.job != nil {
		t.Fatal(m.states)
	}
}

func TestProbeBudgetRotatesInsteadOfStarvingLaterTargets(t *testing.T) {
	m, b := schedulerFixture(t, 20, true)
	m.platform = "linux"
	for cycle := 0; cycle < 3; cycle++ {
		before := 0
		for _, n := range b.pings {
			before += n
		}
		if err := m.step(context.Background(), nil); err != nil {
			t.Fatal(err)
		}
		after := 0
		for _, n := range b.pings {
			after += n
		}
		if after-before > 8 {
			t.Fatal("unbounded probe fanout", after-before)
		}
	}
	if len(b.pings) != 20 {
		t.Fatal("later targets were starved", len(b.pings))
	}
}

func TestNetworkChangeCancelsSearchWithoutReusingOldRelayEvidence(t *testing.T) {
	m, b := schedulerFixture(t, 2, true)
	canceled := make(chan struct{})
	m.optimize = func(ctx context.Context, _ Target, _ string) *optimize.Report {
		<-ctx.Done()
		close(canceled)
		return &optimize.Report{Outcome: "cancelled"}
	}
	defer m.stopJob()
	if err := m.step(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	b.mu.Lock()
	b.generation = "wifi2"
	b.mu.Unlock()
	// The other peer had automatic relay evidence in the previous network.
	m.policies["peer-01"] = &Policy{Generation: "wifi1", LastRequest: 1, RelaySamples: 3, RelaySince: time.Now().Add(-time.Minute)}
	if err := m.step(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("network change kept old search running")
	}
	waitJobResult(t, m)
	if err := m.step(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if m.job != nil || m.policies["peer-01"].RelaySamples != 0 {
		t.Fatal("old network evidence started a new search")
	}
}

func TestSchedulerPreservesCompletionWhenCurrentPathBecomesDirect(t *testing.T) {
	m, b := schedulerFixture(t, 1, true)
	m.optimize = func(context.Context, Target, string) *optimize.Report {
		return &optimize.Report{Outcome: "unproven", DirectVerified: false}
	}
	defer m.stopJob()
	if err := m.step(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	waitJobResult(t, m)
	if err := m.step(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	b.mu.Lock()
	b.peers[0].Path.Type = "direct"
	b.peers[0].RxBytes += 100
	b.mu.Unlock()
	if err := m.step(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	st := m.states["peer-00"]
	if st.Phase != "direct" || st.LastOptimization == nil || st.LastOptimization.Request != 1 || st.LastOptimization.DirectVerified {
		t.Fatal("current direct overwrote failed business proof", st)
	}
}
