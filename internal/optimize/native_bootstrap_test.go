package optimize

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Yuej1nz/tailscale-linkpilot/internal/mapping"
	"github.com/Yuej1nz/tailscale-linkpilot/internal/model"
)

type bootstrapTestBackend struct {
	*testBackend
	mu          sync.Mutex
	result      model.PingResult
	pingError   error
	ping        func(context.Context, netip.Addr, string) (model.PingResult, error)
	modifyState func(*model.Report)
	kinds       []string
}

func (b *bootstrapTestBackend) Snapshot(ctx context.Context) (*model.Report, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	r, err := b.testBackend.Snapshot(ctx)
	b.mu.Lock()
	if b.modifyState != nil {
		b.modifyState(r)
	}
	b.mu.Unlock()
	return r, err
}

func (b *bootstrapTestBackend) Ping(ctx context.Context, ip netip.Addr, kind string) (model.PingResult, error) {
	b.mu.Lock()
	b.kinds = append(b.kinds, kind)
	fn, result, err := b.ping, b.result, b.pingError
	b.mu.Unlock()
	if fn != nil {
		return fn(ctx, ip, kind)
	}
	return result, err
}

func (b *bootstrapTestBackend) pingKinds() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.kinds...)
}

func bootstrapFixture(t *testing.T) (*bootstrapTestBackend, *fakeSession, mapping.Input) {
	t.Helper()
	physical := netip.MustParseAddrPort("203.0.113.9:53001")
	local := netip.MustParseAddrPort("127.0.0.1:51001")
	input := mapping.Input{SelfID: "client", PeerID: "server", Generation: "fixture", Native: netip.MustParseAddrPort("127.0.0.1:41641"), SelfDisco: [32]byte{1}, PeerDisco: [32]byte{2}, Peers: []netip.AddrPort{physical}}
	state := mapping.State{
		SessionID: "0123456789abcdef0123456789abcdef", SelfID: input.SelfID, PeerID: input.PeerID, Generation: input.Generation,
		Local: local, Physical: physical, OutboundPhysical: physical, FrozenPhysical: true, ExpiresAt: time.Now().Add(time.Minute),
		Counters: mapping.Counters{PeerIn: 1},
		Prevalidation: &mapping.ProbeState{ID: "fedcba9876543210fedcba9876543210", ExpiresAt: time.Now().Add(20 * time.Second), Bursts: 8,
			Selected: physical, SentRequests: 8, RequestsReceived: 8, RepliesReceived: 8, RepliesSent: 8,
			Results: []mapping.ProbeResult{{Target: physical, ReplyFrom: physical, At: time.Now(), RTTMS: 1}}},
	}
	backend := &bootstrapTestBackend{testBackend: &testBackend{self: input.SelfID, peer: input.PeerID, direct: &atomic.Bool{}},
		result: model.PingResult{IP: "127.0.0.1", NodeIP: "127.0.0.1", Endpoint: local.String(), LatencySeconds: .001}}
	return backend, &fakeSession{state: state}, input
}

func bootstrapLimits() nativeBootstrapLimits {
	return nativeBootstrapLimits{Lease: 300 * time.Millisecond, ProbeTimeout: 20 * time.Millisecond, Interval: 5 * time.Millisecond, PollInterval: 2 * time.Millisecond, Attempts: 8}
}

func awaitBootstrap(t *testing.T, task *nativeBootstrap) NativeBootstrapState {
	t.Helper()
	select {
	case <-task.done:
		return task.snapshot()
	case <-time.After(2 * time.Second):
		t.Fatal("bounded native bootstrap did not finish")
		return NativeBootstrapState{}
	}
}

func TestNativeBootstrapWaitsForDiscoveryAndActivatesBeforeTSMP(t *testing.T) {
	b, s, in := bootstrapFixture(t)
	s.state.Counters.PeerIn = 0
	started := make(chan struct{}, 1)
	b.ping = func(_ context.Context, _ netip.Addr, kind string) (model.PingResult, error) {
		if kind != "disco" {
			return model.PingResult{}, errors.New("WireGuard must not precede native activation")
		}
		started <- struct{}{}
		return b.result, nil
	}
	task, err := startNativeBootstrapWithLimits(context.Background(), b, s, in, bootstrapLimits())
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
		t.Fatal("actively pinged before receiving discovery through the carrier")
	case <-time.After(20 * time.Millisecond):
	}
	s.mu.Lock()
	s.state.Counters.PeerIn = 1
	s.mu.Unlock()
	state := awaitBootstrap(t, task)
	s.mu.Lock()
	defer s.mu.Unlock()
	if state.State != "activated" || state.Attempts != 1 || !s.state.Activated || s.closed || s.committed || s.state.Counters.DataIn != 0 || s.state.Counters.DataOut != 0 {
		t.Fatal("discovery proof did not immediately activate without claiming business", state, s.state)
	}
	if kinds := b.pingKinds(); len(kinds) != 1 || kinds[0] != "disco" {
		t.Fatal("native activation depended on TSMP or application traffic", kinds)
	}
}

func TestNativeBootstrapRejectsWrongPeerAndUnprovenEndpoints(t *testing.T) {
	for name, alter := range map[string]func(*model.PingResult){
		"wrong_target_ip": func(r *model.PingResult) { r.IP = "100.64.0.2" },
		"wrong_peer_ip":   func(r *model.PingResult) { r.NodeIP = "100.64.0.2" },
		"missing_peer_ip": func(r *model.PingResult) { r.NodeIP = "" },
		"wrong_endpoint":  func(r *model.PingResult) { r.Endpoint = "127.0.0.1:51002" },
		"native_endpoint": func(r *model.PingResult) { r.Endpoint = "127.0.0.1:41641" },
		"relay":           func(r *model.PingResult) { r.Endpoint = ""; r.DERPRegionID = 1; r.DERPRegionCode = "fixture" },
		"conflict":        func(r *model.PingResult) { r.DERPRegionID = 1 },
		"raw_error":       func(r *model.PingResult) { r.Err = "native peer authentication failed" },
	} {
		t.Run(name, func(t *testing.T) {
			b, s, in := bootstrapFixture(t)
			alter(&b.result)
			limits := bootstrapLimits()
			limits.Attempts = 1
			task, err := startNativeBootstrapWithLimits(context.Background(), b, s, in, limits)
			if err != nil {
				t.Fatal(err)
			}
			state := awaitBootstrap(t, task)
			s.mu.Lock()
			defer s.mu.Unlock()
			if state.State != "failed" || s.state.Activated || !s.closed || s.committed {
				t.Fatal("invalid native evidence activated or retained a carrier", state, s.state)
			}
		})
	}
}

func TestNativeBootstrapRequiresCurrentIdentityAndSelectedSession(t *testing.T) {
	for name, change := range map[string]func(*bootstrapTestBackend, *fakeSession){
		"self_identity": func(b *bootstrapTestBackend, _ *fakeSession) {
			b.modifyState = func(r *model.Report) { r.Self.ID = "other" }
		},
		"peer_identity": func(b *bootstrapTestBackend, _ *fakeSession) {
			b.modifyState = func(r *model.Report) { r.Peers[0].ID = "other" }
		},
		"generation": func(b *bootstrapTestBackend, _ *fakeSession) {
			b.modifyState = func(r *model.Report) { r.NetworkGeneration = "changed" }
		},
		"stopped_native": func(b *bootstrapTestBackend, _ *fakeSession) {
			b.modifyState = func(r *model.Report) { r.BackendState = "Stopped" }
		},
		"no_udp_proof": func(_ *bootstrapTestBackend, s *fakeSession) { s.state.Prevalidation = nil },
		"unselected":   func(_ *bootstrapTestBackend, s *fakeSession) { s.state.FrozenPhysical = false },
		"unconfirmed":  func(_ *bootstrapTestBackend, s *fakeSession) { s.state.Prevalidation.Bursts = 7 },
	} {
		t.Run(name, func(t *testing.T) {
			b, s, in := bootstrapFixture(t)
			change(b, s)
			if task, err := startNativeBootstrapWithLimits(context.Background(), b, s, in, bootstrapLimits()); err == nil {
				_ = task.cancelAndWait(context.Background())
				t.Fatal("armed native bootstrap with changed identity or missing UDP proof")
			}
			if s.state.Activated || len(b.pingKinds()) != 0 {
				t.Fatal("invalid preparation made active native requests")
			}
		})
	}
}

func TestNativeBootstrapCancellationAndDeadlineWithoutDiscoveryMakeNoRequests(t *testing.T) {
	for _, cancelEarly := range []bool{false, true} {
		t.Run(map[bool]string{false: "deadline", true: "cancel"}[cancelEarly], func(t *testing.T) {
			b, s, in := bootstrapFixture(t)
			s.state.Counters.PeerIn = 0
			limits := bootstrapLimits()
			limits.Lease = 40 * time.Millisecond
			task, err := startNativeBootstrapWithLimits(context.Background(), b, s, in, limits)
			if err != nil {
				t.Fatal(err)
			}
			if cancelEarly {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				if err := task.cancelAndWait(ctx); err != nil {
					t.Fatal(err)
				}
			}
			state := awaitBootstrap(t, task)
			s.mu.Lock()
			defer s.mu.Unlock()
			if len(b.pingKinds()) != 0 || state.Attempts != 0 || s.state.Activated || !s.closed || s.committed {
				t.Fatal("unreceived discovery or cancelled lease sent probes/retained carrier", state, s.state)
			}
		})
	}
}

func TestNativeBootstrapNeverExceedsEightNativeRequests(t *testing.T) {
	b, s, in := bootstrapFixture(t)
	b.result.Endpoint = "127.0.0.1:51002"
	task, err := startNativeBootstrapWithLimits(context.Background(), b, s, in, bootstrapLimits())
	if err != nil {
		t.Fatal(err)
	}
	state := awaitBootstrap(t, task)
	if state.Attempts != 8 || len(b.pingKinds()) != 8 || state.State != "failed" {
		t.Fatal("native validation budget not enforced", state, b.pingKinds())
	}
	for _, kind := range b.pingKinds() {
		if kind != "disco" {
			t.Fatal("sent a WireGuard-dependent ping before activation", kind)
		}
	}
}

func TestNativeBootstrapSuccessAfterFailedAttemptClearsFailure(t *testing.T) {
	b, s, in := bootstrapFixture(t)
	var calls atomic.Int32
	b.ping = func(context.Context, netip.Addr, string) (model.PingResult, error) {
		if calls.Add(1) == 1 {
			return model.PingResult{}, errors.New("temporary discovery failure")
		}
		return b.result, nil
	}
	task, err := startNativeBootstrapWithLimits(context.Background(), b, s, in, bootstrapLimits())
	if err != nil {
		t.Fatal(err)
	}
	state := awaitBootstrap(t, task)
	s.mu.Lock()
	defer s.mu.Unlock()
	if state.State != "activated" || state.Error != "" || state.Attempts != 2 || !s.state.Activated || s.closed || s.committed {
		t.Fatal("a previous attempt's failure overrode a valid native result", state, s.state)
	}
}

func TestNativeBootstrapRechecksIdentityAfterDiscovery(t *testing.T) {
	for name, modify := range map[string]func(*model.Report){
		"self_changed":       func(r *model.Report) { r.Self.ID = "other" },
		"peer_changed":       func(r *model.Report) { r.Peers[0].ID = "other" },
		"generation_changed": func(r *model.Report) { r.NetworkGeneration = "changed" },
		"peer_ip_changed":    func(r *model.Report) { r.Peers[0].IPs = []string{"127.0.0.2"} },
	} {
		t.Run(name, func(t *testing.T) {
			b, s, in := bootstrapFixture(t)
			b.ping = func(context.Context, netip.Addr, string) (model.PingResult, error) {
				b.mu.Lock()
				b.modifyState = modify
				b.mu.Unlock()
				return b.result, nil
			}
			limits := bootstrapLimits()
			limits.Attempts = 1
			task, err := startNativeBootstrapWithLimits(context.Background(), b, s, in, limits)
			if err != nil {
				t.Fatal(err)
			}
			state := awaitBootstrap(t, task)
			s.mu.Lock()
			defer s.mu.Unlock()
			if state.State != "failed" || s.state.Activated || !s.closed {
				t.Fatal("discovery authorized a changed node/network", state)
			}
		})
	}
}

func TestNativeBootstrapDoesNotActivateOrStopAReplacementSession(t *testing.T) {
	b, s, in := bootstrapFixture(t)
	b.ping = func(context.Context, netip.Addr, string) (model.PingResult, error) {
		s.mu.Lock()
		s.state.SessionID = "00112233445566778899aabbccddeeff"
		s.mu.Unlock()
		return b.result, nil
	}
	limits := bootstrapLimits()
	limits.Attempts = 1
	task, err := startNativeBootstrapWithLimits(context.Background(), b, s, in, limits)
	if err != nil {
		t.Fatal(err)
	}
	state := awaitBootstrap(t, task)
	s.mu.Lock()
	defer s.mu.Unlock()
	if state.State != "failed" || s.state.Activated || s.closed {
		t.Fatal("an obsolete task touched a replacement carrier", state, s.state)
	}
}

func TestNativeBootstrapCancellationInterruptsAnActiveProbe(t *testing.T) {
	b, s, in := bootstrapFixture(t)
	entered := make(chan struct{})
	b.ping = func(ctx context.Context, _ netip.Addr, _ string) (model.PingResult, error) {
		close(entered)
		<-ctx.Done()
		return model.PingResult{}, ctx.Err()
	}
	limits := bootstrapLimits()
	limits.ProbeTimeout = 200 * time.Millisecond
	task, err := startNativeBootstrapWithLimits(context.Background(), b, s, in, limits)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("native request did not start")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := task.cancelAndWait(ctx); err != nil {
		t.Fatal(err)
	}
	state := awaitBootstrap(t, task)
	if state.State != "failed" || state.Attempts != 1 || len(b.pingKinds()) != 1 {
		t.Fatal("cancelled probe was retried", state)
	}
}

type bootstrapHTTPBackend struct {
	*pairedBackend
	endpoint string
	pings    atomic.Int32
}

func (b *bootstrapHTTPBackend) Ping(_ context.Context, ip netip.Addr, kind string) (model.PingResult, error) {
	b.pings.Add(1)
	if kind != "disco" {
		return model.PingResult{}, errors.New("unexpected WireGuard dependency")
	}
	return model.PingResult{IP: ip.String(), NodeIP: "127.0.0.1", Endpoint: b.endpoint, LatencySeconds: .001}, nil
}

func TestArmedNativeBootstrapSurvivesControlHTTPDisconnect(t *testing.T) {
	// Real UDP carriers and the real assistant HTTP handler exercise lifetime
	// separation. LocalAPI's authenticated discovery result is deliberately
	// supplied by a mock; this is not a native Tailscale or NAT success test.
	client, assistant, backend, remote := prevalidationFixture(t)
	h := httptest.NewServer(assistant.Handler())
	t.Cleanup(h.Close)
	r := &rpc{base: h.URL, http: h.Client(), paired: true, prevalidation: true, orderedPrevalidation: true}
	p := &pairedSession{Session: client, client: r, remote: remote, endpoints: []netip.AddrPort{remote.State.Local}}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := p.prevalidate(ctx); err != nil {
		t.Fatal(err)
	}
	// Preserve the already-running carrier's original backend/check callback.
	// A separate owner handler uses the controlled LocalAPI discovery result,
	// avoiding unsynchronized backend replacement in the live worker fixture.
	h.Close()
	localAPI := &bootstrapHTTPBackend{pairedBackend: backend, endpoint: remote.State.Local.String()}
	owner, err := NewAssistant(ctx, localAPI, "client")
	if err != nil {
		t.Fatal(err)
	}
	owner.source, owner.sourceInput = assistant.source, assistant.sourceInput
	t.Cleanup(owner.stopSource)
	control := httptest.NewServer(owner.Handler())
	t.Cleanup(control.Close)
	state, _ := owner.source.State(ctx)
	requestCtx, cancelRequest := context.WithCancel(ctx)
	data, _ := json.Marshal(sourceBootstrapControl{ID: state.SessionID, ProbeID: state.Prevalidation.ID})
	req, err := http.NewRequestWithContext(requestCtx, http.MethodPost, control.URL+"/v1/session/bootstrap/arm", bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	response, err := control.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var ack sourceBootstrapReply
	decodeErr := json.NewDecoder(response.Body).Decode(&ack)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || decodeErr != nil || ack.Bootstrap.State != "armed" {
		t.Fatal("bootstrap not armed before HTTP disconnect", response.StatusCode, decodeErr, ack)
	}
	cancelRequest()
	control.CloseClientConnections()
	control.Close()
	if localAPI.pings.Load() != 0 {
		t.Fatal("native probes started before the carrier received discovery")
	}
	packet := make([]byte, 6+32+24+16)
	copy(packet, []byte("TS💬"))
	packet[6] = 1
	if err := client.Inject(ctx, mapping.Injection{Direction: "out", Peer: remote.State.Local, Packet: packet}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		state, err = owner.source.State(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if state.Activated {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !state.Activated || state.Stopped || state.Committed || state.Counters.DataIn != 0 || state.Counters.DataOut != 0 || localAPI.pings.Load() != 1 {
		t.Fatal("closed control connection prevented independent native activation", state, localAPI.pings.Load())
	}
}
