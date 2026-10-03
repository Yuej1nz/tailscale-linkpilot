package optimize

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Yuej1nz/tailscale-linkpilot/internal/mapping"
)

type observedProbeSession struct {
	*mapping.Embedded
	beforeProbe func() error
}

func (s *observedProbeSession) Probe(ctx context.Context, targets []netip.AddrPort) error {
	if err := s.beforeProbe(); err != nil {
		return err
	}
	return s.Embedded.Probe(ctx, targets)
}

// This fixture uses real owned UDP sockets and the authenticated assistant
// handler. It does not emulate NAT or authenticate native Tailscale packets.
func prevalidationFixture(t *testing.T) (*mapping.Embedded, *Assistant, *pairedBackend, sourceReply) {
	t.Helper()
	listen := func() netip.AddrPort {
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		return conn.LocalAddr().(*net.UDPAddr).AddrPort()
	}
	clientNative, serverNative := listen(), listen()
	client, err := mapping.NewEmbedded(context.Background(), mapping.Input{
		SelfID: "client", PeerID: "server", Generation: "fixture", Native: clientNative,
		SelfDisco: [32]byte{1}, PeerDisco: [32]byte{2}, Peers: []netip.AddrPort{serverNative},
	}, nil, time.Minute, time.Minute, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Stop(context.Background()) })
	backend := &pairedBackend{testBackend: &testBackend{self: "server", peer: "client", direct: &atomic.Bool{}}, native: serverNative}
	assistant, err := NewAssistant(context.Background(), backend, "client")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(assistant.stopSource)
	local, err := client.State(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	w := sourceRequest(t, assistant.Handler(), "/v1/session/prepare", sourcePrepare{
		Mapped: []netip.AddrPort{local.Local}, ServerDisco: [32]byte{2}, ClientDisco: [32]byte{1}, LeaseSeconds: 60,
	})
	if w.Code != http.StatusOK {
		t.Fatalf("prepare: HTTP %d: %s", w.Code, w.Body.String())
	}
	var remote sourceReply
	if err := json.Unmarshal(w.Body.Bytes(), &remote); err != nil {
		t.Fatal(err)
	}
	if err := client.AddPeer(context.Background(), remote.State.Local); err != nil {
		t.Fatal(err)
	}
	return client, assistant, backend, remote
}

func TestPairedPrevalidationUsesOwnedSocketsWithoutActivatingNativeData(t *testing.T) {
	client, assistant, _, remote := prevalidationFixture(t)
	before, err := client.State(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Observe transient control material only in test memory, to verify that
	// serializing the public state cannot leak it into run evidence.
	secret := make(chan []byte, 1)
	var primeACK atomic.Bool
	handler := assistant.Handler()
	h := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/session/probe/configure" {
			data, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "fixture request unreadable", http.StatusBadRequest)
				return
			}
			var request sourceProbeConfigure
			if err := json.Unmarshal(data, &request); err != nil {
				http.Error(w, "fixture request invalid", http.StatusBadRequest)
				return
			}
			secret <- append([]byte(nil), request.Config.Key...)
			r.Body = io.NopCloser(bytes.NewReader(data))
		}
		if r.URL.Path == "/v1/session/probe/run" {
			data, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "fixture phase unreadable", http.StatusBadRequest)
				return
			}
			var request sourceProbeRun
			if err := json.Unmarshal(data, &request); err != nil {
				http.Error(w, "fixture phase invalid", http.StatusBadRequest)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(data))
			if request.Phase == probePrime {
				state, _ := client.State(r.Context())
				if state.Prevalidation == nil || state.Prevalidation.Bursts != 0 || state.Prevalidation.SentRequests != 0 {
					http.Error(w, "client sent before remote prime", http.StatusConflict)
					return
				}
				recorded := httptest.NewRecorder()
				handler.ServeHTTP(recorded, r)
				if recorded.Code == http.StatusOK {
					primeACK.Store(true)
				}
				w.WriteHeader(recorded.Code)
				_, _ = w.Write(recorded.Body.Bytes())
				return
			}
		}
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(h.Close)
	observed := &observedProbeSession{Embedded: client, beforeProbe: func() error {
		if !primeACK.Load() {
			return errors.New("local request preceded remote prime acknowledgement")
		}
		return nil
	}}
	p := &pairedSession{Session: observed, client: &rpc{base: h.URL, http: h.Client(), paired: true, prevalidation: true, orderedPrevalidation: true}, remote: remote, endpoints: []netip.AddrPort{remote.State.Local}}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := p.prevalidate(ctx); err != nil {
		t.Fatal("same-socket roundtrip failed:", err)
	}
	local, err := client.State(ctx)
	if err != nil {
		t.Fatal(err)
	}
	currentRemote, err := p.remoteState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if local.Local != before.Local || local.SessionID != before.SessionID || currentRemote.Local != remote.State.Local || currentRemote.SessionID != remote.State.SessionID {
		t.Fatal("prevalidation replaced an owned socket or session")
	}
	if p.selectedSend != remote.State.Local {
		t.Fatal("native bootstrap target differs from the proven server socket")
	}
	order := p.prevalidationOrder
	if order == nil || order.PrimeDirection != "assistant_to_client" || order.RemotePrimeSentAt.IsZero() || order.LocalPrimeACKAt.IsZero() || order.LocalFirstRequestAt.Before(order.LocalPrimeACKAt) || order.LocalFirstRequestAfterACKMS < 0 {
		t.Fatalf("missing local ACK barrier evidence: %+v", order)
	}
	for _, item := range []struct {
		name string
		got  mapping.State
		peer netip.AddrPort
	}{{"local", local, currentRemote.Local}, {"remote", currentRemote, local.Local}} {
		s := item.got
		if s.Prevalidation == nil || s.Prevalidation.ID != local.Prevalidation.ID || s.Prevalidation.Selected != item.peer || s.OutboundPhysical != item.peer || s.Physical != item.peer || !s.FrozenPhysical {
			t.Fatalf("%s lost selected send/receive provenance: %+v", item.name, s)
		}
		if s.Prevalidation.Bursts != 8 || s.Prevalidation.SentRequests == 0 || s.Prevalidation.RequestsReceived == 0 || s.Prevalidation.RepliesSent == 0 || s.Prevalidation.RepliesReceived == 0 || len(s.Prevalidation.Results) == 0 {
			t.Fatalf("%s lacks bounded bilateral socket evidence: %+v", item.name, s.Prevalidation)
		}
		for _, result := range s.Prevalidation.Results {
			if result.Target != item.peer || result.ReplyFrom != item.peer || result.At.IsZero() {
				t.Fatalf("%s reply attributed to the wrong target or source: %+v", item.name, result)
			}
		}
		if s.Activated || s.Committed || s.Counters != (mapping.Counters{}) {
			t.Fatalf("%s counted probe traffic as native authentication or data: %+v", item.name, s)
		}
	}
	var key []byte
	select {
	case key = <-secret:
	default:
		t.Fatal("prevalidation did not exchange transient authentication material")
	}
	if len(key) != 32 {
		t.Fatal("unexpected transient key size")
	}
	encoded, err := json.Marshal([]mapping.State{local, currentRemote})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(`"key"`)) || bytes.Contains(encoded, []byte(base64.StdEncoding.EncodeToString(key))) || bytes.Contains(encoded, []byte(hex.EncodeToString(key))) {
		t.Fatal("state report exposed transient prevalidation key")
	}
	if err := client.Commit(ctx); err == nil {
		t.Fatal("transport prevalidation committed a carrier without native business")
	}
	if w := sourceRequest(t, handler, "/v1/session/commit", sourceControl{ID: currentRemote.SessionID}); w.Code != http.StatusConflict {
		t.Fatal("server committed transport-only evidence", w.Code)
	}
}

func TestPrimeACKMismatchNeverStartsLocalRequests(t *testing.T) {
	for name, alter := range map[string]func(*sourceProbeReply){
		"session":      func(r *sourceProbeReply) { r.State.SessionID = "00000000000000000000000000000000" },
		"identity":     func(r *sourceProbeReply) { r.State.SelfID = "other" },
		"endpoint":     func(r *sourceProbeReply) { r.State.Local = netip.MustParseAddrPort("127.0.0.1:9") },
		"probe":        func(r *sourceProbeReply) { r.State.Prevalidation.ID = "00000000000000000000000000000000" },
		"bursts":       func(r *sourceProbeReply) { r.State.Prevalidation.Bursts = 2 },
		"unsent":       func(r *sourceProbeReply) { r.State.Prevalidation.SentRequests = 0 },
		"phase":        func(r *sourceProbeReply) { r.Phase = probeSearch },
		"stopped":      func(r *sourceProbeReply) { r.State.Stopped = true },
		"timestamp":    func(r *sourceProbeReply) { r.CompletedAt = time.Time{} },
		"http_failure": nil,
	} {
		t.Run(name, func(t *testing.T) {
			client, assistant, _, remote := prevalidationFixture(t)
			handler := assistant.Handler()
			h := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/session/probe/run" {
					handler.ServeHTTP(w, r)
					return
				}
				recorded := httptest.NewRecorder()
				handler.ServeHTTP(recorded, r)
				if alter == nil {
					http.Error(w, "prime acknowledgement unavailable", http.StatusServiceUnavailable)
					return
				}
				var reply sourceProbeReply
				if recorded.Code != http.StatusOK || json.Unmarshal(recorded.Body.Bytes(), &reply) != nil {
					http.Error(w, "fixture prime failed", http.StatusInternalServerError)
					return
				}
				alter(&reply)
				writeJSON(w, reply)
			}))
			t.Cleanup(h.Close)
			p := &pairedSession{Session: client, client: &rpc{base: h.URL, http: h.Client(), orderedPrevalidation: true}, remote: remote, endpoints: []netip.AddrPort{remote.State.Local}}
			if err := p.prevalidate(context.Background()); err == nil {
				t.Fatal("accepted invalid prime acknowledgement")
			}
			state, _ := client.State(context.Background())
			if state.Prevalidation == nil || state.Prevalidation.Bursts != 0 || state.Prevalidation.SentRequests != 0 || state.Activated || state.Committed || p.selectedSend.IsValid() || p.remote.State.SessionID != remote.State.SessionID {
				t.Fatal("invalid ACK started local probes or changed cleanup ownership", state)
			}
		})
	}
}

func TestOrderedPhasesRejectSkipReplayAndConcurrentRequests(t *testing.T) {
	client, assistant, _, remote := prevalidationFixture(t)
	local, _ := client.State(context.Background())
	handler := assistant.Handler()
	config := mapping.ProbeConfig{ID: "0123456789abcdef0123456789abcdef", Key: bytes.Repeat([]byte{0x5a}, 32), LifetimeSeconds: 20, Role: "responder"}
	if w := sourceRequest(t, handler, "/v1/session/probe/configure", sourceProbeConfigure{ID: remote.State.SessionID, Config: config}); w.Code != http.StatusOK {
		t.Fatal("configuration failed", w.Code)
	}
	request := sourceProbeRun{ID: remote.State.SessionID, ProbeID: config.ID}
	for _, phase := range []string{probeSearch, probeConfirm, ""} {
		request.Phase = phase
		if w := sourceRequest(t, handler, "/v1/session/probe/run", request); w.Code != http.StatusConflict {
			t.Fatal("skipped or unknown phase accepted", phase, w.Code)
		}
	}
	request.Phase = probePrime
	if w := sourceRequest(t, handler, "/v1/session/probe/run", request); w.Code != http.StatusOK {
		t.Fatal("prime incorrectly required the client to receive or reply", w.Code)
	}
	state, _ := assistant.source.State(context.Background())
	if state.Prevalidation.Bursts != 1 || state.Prevalidation.SentRequests != 1 || state.Prevalidation.RepliesReceived != 0 {
		t.Fatal("prime was not one send-only burst", state)
	}
	if w := sourceRequest(t, handler, "/v1/session/probe/run", request); w.Code != http.StatusConflict {
		t.Fatal("replayed prime was accepted", w.Code)
	}
	request.Phase = probeSearch
	data, _ := json.Marshal(request)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan int, 1)
	go func() {
		req := httptest.NewRequest(http.MethodPost, "/v1/session/probe/run", bytes.NewReader(data)).WithContext(ctx)
		req.RemoteAddr = "127.0.0.1:12345"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		done <- w.Code
	}()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		state, _ = assistant.source.State(context.Background())
		if state.Prevalidation.Bursts > 1 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if state.Prevalidation.Bursts <= 1 {
		t.Fatal("search did not start")
	}
	if w := sourceRequest(t, handler, "/v1/session/probe/run", request); w.Code != http.StatusConflict {
		t.Fatal("concurrent search accepted", w.Code)
	}
	if w := sourceRequest(t, handler, "/v1/session/probe/select", sourceProbeSelect{ID: remote.State.SessionID, Target: local.Local}); w.Code != http.StatusConflict {
		t.Fatal("route changed during an active search", w.Code)
	}
	cancel()
	select {
	case code := <-done:
		if code != http.StatusConflict {
			t.Fatal("cancelled phase did not stop", code)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled search retained phase lock")
	}
	state, _ = assistant.source.State(context.Background())
	if state.Prevalidation.Bursts >= 7 || state.Activated || state.Committed {
		t.Fatal("cancelled phase exhausted the budget or enabled data", state)
	}
}

func TestOrderedPrevalidationCapabilityIsRequiredBeforeConfiguration(t *testing.T) {
	client, assistant, _, remote := prevalidationFixture(t)
	h := httptest.NewServer(assistant.Handler())
	t.Cleanup(h.Close)
	r := &rpc{base: h.URL, http: h.Client(), prevalidation: true}
	var hello Hello
	if err := r.call(context.Background(), "/v1/hello", nil, &hello); err != nil || !hello.UDPOrderedPrevalidation {
		t.Fatal("assistant did not advertise the ordered protocol", err)
	}
	p := &pairedSession{Session: client, client: r, remote: remote, endpoints: []netip.AddrPort{remote.State.Local}}
	if err := p.prevalidate(context.Background()); err == nil {
		t.Fatal("legacy capability silently used the ordered protocol")
	}
	state, _ := client.State(context.Background())
	if state.Prevalidation != nil {
		t.Fatal("capability failure changed local probe state")
	}
}

func TestPrevalidationAssistantRejectsUnownedAndUnprovenSelection(t *testing.T) {
	client, assistant, backend, remote := prevalidationFixture(t)
	local, _ := client.State(context.Background())
	handler := assistant.Handler()
	config := mapping.ProbeConfig{ID: "0123456789abcdef0123456789abcdef", Key: bytes.Repeat([]byte{0x5a}, 32), LifetimeSeconds: 20, Role: "responder"}
	for _, wrongIdentity := range []bool{true, false} {
		backend.deny.Store(wrongIdentity)
		id, want := remote.State.SessionID, http.StatusForbidden
		if !wrongIdentity {
			id, want = "00000000000000000000000000000000", http.StatusConflict
		}
		for _, request := range []struct {
			path string
			body any
		}{
			{"/v1/session/probe/configure", sourceProbeConfigure{ID: id, Config: config}},
			{"/v1/session/probe/select", sourceProbeSelect{ID: id, Target: local.Local}},
		} {
			if w := sourceRequest(t, handler, request.path, request.body); w.Code != want {
				t.Fatalf("%s admitted unowned control: HTTP %d; want %d", request.path, w.Code, want)
			}
		}
		state, _ := assistant.source.State(context.Background())
		if state.Prevalidation != nil || state.FrozenPhysical || state.Activated || state.Committed {
			t.Fatal("rejected caller changed server probe state")
		}
	}
	if w := sourceRequest(t, handler, "/v1/session/probe/configure", sourceProbeConfigure{ID: remote.State.SessionID, Config: config}); w.Code != http.StatusOK {
		t.Fatalf("authorized configuration rejected: HTTP %d: %s", w.Code, w.Body.String())
	}
	if w := sourceRequest(t, handler, "/v1/session/probe/select", sourceProbeSelect{ID: remote.State.SessionID, Target: local.Local}); w.Code != http.StatusConflict {
		t.Fatal("selected an endpoint before any authenticated roundtrip", w.Code)
	}
	state, _ := assistant.source.State(context.Background())
	if state.Prevalidation.Selected.IsValid() || state.FrozenPhysical || state.Activated || state.Committed {
		t.Fatal("unproven route selection changed native state")
	}
}

func TestProvenTargetRequiresFreshMatchingEvidenceAndPreservesSendDestination(t *testing.T) {
	now := time.Now()
	id := "0123456789abcdef0123456789abcdef"
	target, reply := netip.MustParseAddrPort("203.0.113.9:45100"), netip.MustParseAddrPort("198.51.100.8:45100")
	valid := func() mapping.State {
		return mapping.State{Prevalidation: &mapping.ProbeState{ID: id, Results: []mapping.ProbeResult{{Target: target, ReplyFrom: reply, At: now}}}}
	}
	if got, err := provenTarget(valid(), id, now); err != nil || got != target || got == reply {
		t.Fatalf("selected reply source instead of proven send target: %s, %v", got, err)
	}
	for name, change := range map[string]func(*mapping.State){
		"missing":      func(s *mapping.State) { s.Prevalidation = nil },
		"wrong_id":     func(s *mapping.State) { s.Prevalidation.ID = "fedcba9876543210fedcba9876543210" },
		"no_roundtrip": func(s *mapping.State) { s.Prevalidation.Results = nil },
		"stale":        func(s *mapping.State) { s.Prevalidation.Results[0].At = now.Add(-11 * time.Second) },
		"future":       func(s *mapping.State) { s.Prevalidation.Results[0].At = now.Add(3 * time.Second) },
		"no_target":    func(s *mapping.State) { s.Prevalidation.Results[0].Target = netip.AddrPort{} },
		"no_reply":     func(s *mapping.State) { s.Prevalidation.Results[0].ReplyFrom = netip.AddrPort{} },
	} {
		t.Run(name, func(t *testing.T) {
			s := valid()
			change(&s)
			if _, err := provenTarget(s, id, now); err == nil {
				t.Fatal("accepted absent, stale, or mismatched route evidence")
			}
		})
	}
}
