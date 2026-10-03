package optimize

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Yuej1nz/tailscale-linkpilot/internal/model"
)

// Loopback addresses are synthetic integration fixtures, not real tailnet
// identities or a NAT emulator. They exercise the authenticated protocol.
type testBackend struct {
	self            string
	peer            string
	direct          *atomic.Bool
	recoverOnRebind bool
	deny            atomic.Bool
	mu              sync.Mutex
	actions         []string
}

func (a *testBackend) Snapshot(context.Context) (*model.Report, error) {
	return &model.Report{SchemaVersion: 1, CollectedAt: time.Now(), BackendState: "Running", NetworkGeneration: "fixture", Self: model.Node{ID: a.self, Name: a.self, IPs: []string{"127.0.0.1"}}, Peers: []model.Peer{{Node: model.Node{ID: a.peer, Name: a.peer, IPs: []string{"127.0.0.1"}}}}, Client: model.Client{Version: "fixture", Capabilities: map[string]model.Capability{}}}, nil
}
func (a *testBackend) Ping(_ context.Context, ip netip.Addr, _ string) (model.PingResult, error) {
	r := model.PingResult{IP: ip.String(), NodeIP: "127.0.0.1", LatencySeconds: .001}
	if a.direct.Load() {
		r.Endpoint = "203.0.113.10:41641"
	} else {
		r.DERPRegionID = 1
		r.DERPRegionCode = "fixture"
	}
	return r, nil
}
func (a *testBackend) DebugAction(_ context.Context, action string) error {
	a.mu.Lock()
	a.actions = append(a.actions, action)
	a.mu.Unlock()
	if action == "rebind" && a.recoverOnRebind {
		a.direct.Store(true)
	}
	return nil
}
func (a *testBackend) WhoIsID(context.Context, string) (string, error) {
	if a.deny.Load() {
		return "wrong-node", nil
	}
	return a.peer, nil
}
func (a *testBackend) NativeEndpoints(context.Context) ([]string, error) {
	return []string{"203.0.113.10:41641"}, nil
}

func pair(t *testing.T, initial, recover bool) (*testBackend, *testBackend, *httptest.Server) {
	t.Helper()
	d := &atomic.Bool{}
	d.Store(initial)
	client := &testBackend{self: "client", peer: "server", direct: d, recoverOnRebind: recover}
	server := &testBackend{self: "server", peer: "client", direct: d}
	a, err := NewAssistant(context.Background(), server, "client")
	if err != nil {
		t.Fatal(err)
	}
	h := httptest.NewServer(a.Handler())
	t.Cleanup(h.Close)
	return client, server, h
}

func runFixture(t *testing.T, a Backend, h *httptest.Server) *Report {
	t.Helper()
	return Run(context.Background(), a, Options{Peer: "server", Coordinator: strings.TrimPrefix(h.URL, "http://"), Budget: 30 * time.Second, Count: 1, Rebinds: 1, AllowRebind: true, Version: "fixture"})
}

func TestRecoveryUsesAuthenticatedAssistantAndVerifiesApplication(t *testing.T) {
	a, b, h := pair(t, false, true)
	r := runFixture(t, a, h)
	if r.Outcome != "direct_after_recovery" || !r.DirectVerified || !r.ApplicationVerified || !r.Optimized || r.PersistentChanges {
		t.Fatalf("unexpected recovery: %+v", r)
	}
	a.mu.Lock()
	actions := append([]string(nil), a.actions...)
	a.mu.Unlock()
	if strings.Join(actions, ",") != "restun,rebind,restun" {
		t.Fatal(actions)
	}
	b.mu.Lock()
	remoteActions := append([]string(nil), b.actions...)
	b.mu.Unlock()
	for _, action := range remoteActions {
		if action != "restun" {
			t.Fatal("remote destructive action:", action)
		}
	}
	if len(r.Verification) != 3 {
		t.Fatal("missing hold verification")
	}
}

func TestExistingDirectPathNeverRebinds(t *testing.T) {
	a, b, h := pair(t, true, true)
	r := runFixture(t, a, h)
	if r.Outcome != "already_direct_preserved" || r.Optimized || !r.DirectVerified || r.RuntimeChanges {
		t.Fatalf("unexpected result: %+v", r)
	}
	if len(a.actions)+len(b.actions) != 0 {
		t.Fatal("disrupted an existing direct path")
	}
}

func TestRelayApplicationSuccessIsNotOptimizerSuccess(t *testing.T) {
	a, _, h := pair(t, false, false)
	r := runFixture(t, a, h)
	if r.DirectVerified || r.Optimized || !r.ApplicationVerified || r.Outcome != "relay_or_unproven_path_application_available" {
		t.Fatalf("relay was promoted: %+v", r)
	}
	if len(r.Trials) != 3 {
		t.Fatal("unexpected retry budget", len(r.Trials))
	}
}

func TestAssistantRejectsOtherNodesBeforeActions(t *testing.T) {
	_, b, h := pair(t, false, true)
	b.deny.Store(true)
	response, err := http.Post(h.URL+"/v1/probe", "application/json", strings.NewReader(`{"attempt_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","refresh":true,"count":1}`))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusForbidden || len(b.actions) != 0 {
		t.Fatal("unauthorized action accepted")
	}
}

func TestWrongCoordinatorIsRejectedBeforeActions(t *testing.T) {
	a, _, _ := pair(t, false, true)
	r := Run(context.Background(), a, Options{Peer: "server", Coordinator: "203.0.113.8:45827", Budget: 30 * time.Second, Count: 1})
	if r.Error == "" || len(a.actions) != 0 || len(r.Trials) != 0 {
		t.Fatal("external coordinator accepted")
	}
}

func TestEchoCorruptionCannotPassVerification(t *testing.T) {
	a, _, _ := pair(t, true, true)
	h := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/echo" {
			var request EchoRequest
			_ = json.NewDecoder(r.Body).Decode(&request)
			_ = json.NewEncoder(w).Encode(EchoResponse{AttemptID: request.AttemptID, Challenge: request.Challenge, Digest: "forged", Data: request.Data})
			return
		}
		http.Error(w, "not available", http.StatusServiceUnavailable)
	}))
	defer h.Close()
	client := &rpc{base: h.URL, http: h.Client()}
	v := verify(context.Background(), a, client, model.Node{ID: "client"}, model.Node{ID: "server"})
	if v.ApplicationOK || v.DirectBothWays || !strings.Contains(v.Error, "mismatch") {
		t.Fatal("corrupted echo accepted")
	}
}

func TestAssistantBodyAndAttemptLimits(t *testing.T) {
	_, _, h := pair(t, false, false)
	for _, body := range []string{`{"attempt_id":"old","count":1}`, `{"attempt_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","count":9}`, `{"attempt_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","count":1,"command":"shell"}`} {
		response, err := http.Post(h.URL+"/v1/probe", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusBadRequest {
			t.Fatal("invalid request accepted:", body)
		}
	}
}

func TestAssistantCannotListenOnPublicOrWildcardAddress(t *testing.T) {
	_, b, _ := pair(t, false, false)
	a, _ := NewAssistant(context.Background(), b, "client")
	for _, address := range []string{"0.0.0.0:45827", "203.0.113.8:45827"} {
		if l, err := a.Listen(address); err == nil {
			l.Close()
			t.Fatal("unsafe listener accepted")
		}
	}
}

func TestRPCRedirectDoesNotReachUnrelatedEndpoint(t *testing.T) {
	var called atomic.Bool
	unrelated := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called.Store(true) }))
	defer unrelated.Close()
	h := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, unrelated.URL, http.StatusTemporaryRedirect)
	}))
	defer h.Close()
	client := &rpc{base: h.URL, http: &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect denied") }}}
	var result Hello
	if client.call(context.Background(), "/v1/hello", nil, &result) == nil || called.Load() {
		t.Fatal("redirect bypassed endpoint restriction")
	}
}
