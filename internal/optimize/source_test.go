package optimize

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Yuej1nz/tailscale-linkpilot/internal/mapping"
	"github.com/Yuej1nz/tailscale-linkpilot/internal/model"
)

type sourceBackend struct {
	*testBackend
	endpoint string
}

func (a *sourceBackend) MappingInput(context.Context, string, []string, int) (mapping.Input, error) {
	return mapping.Input{SelfID: "client", PeerID: "server", Generation: "fixture", Interface: "en7", Native: netip.MustParseAddrPort("127.0.0.1:41641"), SelfDisco: [32]byte{1}, PeerDisco: [32]byte{2}, Peers: []netip.AddrPort{netip.MustParseAddrPort("203.0.113.9:41641")}}, nil
}
func (a *sourceBackend) Ping(ctx context.Context, ip netip.Addr, kind string) (model.PingResult, error) {
	r, err := a.testBackend.Ping(ctx, ip, kind)
	if r.Endpoint != "" {
		r.Endpoint = a.endpoint
	}
	return r, err
}

type fakeSession struct {
	mu                sync.Mutex
	state             mapping.State
	closed, committed bool
}

func (s *fakeSession) State(context.Context) (mapping.State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return mapping.State{}, context.Canceled
	}
	return s.state, nil
}
func (s *fakeSession) Inject(context.Context, mapping.Injection) error { return nil }
func (s *fakeSession) STUN(context.Context) error                      { return nil }
func (s *fakeSession) Activate(context.Context, netip.AddrPort) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Activated = true
	return nil
}
func (s *fakeSession) Commit(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.committed = true
	s.state.Committed = true
	s.state.ExpiresAt = time.Now().Add(time.Minute)
	return nil
}
func (s *fakeSession) Stop(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

type fixtureCapture struct {
	start   func()
	stopped bool
}

func (c *fixtureCapture) Start(context.Context, mapping.Input, func(mapping.Injection)) (func() error, error) {
	c.start()
	return func() error { c.stopped = true; return nil }, nil
}

func TestSourceSessionRequiresRealDataAndRetainsOnlyVerifiedCarrier(t *testing.T) {
	for _, dataThroughCarrier := range []bool{false, true} {
		t.Run(map[bool]string{false: "discovery_only_rejected", true: "business_and_path_committed"}[dataThroughCarrier], func(t *testing.T) {
			client, server, original := pair(t, false, false)
			a := &sourceBackend{testBackend: client, endpoint: "127.0.0.1:51001"}
			s := &fakeSession{state: mapping.State{SessionID: "fixture-session", SelfID: "client", PeerID: "server", Generation: "fixture", Local: netip.MustParseAddrPort(a.endpoint), Physical: netip.MustParseAddrPort("203.0.113.9:41641"), FrozenPhysical: true, Counters: mapping.Counters{NativeOut: 3, PeerIn: 3}}}
			capture := &fixtureCapture{start: func() { client.direct.Store(true) }}
			// Echo follows the existing authenticated server handler. The counter
			// hook tests attribution logic; it is not a real encrypted/NAT test.
			handler := original.Config.Handler
			h := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/echo" && dataThroughCarrier {
					s.mu.Lock()
					s.state.Counters.DataOut += 90 << 10
					s.state.Counters.DataIn += 90 << 10
					s.mu.Unlock()
				}
				handler.ServeHTTP(w, r)
			}))
			defer h.Close()
			spawns := 0
			r := Run(context.Background(), a, Options{Peer: "server", Coordinator: strings.TrimPrefix(h.URL, "http://"), Budget: 30 * time.Second, Count: 1, SourceSessions: 3, SessionLease: time.Minute, Capture: capture, SpawnSession: func(_ context.Context, in mapping.Input, tried []uint16, _, _ time.Duration) (mapping.Session, error) {
				spawns++
				if len(tried) != 0 || in.SelfID != "client" || in.PeerID != "server" {
					t.Fatal("incorrect source ownership or attempted-port set")
				}
				return s, nil
			}, ActiveSession: func(context.Context) (mapping.Session, mapping.State, error) {
				return nil, mapping.State{}, context.Canceled
			}})
			_ = server
			if spawns != 1 || !capture.stopped || !r.ApplicationVerified {
				t.Fatalf("incomplete bounded run: %+v", r)
			}
			if dataThroughCarrier {
				if !r.DirectVerified || !r.Optimized || !s.committed || s.closed || r.Carrier == nil || r.Outcome != "direct_via_new_local_session" {
					t.Fatalf("verified carrier not retained: %+v", r)
				}
			} else if r.DirectVerified || s.committed || !s.closed || r.Carrier != nil {
				t.Fatalf("discovery-only carrier promoted to success: %+v", r)
			}
		})
	}
}

func TestExistingDirectSkipsSourceCaptureAndPortSearch(t *testing.T) {
	a, _, h := pair(t, true, false)
	r := Run(context.Background(), a, Options{Peer: "server", Coordinator: strings.TrimPrefix(h.URL, "http://"), Budget: 30 * time.Second, Count: 1, SourceSessions: 3, SessionLease: time.Minute, SpawnSession: func(context.Context, mapping.Input, []uint16, time.Duration, time.Duration) (mapping.Session, error) {
		t.Fatal("disrupted existing direct path")
		return nil, context.Canceled
	}})
	if !r.DirectVerified || r.RuntimeChanges || len(r.SourceTrials) != 0 {
		t.Fatalf("existing direct was searched: %+v", r)
	}
}
