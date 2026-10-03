package optimize

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"sync"
	"time"

	"github.com/Yuej1nz/tailscale-linkpilot/internal/diagnostic"
	"github.com/Yuej1nz/tailscale-linkpilot/internal/mapping"
	"github.com/Yuej1nz/tailscale-linkpilot/internal/model"
)

var attemptPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

type Assistant struct {
	Backend         Backend
	Self            model.Node
	Peer            model.Node
	Version         string
	mu              sync.Mutex
	sourceMu        sync.Mutex
	sourceProbeMu   sync.Mutex
	source          *mapping.Embedded
	sourceBootstrap *nativeBootstrap
	sourceInput     mapping.Input
	sourcePorts     []uint16
	serveContext    context.Context
}

func NewAssistant(ctx context.Context, a Backend, selector string) (*Assistant, error) {
	r, err := a.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	if r.BackendState != "Running" || r.Self.ID == "" {
		return nil, errors.New("local Tailscale identity is not Running")
	}
	p, err := diagnostic.ResolvePeer(r, selector)
	if err != nil {
		return nil, err
	}
	return &Assistant{Backend: a, Self: r.Self, Peer: p.Node, Version: r.Client.Version}, nil
}

// Listen accepts only an address owned by this Tailscale node. Never expose
// the helper on wildcard, LAN, or public interfaces.
func (a *Assistant) Listen(address string) (net.Listener, error) {
	ap, err := netip.ParseAddrPort(address)
	if err != nil || ap.Port() == 0 {
		return nil, errors.New("assistant requires a numeric Tailscale IP:port")
	}
	for _, value := range a.Self.IPs {
		if value == ap.Addr().String() {
			return net.Listen("tcp", ap.String())
		}
	}
	return nil, errors.New("listen address is not assigned to this Tailscale node")
}

func (a *Assistant) Serve(ctx context.Context, listener net.Listener) error {
	a.serveContext = ctx
	defer a.stopSource()
	srv := &http.Server{Handler: a.Handler(), ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 25 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 5 * time.Second,
		BaseContext: func(net.Listener) context.Context { return ctx }}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = srv.Close()
		case <-done:
		}
	}()
	err := srv.Serve(listener)
	close(done)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (a *Assistant) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/hello", a.hello)
	mux.HandleFunc("/v1/probe", a.probe)
	mux.HandleFunc("/v1/echo", a.echo)
	mux.HandleFunc("/v1/session/prepare", a.prepareSource)
	mux.HandleFunc("/v1/session/seed", a.seedSource)
	mux.HandleFunc("/v1/session/state", a.stateSource)
	mux.HandleFunc("/v1/session/probe/configure", a.configureSourceProbe)
	mux.HandleFunc("/v1/session/probe/run", a.runSourceProbe)
	mux.HandleFunc("/v1/session/probe/select", a.selectSourceProbe)
	mux.HandleFunc("/v1/session/bootstrap/arm", a.armSourceBootstrap)
	mux.HandleFunc("/v1/session/bootstrap/state", a.controlSourceBootstrap)
	mux.HandleFunc("/v1/session/bootstrap/cancel", a.controlSourceBootstrap)
	mux.HandleFunc("/v1/session/commit", a.commitSource)
	mux.HandleFunc("/v1/session/renew", a.renewSource)
	mux.HandleFunc("/v1/session/stop", a.endSource)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
		defer cancel()
		id, err := a.Backend.WhoIsID(ctx, r.RemoteAddr)
		if err != nil || id != a.Peer.ID {
			http.Error(w, "authenticated node is not the locally authorized peer", http.StatusForbidden)
			return
		}
		// Re-resolve before every request; account switches invalidate the helper.
		s, err := a.Backend.Snapshot(ctx)
		if err != nil || s.Self.ID != a.Self.ID || s.BackendState != "Running" {
			http.Error(w, "local identity changed", http.StatusConflict)
			return
		}
		p, err := diagnostic.ResolvePeer(s, a.Peer.ID)
		if err != nil || !hasIP(p.IPs, remoteIP(r.RemoteAddr)) {
			http.Error(w, "peer address changed", http.StatusForbidden)
			return
		}
		mux.ServeHTTP(w, r.WithContext(ctx))
	})
}

func remoteIP(address string) string {
	host, _, _ := net.SplitHostPort(address)
	return host
}

func hasIP(values []string, ip string) bool {
	for _, value := range values {
		if value == ip {
			return true
		}
	}
	return false
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

func decode(w http.ResponseWriter, r *http.Request, value any) bool {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(value); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return false
	}
	return true
}

func (a *Assistant) hello(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	_, paired := a.Backend.(peerSessionBackend)
	a.sourceMu.Lock()
	existing := ""
	if a.source != nil {
		state, err := a.source.State(r.Context())
		if err == nil && !state.Stopped {
			existing = state.SessionID
		}
	}
	a.sourceMu.Unlock()
	writeJSON(w, Hello{ExistingSourceSession: existing, Protocol: ProtocolVersion, Self: a.Self, Version: a.Version, PairedSessions: paired, UDPPrevalidation: paired, UDPOrderedPrevalidation: paired, AutonomousNativeBootstrap: paired})
}

func action(ctx context.Context, a Backend, side, name string) Action {
	x := Action{Side: side, Name: name, StartedAt: time.Now().UTC()}
	if err := a.DebugAction(ctx, name); err != nil {
		x.Error = err.Error()
	}
	x.FinishedAt = time.Now().UTC()
	return x
}

func endpoints(ctx context.Context, a Backend, generation string) EndpointSnapshot {
	x := EndpointSnapshot{ObservedAt: time.Now().UTC(), Generation: generation, Source: "native_client_self_addrs"}
	var err error
	x.Addresses, err = a.NativeEndpoints(ctx)
	if err != nil {
		x.Error = err.Error()
	}
	return x
}

func (a *Assistant) probe(w http.ResponseWriter, r *http.Request) {
	var req RoundRequest
	if !decode(w, r, &req) {
		return
	}
	if !attemptPattern.MatchString(req.AttemptID) || req.Count < 1 || req.Count > 8 {
		http.Error(w, "invalid attempt or count", http.StatusBadRequest)
		return
	}
	if !a.mu.TryLock() {
		http.Error(w, "another probe is active", http.StatusConflict)
		return
	}
	defer a.mu.Unlock()
	resp := RoundResponse{AttemptID: req.AttemptID}
	if req.Refresh {
		x := action(r.Context(), a.Backend, "remote", "restun")
		resp.Action = &x
	}
	// The client starts its own probes while this request is in flight.
	if err := sleep(r.Context(), 500*time.Millisecond); err != nil {
		resp.Error = err.Error()
		writeJSON(w, resp)
		return
	}
	var err error
	resp.Report, err = diagnostic.Diagnose(r.Context(), a.Backend, diagnostic.Options{Peer: a.Peer.ID, Count: req.Count, Timeout: 2 * time.Second, Budget: 20 * time.Second, WireGuard: true})
	if err != nil {
		resp.Error = err.Error()
	}
	gen := ""
	if resp.Report != nil {
		gen = resp.Report.NetworkGeneration
	}
	resp.Endpoints = endpoints(r.Context(), a.Backend, gen)
	if req.SourceSessionID != "" {
		state, err := a.activateSource(r.Context(), req.SourceSessionID, resp.Report)
		resp.SourceSession = &state
		if err != nil {
			resp.Error = "paired session activation: " + err.Error()
		}
	}
	writeJSON(w, resp)
}

func (a *Assistant) echo(w http.ResponseWriter, r *http.Request) {
	var req EchoRequest
	if !decode(w, r, &req) {
		return
	}
	if !attemptPattern.MatchString(req.AttemptID) || len(req.Challenge) != 64 || len(req.Data) < 1 || len(req.Data) > 256<<10 {
		http.Error(w, "invalid echo", http.StatusBadRequest)
		return
	}
	if _, err := hex.DecodeString(req.Challenge); err != nil {
		http.Error(w, "invalid challenge", http.StatusBadRequest)
		return
	}
	h := sha256.Sum256(req.Data)
	writeJSON(w, EchoResponse{AttemptID: req.AttemptID, Challenge: req.Challenge, Digest: fmt.Sprintf("%x", h), Data: req.Data})
}
