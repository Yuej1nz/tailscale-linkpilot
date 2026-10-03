package optimize

import (
	"context"
	"errors"
	"net"
	"net/http"
	"runtime"
	"sync"
	"time"

	"github.com/Yuej1nz/tailscale-linkpilot/internal/diagnostic"
)

// Hub isolates the carrier and bootstrap state of each explicitly allowed node.
// Tailnet membership alone never grants permission to refresh mappings.
type Hub struct {
	Backend Backend
	Version string
	Allowed func(string) bool
	SelfID  string
	mu      sync.Mutex
	peers   map[string]*Assistant
	context context.Context
}

func NewHub(ctx context.Context, b Backend, version string, allowed func(string) bool) (*Hub, error) {
	s, err := b.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	if s.BackendState != "Running" || s.Self.ID == "" {
		return nil, errors.New("Tailscale must be running")
	}
	return &Hub{Backend: b, Version: version, Allowed: allowed, SelfID: s.Self.ID, peers: map[string]*Assistant{}, context: ctx}, nil
}

type ProductInfo struct {
	Product         string `json:"product"`
	Version         string `json:"version"`
	Protocol        int    `json:"protocol"`
	SelfID          string `json:"self_id"`
	Authorized      bool   `json:"authorized"`
	PairedResponder bool   `json:"paired_responder"`
	Platform        string `json:"platform"`
}

func (h *Hub) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
		defer cancel()
		id, err := h.Backend.WhoIsID(ctx, r.RemoteAddr)
		if err != nil || id == "" {
			http.Error(w, "Tailscale identity required", 403)
			return
		}
		s, err := h.Backend.Snapshot(ctx)
		if err != nil || s.Self.ID != h.SelfID || s.BackendState != "Running" {
			http.Error(w, "local identity changed", 409)
			return
		}
		p, err := diagnostic.ResolvePeer(s, id)
		if err != nil || !hasIP(p.IPs, remoteIP(r.RemoteAddr)) {
			http.Error(w, "peer address changed", 403)
			return
		}
		allowed := h.Allowed != nil && h.Allowed(id)
		if r.URL.Path == "/product/v1/info" && r.Method == http.MethodGet {
			writeJSON(w, ProductInfo{"Tailscale LinkPilot", h.Version, 1, h.SelfID, allowed, runtime.GOOS == "linux", runtime.GOOS})
			return
		}
		if !allowed {
			h.Revoke(id)
			http.Error(w, "peer has not been authorized locally", 403)
			return
		}
		h.mu.Lock()
		a := h.peers[id]
		if a == nil {
			a = &Assistant{Backend: h.Backend, Self: s.Self, Peer: p.Node, Version: s.Client.Version, serveContext: h.context}
			h.peers[id] = a
		}
		h.mu.Unlock()
		a.Handler().ServeHTTP(w, r.WithContext(ctx))
	})
}
func (h *Hub) Revoke(id string) {
	h.mu.Lock()
	a := h.peers[id]
	delete(h.peers, id)
	h.mu.Unlock()
	if a != nil {
		a.stopSource()
	}
}
func (h *Hub) Close() {
	h.mu.Lock()
	peers := h.peers
	h.peers = map[string]*Assistant{}
	h.mu.Unlock()
	for _, a := range peers {
		a.stopSource()
	}
}
func (h *Hub) Serve(ctx context.Context, l net.Listener) error {
	defer h.Close()
	srv := &http.Server{Handler: h.Handler(), ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 25 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 5 * time.Second, BaseContext: func(net.Listener) context.Context { return ctx }}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			srv.Close()
		case <-done:
		}
	}()
	err := srv.Serve(l)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (h *Hub) Sweep() {
	h.mu.Lock()
	ids := make([]string, 0, len(h.peers))
	for id := range h.peers {
		ids = append(ids, id)
	}
	h.mu.Unlock()
	for _, id := range ids {
		if h.Allowed == nil || !h.Allowed(id) {
			h.Revoke(id)
		}
	}
}
