package optimize

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Yuej1nz/tailscale-linkpilot/internal/mapping"
)

type pairedBackend struct {
	*testBackend
	native   netip.AddrPort
	prepares atomic.Int32
}

func (b *pairedBackend) PeerSessionInput(_ context.Context, _ string, peer string, addresses []netip.AddrPort, selfKey, peerKey [32]byte) (mapping.Input, error) {
	b.prepares.Add(1)
	return mapping.Input{SelfID: b.self, PeerID: peer, Generation: "fixture", Native: b.native, SelfDisco: selfKey, PeerDisco: peerKey, Peers: addresses}, nil
}
func (b *pairedBackend) NativeEndpoints(context.Context) ([]string, error) {
	return []string{b.native.String()}, nil
}
func sourceRequest(t *testing.T, h http.Handler, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(data))
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}
func TestPairedAssistantRequiresIdentityOwnershipAndVerifiedData(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	b := &pairedBackend{testBackend: &testBackend{self: "server", peer: "client", direct: &atomic.Bool{}}, native: conn.LocalAddr().(*net.UDPAddr).AddrPort()}
	a, err := NewAssistant(context.Background(), b, "client")
	if err != nil {
		t.Fatal(err)
	}
	defer a.stopSource()
	handler := a.Handler()
	request := sourcePrepare{Mapped: []netip.AddrPort{netip.MustParseAddrPort("203.0.113.20:45678")}, ServerDisco: [32]byte{2}, ClientDisco: [32]byte{1}, LeaseSeconds: 60}
	b.deny.Store(true)
	if w := sourceRequest(t, handler, "/v1/session/prepare", request); w.Code != 403 || b.prepares.Load() != 0 {
		t.Fatal("unauthorized peer allocated a socket", w.Code)
	}
	b.deny.Store(false)
	w := sourceRequest(t, handler, "/v1/session/prepare", request)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var reply sourceReply
	if err := json.Unmarshal(w.Body.Bytes(), &reply); err != nil {
		t.Fatal(err)
	}
	if reply.State.Local.Port() == b.native.Port() || reply.State.Committed {
		t.Fatal("new session reused native socket or committed early")
	}
	if w := sourceRequest(t, handler, "/v1/session/prepare", request); w.Code != 409 {
		t.Fatal("concurrent source session accepted")
	}
	old := a.source
	request.ReplaceSessionID = "00000000000000000000000000000000"
	if w := sourceRequest(t, handler, "/v1/session/prepare", request); w.Code != 409 {
		t.Fatal("wrong old session ID replaced the current session")
	}
	request.ReplaceSessionID = reply.State.SessionID
	b.deny.Store(true)
	if w := sourceRequest(t, handler, "/v1/session/prepare", request); w.Code != 403 {
		t.Fatal("unauthenticated client replaced an owned session")
	}
	b.deny.Store(false)
	state, _ := old.State(context.Background())
	if state.Stopped {
		t.Fatal("rejected replacement stopped active session")
	}
	w = sourceRequest(t, handler, "/v1/session/prepare", request)
	if w.Code != 200 {
		t.Fatal("authenticated owner could not replace abandoned session", w.Body.String())
	}
	if err := json.Unmarshal(w.Body.Bytes(), &reply); err != nil {
		t.Fatal(err)
	}
	state, _ = old.State(context.Background())
	if !state.Stopped || reply.State.SessionID == request.ReplaceSessionID {
		t.Fatal("replacement did not retire exactly the old session")
	}
	if w := sourceRequest(t, handler, "/v1/session/prepare", request); w.Code != 409 {
		t.Fatal("stale replacement request stopped a newer session")
	}
	if w := sourceRequest(t, handler, "/v1/session/commit", sourceControl{ID: reply.State.SessionID}); w.Code != 409 {
		t.Fatal("session retained without encrypted business", w.Code)
	}
	if w := sourceRequest(t, handler, "/v1/session/stop", sourceControl{ID: "00000000000000000000000000000000"}); w.Code != 409 {
		t.Fatal("unowned session stopped")
	}
	if w := sourceRequest(t, handler, "/v1/session/seed", sourceControl{ID: reply.State.SessionID, Packet: make([]byte, 100)}); w.Code != 409 {
		t.Fatal("arbitrary UDP accepted for priming")
	}
	if w := sourceRequest(t, handler, "/v1/session/stop", sourceControl{ID: reply.State.SessionID}); w.Code != 200 {
		t.Fatal(w.Code)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		state, _ := a.source.State(context.Background())
		if state.Stopped {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("server source socket not closed")
}
