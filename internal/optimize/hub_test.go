package optimize

import (
	"context"
	"github.com/Yuej1nz/tailscale-linkpilot/internal/model"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

type hubFixture struct{ *testBackend }

func (f *hubFixture) Snapshot(ctx context.Context) (*model.Report, error) {
	r, e := f.testBackend.Snapshot(ctx)
	r.Peers = []model.Peer{{Node: model.Node{ID: "alice", IPs: []string{"127.0.0.1"}}}, {Node: model.Node{ID: "bob", IPs: []string{"127.0.0.2"}}}, {Node: model.Node{ID: "guest", IPs: []string{"127.0.0.3"}}}}
	return r, e
}
func (f *hubFixture) WhoIsID(_ context.Context, address string) (string, error) {
	if strings.HasPrefix(address, "127.0.0.2:") {
		return "bob", nil
	}
	if strings.HasPrefix(address, "127.0.0.3:") {
		return "guest", nil
	}
	return "alice", nil
}
func TestHubAuthorizationPerPeerStateAndRevocation(t *testing.T) {
	b := &hubFixture{&testBackend{self: "server", direct: &atomic.Bool{}}}
	allowed := map[string]bool{"alice": true, "bob": true}
	h, e := NewHub(context.Background(), b, "fixture", func(id string) bool { return allowed[id] })
	if e != nil {
		t.Fatal(e)
	}
	defer h.Close()
	request := func(ip, path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", path, nil)
		r.RemoteAddr = ip + ":1234"
		w := httptest.NewRecorder()
		h.Handler().ServeHTTP(w, r)
		return w
	}
	for _, ip := range []string{"127.0.0.1", "127.0.0.2"} {
		if w := request(ip, "/v1/hello"); w.Code != 200 {
			t.Fatal(w.Code, w.Body)
		}
	}
	if len(h.peers) != 2 || h.peers["alice"] == h.peers["bob"] {
		t.Fatal("carrier state shared between peers")
	}
	if w := request("127.0.0.3", "/v1/hello"); w.Code != 403 {
		t.Fatal("tailnet membership granted refresh permission")
	}
	if w := request("127.0.0.3", "/product/v1/info"); w.Code != 200 || !strings.Contains(w.Body.String(), `"authorized":false`) {
		t.Fatal("unauthorized discovery failed")
	}
	delete(allowed, "alice")
	h.Sweep()
	if len(h.peers) != 1 {
		t.Fatal("revoked carrier remained registered")
	}
	if w := request("127.0.0.1", "/v1/hello"); w.Code != 403 {
		t.Fatal("revoked node still authorized")
	}
	b.self = "another"
	if w := request("127.0.0.2", "/v1/hello"); w.Code != 409 {
		t.Fatal("account switch did not suspend hub")
	}
}
