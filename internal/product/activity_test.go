package product

import (
	"github.com/Yuej1nz/tailscale-linkpilot/internal/model"
	"testing"
	"time"
)

func TestActivityTracksBusinessWhenNativeTimestampIsStale(t *testing.T) {
	now := time.Now()
	stale := now.Add(-time.Hour)
	p := model.Peer{Node: model.Node{ID: "peer"}, Active: true, RxBytes: 100, TxBytes: 100, Path: model.Path{LastTrafficAt: &stale}}
	var a activityTracker
	a.settle("wifi1", []model.Peer{p})
	if a.observe(now, "wifi1", p) {
		t.Fatal("old status activated demand")
	}
	p.RxBytes += 64 * 1024
	if !a.observe(now, "wifi1", p) {
		t.Fatal("real business increment missed with stale LastWrite")
	}
	// Exclude our own verification traffic, without renewing the demand clock.
	p.RxBytes += 64 * 1024
	p.TxBytes += 64 * 1024
	a.settle("wifi1", []model.Peer{p})
	if a.observe(now.Add(31*time.Second), "wifi1", p) {
		t.Fatal("own probes kept demand alive")
	}
	p.RxBytes += 64 * 1024
	if !a.observe(now.Add(32*time.Second), "wifi1", p) {
		t.Fatal("new business missed")
	}
	if a.observe(now.Add(33*time.Second), "wifi2", p) {
		t.Fatal("old demand migrated across networks")
	}
	p.RxBytes = 0
	p.TxBytes = 0
	if a.observe(now.Add(34*time.Second), "wifi2", p) {
		t.Fatal("counter reset activated demand")
	}
	// LastWrite can also be advanced by our own control-plane traffic. Settling
	// excludes that timestamp, not just its bytes.
	fresh := now.Add(35 * time.Second)
	p.Path.LastTrafficAt = &fresh
	a.settle("wifi2", []model.Peer{p})
	if a.observe(now.Add(36*time.Second), "wifi2", p) {
		t.Fatal("own LastWrite activated demand")
	}
}
