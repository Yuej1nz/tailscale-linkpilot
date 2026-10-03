package product

import (
	"github.com/Yuej1nz/tailscale-linkpilot/internal/model"
	"time"
)

type trafficSample struct {
	rx, tx       int64
	at           time.Time
	ignoredWrite time.Time
}
type activityTracker struct {
	generation string
	peers      map[string]trafficSample
}

func (a *activityTracker) reset(generation string) {
	if a.peers == nil || a.generation != generation {
		a.generation = generation
		a.peers = map[string]trafficSample{}
	}
}
func (a *activityTracker) observe(now time.Time, generation string, peer model.Peer) bool {
	a.reset(generation)
	old, known := a.peers[peer.ID]
	at := old.at
	if known && (peer.RxBytes < old.rx || peer.TxBytes < old.tx) {
		at = time.Time{}
	} else if known && (peer.RxBytes > old.rx || peer.TxBytes > old.tx) {
		at = now
	}
	a.peers[peer.ID] = trafficSample{rx: peer.RxBytes, tx: peer.TxBytes, at: at, ignoredWrite: old.ignoredWrite}
	native := peer.Active && peer.Path.LastTrafficAt != nil && peer.Path.LastTrafficAt.After(old.ignoredWrite) && !peer.Path.LastTrafficAt.After(now) && now.Sub(*peer.Path.LastTrafficAt) < 30*time.Second
	return native || !at.IsZero() && now.Sub(at) < 30*time.Second
}
func (a *activityTracker) settle(generation string, peers []model.Peer) {
	a.reset(generation)
	for _, p := range peers {
		old := a.peers[p.ID]
		ignored := old.ignoredWrite
		if p.Path.LastTrafficAt != nil {
			ignored = *p.Path.LastTrafficAt
		}
		a.peers[p.ID] = trafficSample{rx: p.RxBytes, tx: p.TxBytes, at: old.at, ignoredWrite: ignored}
	}
}
