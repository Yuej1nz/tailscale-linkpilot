package optimize

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/Yuej1nz/tailscale-linkpilot/internal/mapping"
	"tailscale.com/disco"
	"tailscale.com/tsconst"
)

// A copied ping's pong is attributed by magicsock to sentPing.to, not to the
// address where its pong arrived. Seed only after that original transaction
// has expired, so native clients learn the carrier from an authenticated ping
// and independently probe it. This depends on the supported native protocol;
// native identity, exact endpoint and business verification remain mandatory.
const discoverySeedAge = tsconst.DefaultPingTimeout + time.Second

// The current protocol's unpadded keyed ping is 124 bytes, its pong 110.
// Length is only a conservative seed selector, never authentication. In
// particular, never copy a pong and credit an old destination via a new path.
func seedShape(req mapping.Injection) bool {
	return (req.Direction == "in" || req.Direction == "out") && len(req.Packet) == len(disco.Magic)+32+disco.NonceLen+16+disco.MessageHeaderLen+disco.PingLen
}

type agedSeed struct {
	req mapping.Injection
	due time.Time
}

type discoverySeeder struct {
	mu     sync.Mutex
	seen   map[string]bool
	queue  chan agedSeed
	first  chan struct{}
	done   chan struct{}
	cancel context.CancelFunc
	age    time.Duration
	err    error
}

func newDiscoverySeeder(ctx context.Context, age time.Duration, deliver func(context.Context, mapping.Injection) error) *discoverySeeder {
	ctx, cancel := context.WithCancel(ctx)
	s := &discoverySeeder{seen: make(map[string]bool), queue: make(chan agedSeed, 2), first: make(chan struct{}), done: make(chan struct{}), cancel: cancel, age: age}
	go func() {
		defer close(s.done)
		var once sync.Once
		for {
			select {
			case <-ctx.Done():
				return
			case seed := <-s.queue:
				if err := sleep(ctx, max(0, time.Until(seed.due))); err != nil {
					return
				}
				if ctx.Err() != nil {
					return
				}
				callCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
				err := deliver(callCtx, seed.req)
				cancel()
				once.Do(func() { s.mu.Lock(); s.err = err; s.mu.Unlock(); close(s.first) })
			}
		}
	}()
	return s
}

func (s *discoverySeeder) enqueue(req mapping.Injection) {
	if !seedShape(req) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.seen[req.Direction] {
		return
	}
	s.seen[req.Direction] = true
	req.Packet = append([]byte(nil), req.Packet...)
	s.queue <- agedSeed{req: req, due: time.Now().Add(s.age)}
}

func (s *discoverySeeder) wait(ctx context.Context) error {
	timer := time.NewTimer(s.age + 3*time.Second)
	defer timer.Stop()
	select {
	case <-s.first:
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.err
	case <-s.done:
		return errors.New("discovery seeding stopped")
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return errors.New("no supported native discovery seed observed")
	}
}

func (s *discoverySeeder) stop() { s.cancel(); <-s.done }
