package mapping

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"time"
)

// Embedded uses only an ordinary user's socket. Its lifetime is bounded by
// both the assistant process and a lease, with no capture or native changes.
type Embedded struct {
	c      *socketCarrier
	cancel context.CancelFunc
	done   chan struct{}
	lease  time.Duration
	once   sync.Once
}

func NewEmbedded(ctx context.Context, input Input, tried []uint16, prepare, lease time.Duration, check func(context.Context, Input) error) (*Embedded, error) {
	if prepare <= 0 || prepare > 180*time.Second || lease < time.Minute || lease > 24*time.Hour {
		return nil, errors.New("invalid embedded lease")
	}
	conn, err := freshSocket(input.Native.Addr(), input.Native.Port(), tried)
	if err != nil {
		return nil, err
	}
	workerCtx, cancel := context.WithCancel(ctx)
	s := &Embedded{c: newSocketCarrier(conn, input, randomToken()), cancel: cancel, done: make(chan struct{}), lease: lease}
	s.c.state.ExpiresAt = time.Now().Add(prepare)
	go func() {
		if err := s.c.read(workerCtx); err != nil && workerCtx.Err() == nil {
			s.stop("udp_socket_failed")
		}
	}()
	go func() {
		defer close(s.done)
		tick := time.NewTicker(2 * time.Second)
		defer tick.Stop()
		defer s.stop("assistant_stopped")
		for {
			select {
			case <-workerCtx.Done():
				return
			case <-tick.C:
				state := s.c.snapshot()
				if time.Now().After(state.ExpiresAt) {
					s.stop("lease_expired")
					return
				}
				if check != nil {
					x, done := context.WithTimeout(workerCtx, 3*time.Second)
					err := check(x, input)
					done()
					if err != nil {
						s.stop("identity_or_network_changed")
						return
					}
				}
			}
		}
	}()
	return s, nil
}
func (s *Embedded) stop(reason string) {
	s.once.Do(func() {
		s.c.mu.Lock()
		s.c.state.Stopped = true
		s.c.state.StopReason = reason
		s.c.mu.Unlock()
		s.cancel()
		_ = s.c.conn.Close()
	})
}
func (s *Embedded) State(context.Context) (State, error) { return s.c.snapshot(), nil }
func (s *Embedded) Inject(ctx context.Context, in Injection) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return s.c.inject(in)
}
func (s *Embedded) STUN(ctx context.Context) error { return s.c.restun(ctx) }
func (s *Embedded) AddPeer(ctx context.Context, endpoint netip.AddrPort) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return s.c.addPeer(endpoint)
}
func (s *Embedded) ConfigureProbe(ctx context.Context, config ProbeConfig) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return s.c.configureProbe(config)
}
func (s *Embedded) Probe(ctx context.Context, endpoints []netip.AddrPort) error {
	return s.c.sendProbe(ctx, endpoints)
}
func (s *Embedded) SelectProbe(ctx context.Context, endpoint netip.AddrPort) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return s.c.selectProbe(endpoint)
}
func (s *Embedded) Activate(ctx context.Context, ap netip.AddrPort) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return s.c.activate(ap)
}
func (s *Embedded) Commit(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	s.c.mu.Lock()
	defer s.c.mu.Unlock()
	if s.c.state.Stopped || !s.c.state.Activated || s.c.state.Counters.DataOut == 0 || s.c.state.Counters.DataIn == 0 {
		return errors.New("embedded session has not carried verified encrypted data")
	}
	if !s.c.state.Committed {
		s.c.state.Committed = true
		s.c.state.ExpiresAt = time.Now().Add(s.lease)
	}
	return nil
}
func (s *Embedded) Stop(ctx context.Context) error {
	s.stop("stopped_by_owner")
	select {
	case <-s.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Embedded) Renew(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	s.c.mu.Lock()
	defer s.c.mu.Unlock()
	if s.c.state.Stopped || !s.c.state.Committed || !s.c.state.Activated || time.Now().After(s.c.state.ExpiresAt) {
		return errors.New("only a live committed carrier can be renewed")
	}
	s.c.state.ExpiresAt = time.Now().Add(s.lease)
	return nil
}
