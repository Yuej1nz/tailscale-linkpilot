package optimize

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Yuej1nz/tailscale-linkpilot/internal/mapping"
)

func TestDiscoverySeedsExpireOriginalTransactionsAndRejectPongs(t *testing.T) {
	// Model the native transaction that would wrongly credit its original
	// destination if a copied ping were answered while still outstanding.
	started := time.Now()
	transactionExpires := started.Add(30 * time.Millisecond)
	received := make(chan mapping.Injection, 3)
	s := newDiscoverySeeder(context.Background(), 60*time.Millisecond, func(_ context.Context, req mapping.Injection) error {
		if time.Now().Before(transactionExpires) {
			t.Error("copied pong can still credit the old native destination")
		}
		received <- req
		return nil
	})
	defer s.stop()
	s.enqueue(mapping.Injection{Direction: "out", Packet: make([]byte, 110)})
	s.enqueue(mapping.Injection{Direction: "in", Packet: make([]byte, 110)})
	s.enqueue(mapping.Injection{Direction: "invalid", Packet: make([]byte, 124)})
	packet := make([]byte, 124)
	packet[0] = 42
	for i := 0; i < 20; i++ {
		s.enqueue(mapping.Injection{Direction: "out", Packet: packet})
	}
	packet[0] = 99
	s.enqueue(mapping.Injection{Direction: "in", Packet: make([]byte, 124)})
	select {
	case <-received:
		t.Fatal("seed transmitted before transaction expiry")
	case <-time.After(20 * time.Millisecond):
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.wait(ctx); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		select {
		case req := <-received:
			if req.Direction == "out" && req.Packet[0] != 42 {
				t.Fatal("capture buffer reused after enqueue")
			}
		case <-ctx.Done():
			t.Fatal("missing aged direction")
		}
	}
	select {
	case <-received:
		t.Fatal("duplicated seed or forwarded pong")
	case <-time.After(10 * time.Millisecond):
	}
}

func TestDiscoverySeederCancellationAndDeliveryFailure(t *testing.T) {
	t.Run("cancel_pending", func(t *testing.T) {
		s := newDiscoverySeeder(context.Background(), time.Second, func(context.Context, mapping.Injection) error { t.Error("sent seed after cleanup"); return nil })
		s.enqueue(mapping.Injection{Direction: "out", Packet: make([]byte, 124)})
		s.stop()
		if err := s.wait(context.Background()); err == nil {
			t.Fatal("canceled seed reported success")
		}
	})
	t.Run("delivery_failure", func(t *testing.T) {
		want := errors.New("session disappeared")
		s := newDiscoverySeeder(context.Background(), time.Millisecond, func(context.Context, mapping.Injection) error { return want })
		defer s.stop()
		s.enqueue(mapping.Injection{Direction: "out", Packet: make([]byte, 124)})
		if err := s.wait(context.Background()); !errors.Is(err, want) {
			t.Fatal("lost first delivery failure", err)
		}
	})
}
