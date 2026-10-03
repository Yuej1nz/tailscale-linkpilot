package product

import (
	"testing"
	"time"
)

func TestRelayRequiresSustainedActiveConfirmation(t *testing.T) {
	now := time.Now()
	p := &Policy{}
	if p.Observe(now, "a", "derp", true, 0) || p.Observe(now.Add(10*time.Second), "a", "derp", true, 0) {
		t.Fatal("optimized transient relay")
	}
	if !p.Observe(now.Add(20*time.Second), "a", "derp", true, 0) {
		t.Fatal("did not trigger sustained relay")
	}
	p.Complete(now.Add(20*time.Second), false)
	for i := 1; i <= 3; i++ {
		if p.Observe(now.Add(time.Duration(20+i*10)*time.Second), "a", "derp", true, 0) {
			t.Fatal("ignored failure backoff")
		}
	}
	if !p.Observe(now.Add(80*time.Second), "a", "derp", true, 0) {
		t.Fatal("never left cooldown")
	}
	p.Observe(now.Add(81*time.Second), "a", "derp", false, 0)
	if p.RelaySamples != 0 {
		t.Fatal("idle interval retained relay confirmation")
	}
}
func TestNetworkChangeManualRequestAndFailureBackoff(t *testing.T) {
	p := &Policy{}
	now := time.Now()
	if !p.Observe(now, "a", "unknown", false, 1) {
		t.Fatal("manual optimization requires active traffic")
	}
	if p.Observe(now, "a", "unknown", false, 1) {
		t.Fatal("manual request replayed")
	}
	p.Complete(now, false)
	if p.NextTry.Sub(now) != time.Minute {
		t.Fatal(p)
	}
	p.Complete(now, false)
	if p.NextTry.Sub(now) != 5*time.Minute {
		t.Fatal(p)
	}
	p.Complete(now, false)
	if p.NextTry.Sub(now) != 15*time.Minute {
		t.Fatal(p)
	}
	if p.Observe(now, "b", "derp", true, 1) || p.Failures != 0 || p.RelaySamples != 1 {
		t.Fatal("network change did not reset old evidence")
	}
	if !p.Observe(now, "b", "direct", false, 2) {
		t.Fatal("explicit request did not override cooldown")
	}
}
