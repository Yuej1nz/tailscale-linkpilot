package product

import "time"

// Policy is independent of network IO so relay confirmation, cooldown and
// network transitions can be verified without a real NAT.
type Policy struct {
	Generation   string
	RelaySince   time.Time
	RelaySamples int
	Failures     int
	NextTry      time.Time
	LastRequest  int64
}

func (p *Policy) Observe(now time.Time, generation, path string, active bool, request int64) bool {
	if generation != p.Generation {
		*p = Policy{Generation: generation, LastRequest: p.LastRequest}
	}
	if request > p.LastRequest {
		p.LastRequest = request
		return true
	}
	if path != "derp" && path != "peer_relay" {
		p.RelaySince = time.Time{}
		p.RelaySamples = 0
		return false
	}
	if !active {
		p.RelaySince = time.Time{}
		p.RelaySamples = 0
		return false
	}
	if p.RelaySince.IsZero() {
		p.RelaySince = now
	}
	p.RelaySamples++
	return p.RelaySamples >= 3 && now.Sub(p.RelaySince) >= 20*time.Second && !now.Before(p.NextTry)
}
func (p *Policy) Complete(now time.Time, success bool) {
	p.RelaySamples = 0
	p.RelaySince = time.Time{}
	if success {
		p.Failures = 0
		p.NextTry = now.Add(time.Minute)
		return
	}
	p.Failures++
	delay := time.Minute
	if p.Failures == 2 {
		delay = 5 * time.Minute
	}
	if p.Failures >= 3 {
		delay = 15 * time.Minute
	}
	p.NextTry = now.Add(delay)
}
