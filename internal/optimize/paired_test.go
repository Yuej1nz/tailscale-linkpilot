package optimize

import (
	"github.com/Yuej1nz/tailscale-linkpilot/internal/mapping"
	"net/netip"
	"testing"
	"time"
)

func TestFreshUnpublishedPeerIPIsNotSilentlyDiscarded(t *testing.T) {
	now := time.Now()
	id := "0123456789abcdef0123456789abcdef"
	in := mapping.Input{PeerID: "server", Peers: []netip.AddrPort{netip.MustParseAddrPort("203.0.113.10:41641")}}
	observation := mapping.Observation{Server: netip.MustParseAddrPort("198.51.100.20:3478"), Mapped: netip.MustParseAddrPort("198.51.100.30:40519"), At: now, SessionID: id}
	reply := sourceReply{State: mapping.State{SelfID: "server", SessionID: id, Local: netip.MustParseAddrPort("203.0.113.10:40519"), Mappings: []mapping.Observation{observation, observation}}}
	candidates := coordinatedCandidates(in, reply, now)
	if len(candidates) != 3 || !candidates[0].Selected || candidates[0].Endpoint != observation.Mapped || candidates[1].Selected || candidates[1].Reason != "duplicate" || !candidates[2].Selected {
		t.Fatalf("lost fresh endpoint or selection provenance: %+v", candidates)
	}
	reply.State.Mappings[0].At = now.Add(-11 * time.Second)
	reply.State.Mappings[1].SessionID = "fedcba9876543210fedcba9876543210"
	candidates = coordinatedCandidates(in, reply, now)
	if candidates[0].Selected || candidates[1].Selected || !candidates[2].Selected {
		t.Fatalf("accepted stale/wrong-session observation: %+v", candidates)
	}
}

func TestBoundedPortPreservingHypothesesRequireFreshEvidence(t *testing.T) {
	now := time.Now()
	id := "0123456789abcdef0123456789abcdef"
	in := mapping.Input{PeerID: "server", Peers: []netip.AddrPort{netip.MustParseAddrPort("203.0.113.11:41641"), netip.MustParseAddrPort("203.0.113.12:41641"), netip.MustParseAddrPort("203.0.113.10:41641"), netip.MustParseAddrPort("192.168.1.20:41641")}}
	o := mapping.Observation{Server: netip.MustParseAddrPort("198.51.100.20:3478"), Mapped: netip.MustParseAddrPort("198.51.100.30:47063"), At: now, SessionID: id}
	reply := sourceReply{State: mapping.State{SelfID: "server", SessionID: id, Local: netip.MustParseAddrPort("203.0.113.10:47063"), Mappings: []mapping.Observation{o}}}
	candidates := coordinatedCandidates(in, reply, now)
	if len(candidates) != 4 {
		t.Fatalf("did not cover public alias candidates: %+v", candidates)
	}
	for _, c := range candidates {
		if !c.Selected || c.Endpoint.Port() != 47063 {
			t.Fatalf("invalid candidate: %+v", c)
		}
	}
	if candidates[1].Origin != "known_peer_ip_port_preserving_hypothesis" {
		t.Fatal("hypothesis presented as observation")
	}
	reply.State.Mappings[0].Mapped = netip.MustParseAddrPort("198.51.100.30:55555")
	if got := coordinatedCandidates(in, reply, now); len(got) != 2 {
		t.Fatalf("guessed local port without preservation evidence: %+v", got)
	}
	reply.State.Mappings[0].At = now.Add(-11 * time.Second)
	if got := coordinatedCandidates(in, reply, now); len(got) != 2 || got[0].Selected {
		t.Fatalf("used expired observation: %+v", got)
	}
}
