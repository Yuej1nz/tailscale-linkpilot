package diagnostic

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/Yuej1nz/tailscale-linkpilot/internal/model"
)

type fakeAdapter struct {
	report    *model.Report
	calls     []string
	responses []model.PingResult
	errs      []error
}

func (f *fakeAdapter) Snapshot(context.Context) (*model.Report, error) { return f.report, nil }
func (f *fakeAdapter) Ping(_ context.Context, _ netip.Addr, kind string) (model.PingResult, error) {
	i := len(f.calls)
	f.calls = append(f.calls, kind)
	if i >= len(f.responses) {
		return model.PingResult{}, errors.New("unplanned probe")
	}
	var err error
	if i < len(f.errs) {
		err = f.errs[i]
	}
	return f.responses[i], err
}
func reportFixture() *model.Report {
	return &model.Report{SchemaVersion: 1, CollectedAt: time.Now(), BackendState: "Running", Client: model.Client{Capabilities: map[string]model.Capability{}}, Peers: []model.Peer{{Node: model.Node{ID: "test-peer", Name: "example-peer", DNSName: "example-peer.example.invalid", IPs: []string{"100.100.1.2"}}, Path: model.UnknownPath(time.Now(), "status_only")}}}
}
func opts() Options {
	return Options{Peer: "example-peer", Count: 1, Timeout: time.Second, Budget: 3 * time.Second}
}
func direct() model.PingResult {
	return model.PingResult{IP: "100.100.1.2", NodeIP: "100.100.1.2", Endpoint: "203.0.113.8:41641", LatencySeconds: .01}
}

func TestStatusAndPlanNeverProbe(t *testing.T) {
	a := &fakeAdapter{report: reportFixture()}
	r, err := Status(context.Background(), a, "example-peer")
	if err != nil {
		t.Fatal(err)
	}
	if err := Plan(r, "example-peer"); err != nil {
		t.Fatal(err)
	}
	if len(a.calls) != 0 || r.ActiveProbes || r.ConfigurationChanges || r.Plan.ConfigurationChanges {
		t.Fatal("passive command had side effects")
	}
}

func TestLaterTimeoutInvalidatesCurrentPathProof(t *testing.T) {
	a := &fakeAdapter{report: reportFixture(), responses: []model.PingResult{direct(), {}}, errs: []error{nil, context.DeadlineExceeded}}
	o := opts()
	o.Count = 2
	r, err := Diagnose(context.Background(), a, o)
	if err != nil {
		t.Fatal(err)
	}
	if r.Summary.DiscoverySuccesses != 1 || r.Summary.LastProbePath.Type != "unknown" || r.Probes[1].Error.Code != "probe_timeout" {
		t.Fatalf("stale success: %+v", r.Summary)
	}
	if r.Summary.ApplicationVerification != "not_tested" {
		t.Fatal("probe was mistaken for an application test")
	}
}

func TestAmbiguousOrExternalTargetIsRejectedBeforeProbing(t *testing.T) {
	for _, selector := range []string{"example-peer", "203.0.113.1"} {
		a := &fakeAdapter{report: reportFixture()}
		if selector == "example-peer" {
			other := a.report.Peers[0]
			other.ID = "other-node"
			a.report.Peers = append(a.report.Peers, other)
		}
		o := opts()
		o.Peer = selector
		if _, err := Diagnose(context.Background(), a, o); err == nil {
			t.Fatalf("accepted %s", selector)
		}
		if len(a.calls) > 0 {
			t.Fatal("probed before resolving identity")
		}
	}
}

func TestTSMPDoesNotReplaceDiscoveryPathOrProveApplication(t *testing.T) {
	a := &fakeAdapter{report: reportFixture(), responses: []model.PingResult{{IP: "100.100.1.2", NodeIP: "100.100.1.2", DERPRegionID: 1, DERPRegionCode: "example"}, {IP: "100.100.1.2", NodeIP: "100.100.1.2"}}}
	o := opts()
	o.WireGuard = true
	r, err := Diagnose(context.Background(), a, o)
	if err != nil {
		t.Fatal(err)
	}
	if r.Summary.LastProbePath.Type != "derp" || r.Summary.WireGuardReachability != "verified_by_tsmp" || r.Summary.ApplicationVerification != "not_tested" {
		t.Fatalf("overclaimed path: %+v", r.Summary)
	}
}

func TestIdentityMismatchIsNotSuccess(t *testing.T) {
	v := direct()
	v.NodeIP = "100.100.9.9"
	a := &fakeAdapter{report: reportFixture(), responses: []model.PingResult{v}}
	r, err := Diagnose(context.Background(), a, opts())
	if err != nil {
		t.Fatal(err)
	}
	if r.Summary.DiscoverySuccesses != 0 || r.Probes[0].Error.Code != "identity_mismatch" {
		t.Fatal("wrong node accepted")
	}
}

func TestPlanDoesNotReuseOtherPeersSavedProbes(t *testing.T) {
	r := reportFixture()
	r.Target = &model.Node{ID: "different"}
	r.Probes = []model.Probe{{Kind: "disco"}}
	if Plan(r, "example-peer") == nil {
		t.Fatal("cross-peer probe reuse")
	}
}
