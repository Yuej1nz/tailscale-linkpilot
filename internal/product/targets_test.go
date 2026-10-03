package product

import (
	"bytes"
	"context"
	"testing"

	"github.com/Yuej1nz/tailscale-linkpilot/internal/model"
)

func peerList(ids ...string) *model.Report {
	s := &model.Report{BackendState: "Running", Self: model.Node{ID: "self"}}
	for _, id := range ids {
		s.Peers = append(s.Peers, model.Peer{Node: model.Node{ID: id, Name: "name-" + id}})
	}
	return s
}

func TestAllPeersDiscoveryPreservesUserChoicesAndAuthorization(t *testing.T) {
	c := Config{Schema: 1, SelfID: "self", AllPeers: true, Allowed: []string{"explicitly-authorized"}, Excluded: []string{"excluded"}, Targets: []Target{
		{ID: "explicit", Name: "old", Enabled: true, Requested: 123},
		{ID: "paused", Enabled: false, Automatic: true},
		{ID: "departed", Enabled: true, Automatic: true},
	}}
	s := peerList("new", "paused", "excluded", "explicit", "self", "")
	if !c.reconcile(s) || len(c.Targets) != 3 {
		t.Fatal("unexpected discovery result", c.Targets)
	}
	if c.Authorizes("new") || len(c.Allowed) != 1 {
		t.Fatal("node discovery implicitly granted incoming permissions")
	}
	for _, id := range []string{"new", "paused", "explicit"} {
		target, err := c.Find(id)
		if err != nil {
			t.Fatal(err)
		}
		switch id {
		case "new":
			if !target.Enabled || !target.Automatic || target.Requested != 0 {
				t.Fatal("new idle node forced an optimization", target)
			}
		case "paused":
			if target.Enabled {
				t.Fatal("discovery undid a pause")
			}
		case "explicit":
			if target.Automatic || target.Requested != 123 || target.Name != "name-explicit" {
				t.Fatal("explicit configuration lost", target)
			}
		}
	}
	if c.reconcile(s) {
		t.Fatal("unchanged snapshot caused another config write")
	}
	c.exclude("new")
	if !c.reconcile(s) || len(c.Targets) != 2 || c.reconcile(s) {
		t.Fatal("disconnected automatic target was rediscovered")
	}
	c.include("new")
	if !c.reconcile(s) {
		t.Fatal("explicit reconnection did not remove exclusion")
	}
	if !c.reconcile(peerList()) || len(c.Targets) != 1 || c.Targets[0].ID != "explicit" {
		t.Fatal("removed nodes persisted or explicit target vanished", c.Targets)
	}
}

func TestAllPeersCannotMigrateToAnotherIdentity(t *testing.T) {
	c := Config{Schema: 1, SelfID: "other", AllPeers: true}
	if c.reconcile(peerList("new")) || len(c.Targets) != 0 {
		t.Fatal("automatic selection crossed an identity boundary")
	}
	c.SelfID = "self"
	s := peerList("new")
	s.BackendState = "Stopped"
	if c.reconcile(s) {
		t.Fatal("stopped native client changed selection")
	}
}

func TestConnectAllPersistsWithoutForcingTrafficOrGrantingPermissions(t *testing.T) {
	s := Store{t.TempDir()}
	if err := s.SaveStatus(Status{SelfID: "self", Version: Version}); err != nil {
		t.Fatal(err)
	}
	if err := s.Pulse("self"); err != nil {
		t.Fatal(err)
	}
	var out, errs bytes.Buffer
	if code := connectAll(context.Background(), s, peerList("a", "b"), []string{"--all"}, &out, &errs); code != 0 {
		t.Fatal(code, errs.String())
	}
	c, err := s.Config()
	if err != nil || !c.AllPeers || len(c.Targets) != 2 || len(c.Allowed) != 0 {
		t.Fatal(c, err)
	}
	for _, target := range c.Targets {
		if target.Requested != 0 {
			t.Fatal("bulk selection scheduled unsolicited heavy IO")
		}
	}
	if connectAll(context.Background(), s, peerList("c"), []string{"--all", "--ssh", "login"}, &out, &errs) != 2 {
		t.Fatal("bulk deployment unexpectedly accepted")
	}
	if len(c.Targets) != 2 {
		t.Fatal("invalid CLI arguments changed selection")
	}
	other := peerList("c")
	other.Self.ID = "other"
	if connectAll(context.Background(), s, other, []string{"--all"}, &out, &errs) != 1 {
		t.Fatal("CLI migrated another account's automatic selection")
	}
}

func TestTargetNamesCannotSelectAnAmbiguousDevice(t *testing.T) {
	c := Config{Targets: []Target{{ID: "a", Name: "same"}, {ID: "b", Name: "same"}}}
	if _, err := c.Find("same"); err == nil {
		t.Fatal("ambiguous name selected arbitrary node")
	}
	if target, err := c.Find("b"); err != nil || target.ID != "b" {
		t.Fatal(target, err)
	}
}

func TestAllControlsPreserveIndividualPauseExclusionsAndIncomingGrants(t *testing.T) {
	c := Config{Schema: 1, SelfID: "self", AllPeers: true, Allowed: []string{"incoming-only"}}
	c.reconcile(peerList("a", "b"))
	for _, operation := range []struct{ command, selector string }{{"pause", "a"}, {"pause", "--all"}, {"resume", "--all"}} {
		if _, _, err := applyTargetCommand(&c, operation.command, operation.selector, 123); err != nil {
			t.Fatal(err)
		}
	}
	a, _ := c.Find("a")
	b, _ := c.Find("b")
	if c.Paused || a.Enabled || !b.Enabled {
		t.Fatal("global resume undid an individual pause")
	}
	if _, _, err := applyTargetCommand(&c, "disconnect", "b", 123); err != nil {
		t.Fatal(err)
	}
	c.reconcile(peerList("a", "b", "new"))
	if !c.excludes("b") || len(c.Targets) != 2 {
		t.Fatal("disconnected node was added back")
	}
	if _, _, err := applyTargetCommand(&c, "optimize", "--all", 123); err == nil {
		t.Fatal("unsolicited bulk optimization accepted")
	}
	if _, _, err := applyTargetCommand(&c, "disconnect", "--all", 123); err != nil {
		t.Fatal(err)
	}
	if c.AllPeers || len(c.Targets) != 0 || len(c.Excluded) != 0 || !c.Authorizes("incoming-only") {
		t.Fatal("bulk disconnect changed incoming responder authorization", c)
	}
	if c.reconcile(peerList("new")) {
		t.Fatal("disconnected mode kept discovering nodes")
	}
}

func TestManualResultCannotBeOverwrittenByALaterDirectProbe(t *testing.T) {
	s := Store{t.TempDir()}
	state := State{ID: "peer", Name: "peer", Phase: "direct", Path: "direct", Requested: 123,
		LastOptimization: &Completion{Request: 123, Outcome: "relay_or_unproven_path_application_available", DirectVerified: false}}
	if err := s.SaveStatus(Status{States: []State{state}}); err != nil {
		t.Fatal(err)
	}
	var out, errs bytes.Buffer
	if code := waitOptimization(context.Background(), s, "peer", 123, &out, &errs); code != 1 {
		t.Fatal("later native direct observation falsely proved a failed optimization", code, out.String())
	}
	state.Phase = "idle"
	state.LastOptimization = &Completion{Request: 123, Outcome: "direct_after_recovery", DirectVerified: true}
	if err := s.SaveStatus(Status{States: []State{state}}); err != nil {
		t.Fatal(err)
	}
	if code := waitOptimization(context.Background(), s, "peer", 123, &out, &errs); code != 0 {
		t.Fatal("idle observation erased a verified completion", code)
	}
}
