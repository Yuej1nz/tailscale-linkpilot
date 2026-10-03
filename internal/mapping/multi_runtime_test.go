package mapping

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestPeerScopedWorkersAndLegacyWorkerRemainIndependent(t *testing.T) {
	home, err := os.MkdirTemp(runtimeTestTemp(), "tsm-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(home) })
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", home)
	} else {
		t.Setenv("HOME", home)
	}
	root, err := runtimeDirectory()
	if err != nil {
		t.Fatal(err)
	}
	if err := privateDirectory(root, true); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	workers := []chan error{}
	defer func() {
		cancel()
		for _, done := range workers {
			if err := <-done; err != nil {
				t.Error(err)
			}
		}
	}()
	sessions := map[string]*LocalSession{}
	states := map[string]State{}
	ids := []string{"first", "second", "legacy"}
	for i := len(ids); i < MaxLocalSessions; i++ {
		ids = append(ids, fmt.Sprintf("peer-%02d", i))
	}
	for _, id := range ids {
		dir := root
		if id != "legacy" {
			dir, err = peerDirectory("self", id)
			if err != nil {
				t.Fatal(err)
			}
		}
		native, remote := udpFixture(t), udpFixture(t)
		cfg := Config{Input: Input{SelfID: "self", PeerID: id, Native: ap(native), SelfDisco: [32]byte{1}, PeerDisco: [32]byte{2}, Peers: []netip.AddrPort{ap(remote)}}, SessionID: randomToken(), Token: randomToken(), Directory: dir, Prepare: 30 * time.Second, Lease: time.Minute}
		done := make(chan error, 1)
		workers = append(workers, done)
		go func() { done <- ServeWorker(ctx, cfg, func(context.Context, Input) error { return nil }) }()
		for ctx.Err() == nil {
			session, state, e := ActiveFor(ctx, "self", id)
			if e == nil && state.SessionID == cfg.SessionID {
				sessions[id], states[id] = session, state
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if sessions[id] == nil {
			t.Fatal("peer worker did not publish independent control", id)
		}
	}
	if states["first"].Local == states["second"].Local || states["first"].SessionID == states["second"].SessionID {
		t.Fatal("shared peer carrier ownership")
	}
	if _, _, err := ActiveFor(ctx, "other-self", "first"); err == nil {
		t.Fatal("carrier returned across a local identity boundary")
	}
	if _, err := prepareSessionDirectory(ctx, Input{SelfID: "self", PeerID: "first"}); err == nil {
		t.Fatal("responsive peer session could be replaced")
	}
	if _, err := prepareSessionDirectory(ctx, Input{SelfID: "self", PeerID: "third"}); err == nil {
		t.Fatal("carrier budget was exceeded")
	}
	if err := sessions["second"].Stop(ctx); err != nil {
		t.Fatal(err)
	}
	for ctx.Err() == nil {
		if _, err := sessions["second"].State(ctx); err != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	for _, id := range ids {
		if id == "second" {
			continue
		}
		if state, err := sessions[id].State(ctx); err != nil || state.Stopped {
			t.Fatal("stopping another peer closed this carrier", id, err)
		}
	}
	if _, err := prepareSessionDirectory(ctx, Input{SelfID: "self", PeerID: "third"}); err != nil {
		t.Fatal("another peer blocked new allocation", err)
	}
	if _, _, err := ActiveFor(ctx, "self", "second"); err == nil {
		t.Fatal("stopped peer resolved to another live carrier")
	}
	if _, err := os.Lstat(filepath.Join(root, "active.json")); err != nil {
		t.Fatal("new peer cleanup removed legacy record", err)
	}
}

func TestPeerRuntimePathIsBoundToIdentitiesAndRejectsArbitraryDirectory(t *testing.T) {
	home, err := os.MkdirTemp(runtimeTestTemp(), "tsp-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(home) })
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", home)
	} else {
		t.Setenv("HOME", home)
	}
	first, _ := peerDirectory("self", "peer")
	other, _ := peerDirectory("self", "other")
	if first == other || len(filepath.Base(first)) != 16 {
		t.Fatal("peer-scoped path is not isolated")
	}
	if _, err := peerDirectory("self", ""); err == nil {
		t.Fatal("unbound worker directory accepted")
	}
	native, remote := udpFixture(t), udpFixture(t)
	cfg := Config{Input: Input{SelfID: "self", PeerID: "peer", Native: ap(native), SelfDisco: [32]byte{1}, PeerDisco: [32]byte{2}, Peers: []netip.AddrPort{ap(remote)}}, SessionID: randomToken(), Token: randomToken(), Directory: t.TempDir(), Prepare: time.Second, Lease: time.Minute}
	if err := ServeWorker(context.Background(), cfg, func(context.Context, Input) error { return nil }); err == nil {
		t.Fatal("worker accepted an arbitrary control directory")
	}
}

func runtimeTestTemp() string {
	// Darwin's default TMPDIR already occupies much of sockaddr_un's limit.
	if runtime.GOOS == "darwin" {
		return "/tmp"
	}
	return ""
}
