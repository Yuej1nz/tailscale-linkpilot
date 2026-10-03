//go:build darwin || linux

package mapping

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestProbeOwnerIPCAuthenticationBoundsAndSameSocket(t *testing.T) {
	home, err := os.MkdirTemp("", "probe-ipc-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(home) })
	t.Setenv("HOME", home)
	dir, _ := runtimeDirectory()
	native, peer := udpFixture(t), udpFixture(t)
	cfg := Config{Input: Input{SelfID: "self", PeerID: "peer", Native: ap(native), SelfDisco: [32]byte{1}, PeerDisco: [32]byte{2}, Peers: []netip.AddrPort{ap(peer)}}, SessionID: randomToken(), Token: randomToken(), Directory: dir, Prepare: 10 * time.Second, Lease: time.Minute}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- ServeWorker(ctx, cfg, func(context.Context, Input) error { return nil }) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	var session *LocalSession
	var state State
	for ctx.Err() == nil {
		session, state, err = Active(ctx)
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatal("worker did not publish owner IPC", err)
	}
	badOwner := localSession(Record{SessionID: cfg.SessionID, Socket: filepath.Join(dir, "control.sock"), Token: randomToken()})
	defer badOwner.http.CloseIdleConnections()
	if err := badOwner.ConfigureProbe(ctx, probeConfig()); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatal("unverified owner configured a probe", err)
	}
	if err := badOwner.Stop(ctx); err == nil {
		t.Fatal("authentication failure was treated as an already closed session")
	}
	oversized := probeConfig()
	oversized.Key = bytes.Repeat([]byte{0xa7}, 2000)
	if err := session.ConfigureProbe(ctx, oversized); err == nil {
		t.Fatal("probe IPC accepted an oversized body")
	}
	if err := session.ConfigureProbe(ctx, probeConfig()); err != nil {
		t.Fatal(err)
	}
	peerCarrier := newSocketCarrier(peer, Input{Peers: []netip.AddrPort{state.Local}}, "peer")
	peerConfig := probeConfig()
	peerConfig.Role = "responder"
	if err := peerCarrier.configureProbe(peerConfig); err != nil {
		t.Fatal(err)
	}
	runCarrier(t, peerCarrier)
	if err := session.Probe(ctx, []netip.AddrPort{ap(peer)}); err != nil {
		t.Fatal(err)
	}
	for ctx.Err() == nil {
		state, err = session.State(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(state.Prevalidation.Results) == 1 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if len(state.Prevalidation.Results) != 1 || state.Prevalidation.Results[0].Target != ap(peer) || peerCarrier.snapshot().Prevalidation.RequestsReceived != 1 {
		t.Fatal("IPC did not operate on actual owned UDP socket", state)
	}
	if err := session.SelectProbe(ctx, ap(peer)); err != nil {
		t.Fatal(err)
	}
	state, err = session.State(ctx)
	if err != nil || state.OutboundPhysical != ap(peer) || state.Physical != ap(peer) || state.Activated || state.Committed {
		t.Fatal("IPC selection changed activation boundary", state, err)
	}
	if err := session.Commit(ctx); err == nil {
		t.Fatal("UDP proof committed a native data path")
	}
	if err := session.Stop(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestUncommittedLeaseClosesSocketAndRemovesController(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir, _ := runtimeDirectory()
	cfg := Config{Input: Input{SelfID: "self", PeerID: "peer", Native: netip.MustParseAddrPort("127.0.0.1:41641"), SelfDisco: [32]byte{1}, PeerDisco: [32]byte{2}, Peers: []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:41642")}}, SessionID: randomToken(), Token: randomToken(), Directory: dir, Prepare: time.Second, Lease: time.Minute}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- ServeWorker(ctx, cfg, func(context.Context, Input) error { return nil }) }()
	var session *LocalSession
	var state State
	for ctx.Err() == nil {
		var err error
		session, state, err = Active(ctx)
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if session == nil {
		t.Fatal("worker failed to publish private controller")
	}
	if err := session.Commit(ctx); err == nil {
		t.Fatal("committed without encrypted business traffic")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := session.Stop(ctx); err != nil {
		t.Fatal("already expired local controller prevented the next source trial", err)
	}
	stoppedCtx, stop := context.WithCancel(context.Background())
	stop()
	if err := session.Stop(stoppedCtx); err == nil {
		t.Fatal("canceled cleanup was silently accepted")
	}
	for _, name := range []string{"control.sock", "active.json"} {
		if _, err := os.Lstat(filepath.Join(dir, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("lease left runtime artifact", name, err)
		}
	}
	c, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(state.Local))
	if err != nil {
		t.Fatal("preparation left an owned UDP socket", err)
	}
	c.Close()
}

func TestPrivateRecordRejectsSymlinksAndPublicPermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "record")
	if err := os.WriteFile(path, []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}
	if privateFile(path) == nil {
		t.Fatal("read a world-readable runtime token")
	}
	os.Chmod(path, 0600)
	alias := filepath.Join(dir, "alias")
	if err := os.Symlink(path, alias); err != nil {
		t.Fatal(err)
	}
	if privateFile(alias) == nil {
		t.Fatal("followed a runtime symlink")
	}
}
