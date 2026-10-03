package mapping

import (
	"bytes"
	"context"
	"golang.org/x/sys/windows"
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
	t.Setenv("USERPROFILE", home)
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

func TestWindowsRuntimeACLRejectsPublicAccess(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	if err := privateDirectory(dir, true); err != nil {
		t.Fatal(err)
	}
	if err := privateDirectory(dir, false); err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	if err := privateDirectory(dir, false); err == nil {
		t.Fatal("public runtime ACL accepted")
	}
}
