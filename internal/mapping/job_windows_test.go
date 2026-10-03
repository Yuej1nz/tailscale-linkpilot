package mapping

import (
	"context"
	"golang.org/x/sys/windows"
	"net/netip"
	"os"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "session-worker" && os.Getenv("TSLINK_TEST_WORKER") == "1" {
		cfg, err := ReadWorkerConfig()
		if err == nil {
			err = ServeWorker(context.Background(), cfg, func(context.Context, Input) error { return nil })
		}
		if err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestManagedWorkerStartsInsideNonBreakawayJob(t *testing.T) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(job)
	if err = windows.AssignProcessToJobObject(job, windows.CurrentProcess()); err != nil {
		t.Fatal(err)
	}
	home, err := os.MkdirTemp("", "job-ipc-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("TSLINK_TEST_WORKER", "1")
	native, peer := udpFixture(t), udpFixture(t)
	in := Input{SelfID: "fixture-self", PeerID: "fixture-peer", Native: ap(native), Peers: []netip.AddrPort{ap(peer)}, SelfDisco: [32]byte{1}, PeerDisco: [32]byte{2}}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	t.Setenv("TSLINK_MANAGED_WORKER", "")
	if s, err := Spawn(ctx, in, nil, 5*time.Second, time.Minute); err == nil {
		s.Stop(ctx)
		t.Fatal("standalone worker bypassed non-breakaway job")
	}
	t.Setenv("TSLINK_MANAGED_WORKER", "1")
	s, err := Spawn(ctx, in, nil, 5*time.Second, time.Minute)
	if err != nil {
		t.Fatal("managed job rejected carrier", err)
	}
	state, err := s.State(ctx)
	if err != nil || state.SelfID != in.SelfID || state.Local == in.Native {
		t.Fatal("carrier IPC not ready", state, err)
	}
	if err = s.Stop(ctx); err != nil {
		t.Fatal(err)
	}
}
