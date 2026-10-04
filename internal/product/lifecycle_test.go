package product

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type fakeService struct {
	running           bool
	starts, stops     int
	startErr, stopErr error
	onStart           func()
	keepRunning       bool
}

func (f *fakeService) Running(context.Context) (bool, error) { return f.running, nil }
func (f *fakeService) Start(context.Context) error {
	f.starts++
	if f.startErr != nil {
		return f.startErr
	}
	f.running = true
	if f.onStart != nil {
		f.onStart()
	}
	return nil
}
func (f *fakeService) Stop(context.Context) error {
	f.stops++
	if f.stopErr != nil {
		return f.stopErr
	}
	if !f.keepRunning {
		f.running = false
	}
	return nil
}

func lifecycleStore(t *testing.T) Store {
	t.Helper()
	s := Store{t.TempDir()}
	if err := s.Update(func(c *Config) error {
		c.SelfID, c.AllPeers, c.Paused = "self", true, true
		c.Allowed = []string{"incoming"}
		c.Excluded = []string{"excluded"}
		c.Targets = []Target{{ID: "peer", Enabled: false, Requested: 321}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveStatus(Status{Version: Version, SelfID: "self"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Pulse("self"); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestServiceLifecycleIsIdempotentAndPreservesUserConfiguration(t *testing.T) {
	s := lifecycleStore(t)
	before, _ := os.ReadFile(filepath.Join(s.Dir, "config.json"))
	f := &fakeService{running: true}
	var out bytes.Buffer
	for range 2 {
		if err := controlService(context.Background(), s, "start", f, &out); err != nil {
			t.Fatal(err)
		}
	}
	if f.starts != 0 || f.stops != 0 {
		t.Fatal("repeated start interrupted the existing daemon")
	}
	for range 2 {
		if err := controlService(context.Background(), s, "stop", f, &out); err != nil {
			t.Fatal(err)
		}
		if s.Online("self") {
			t.Fatal("stopped service still reported online from its old heartbeat")
		}
	}
	f.onStart = func() {
		// A real daemon starts asynchronously. Let the Windows wall clock
		// advance too: a synchronous fake can share the start marker's tick.
		time.Sleep(25 * time.Millisecond)
		if err := s.Pulse("self"); err != nil {
			t.Error(err)
		}
	}
	if err := controlService(context.Background(), s, "start", f, &out); err != nil {
		t.Fatal(err)
	}
	if err := controlService(context.Background(), s, "restart", f, &out); err != nil {
		t.Fatal(err)
	}
	if f.starts != 2 || f.stops != 3 || !s.Online("self") {
		t.Fatal("wrong lifecycle", f)
	}
	after, _ := os.ReadFile(filepath.Join(s.Dir, "config.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("lifecycle changed targets, pauses, exclusions or incoming grants")
	}
}

func TestServiceStartCannotUseStaleHeartbeatOrAnotherIdentity(t *testing.T) {
	for _, identity := range []string{"self", "other"} {
		t.Run(identity, func(t *testing.T) {
			s := lifecycleStore(t)
			f := &fakeService{}
			f.onStart = func() {
				pulse := Heartbeat{SelfID: identity, At: time.Now().Add(-time.Second)}
				if identity == "other" {
					pulse.At = time.Now()
					_ = s.SaveStatus(Status{SelfID: identity, Version: Version})
				}
				_ = writeJSONFile(filepath.Join(s.Dir, "heartbeat.json"), pulse)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			if err := controlService(ctx, s, "start", f, &bytes.Buffer{}); err == nil {
				t.Fatal("accepted stale state or another account's live heartbeat")
			}
		})
	}
}

func TestStopFailureDoesNotEraseLiveHeartbeat(t *testing.T) {
	for _, failure := range []string{"denied", "still_running"} {
		t.Run(failure, func(t *testing.T) {
			s := lifecycleStore(t)
			f := &fakeService{running: true, keepRunning: true}
			if failure == "denied" {
				f.stopErr = errors.New("access denied")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			if err := controlService(ctx, s, "stop", f, &bytes.Buffer{}); err == nil || !s.Online("self") {
				t.Fatal("failed stop reported offline or succeeded")
			}
		})
	}
}

func TestRemovedNativeJobMustReleaseDaemonLockBeforeRestart(t *testing.T) {
	s := lifecycleStore(t)
	unlock, err := fileLock(filepath.Join(s.Dir, "daemon.lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	f := &fakeService{running: true}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := controlService(ctx, s, "restart", f, &bytes.Buffer{}); err == nil {
		t.Fatal("restarted while the old process still owns the daemon lock")
	}
	if f.starts != 0 || !s.Online("self") {
		t.Fatal("started another daemon or erased the old process's heartbeat")
	}
}

func TestRegistrationRejectsWrongStoreAndParsesEscapedMacPaths(t *testing.T) {
	for _, platform := range []string{"linux", "darwin"} {
		t.Run(platform, func(t *testing.T) {
			home := t.TempDir()
			dir := filepath.Join(home, "config with spaces & quotes")
			n := nativeService{platform: platform, home: home, store: Store{dir}}
			var path, contents string
			if platform == "linux" {
				path = filepath.Join(home, ".config/systemd/user/tslink.service")
				contents = "[Service]\nExecStart=/bin/tslink daemon --state-dir " + systemdQuote(dir) + "\n"
			} else {
				path = filepath.Join(home, "Library/LaunchAgents/net.tslink.agent.plist")
				contents = "<plist><dict><key>ProgramArguments</key>\n<array><string>/bin/tslink</string><string>daemon</string><string>--state-dir</string><string>" + xmlEscape(dir) + "</string></array></dict></plist>"
			}
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
				t.Fatal(err)
			}
			if err := n.checkRegistration(); err != nil {
				t.Fatal(err)
			}
			n.store.Dir += "-other"
			if err := n.checkRegistration(); err == nil {
				t.Fatal("another configuration directory can control the same service")
			}
		})
	}
}

func TestServiceCommandsRejectArgumentsBeforeRequiringTailscale(t *testing.T) {
	t.Setenv("TSLINK_STATE_DIR", t.TempDir())
	for _, op := range []string{"start", "stop", "restart"} {
		if code := Run(context.Background(), []string{op, "peer"}, &bytes.Buffer{}, &bytes.Buffer{}); code != 2 {
			t.Fatal(op, code)
		}
	}
}
