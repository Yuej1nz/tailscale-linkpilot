package product

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestAtomicConfigUpdatePreservesAuthorizationAndRejectsConcurrentWriters(t *testing.T) {
	s := Store{t.TempDir()}
	if err := s.Update(func(c *Config) error { c.SelfID = "self"; c.Allow("a"); c.Allow("a"); return nil }); err != nil {
		t.Fatal(err)
	}
	c, err := s.Config()
	if err != nil || len(c.Allowed) != 1 || !c.Authorizes("a") || c.Authorizes("b") {
		t.Fatal(c, err)
	}
	if err := s.Update(func(c *Config) error { c.Allow("b"); return errors.New("aborted") }); err == nil {
		t.Fatal("aborted edit reported success")
	}
	c, _ = s.Config()
	if c.Authorizes("b") {
		t.Fatal("aborted edit changed authorization")
	}
	unlock, err := fileLock(filepath.Join(s.Dir, "config.lock"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Update(func(c *Config) error { c.Allow("b"); return nil }); err == nil {
		t.Fatal("concurrent writer accepted")
	}
	unlock()
	if err := s.Update(func(c *Config) error { c.Allow("b"); return nil }); err != nil {
		t.Fatal(err)
	}
}
func TestHeartbeatBoundToConfiguredIdentity(t *testing.T) {
	s := Store{t.TempDir()}
	if s.Online("a") {
		t.Fatal("missing heartbeat treated as live")
	}
	if err := s.Pulse("a"); err != nil {
		t.Fatal(err)
	}
	if !s.Online("a") || s.Online("b") {
		t.Fatal("identity switch preserved online status")
	}
}
