package product

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const Name = "Tailscale LinkPilot"
const Command = "tslink"
const Version = "0.6.0-macos-agent"
const Port = 45829

type Target struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Enabled     bool   `json:"enabled"`
	Requested   int64  `json:"requested,omitempty"`
	Coordinator string `json:"coordinator,omitempty"`
}
type Config struct {
	Schema     int      `json:"schema"`
	SelfID     string   `json:"self_id"`
	Allowed    []string `json:"allowed_peers"`
	Targets    []Target `json:"targets"`
	SudoRestun bool     `json:"sudo_restun,omitempty"`
}
type State struct {
	Requested int64     `json:"requested,omitempty"`
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Phase     string    `json:"phase"`
	Path      string    `json:"path,omitempty"`
	LatencyMS float64   `json:"latency_ms,omitempty"`
	Error     string    `json:"error,omitempty"`
	Updated   time.Time `json:"updated_at"`
	NextTry   time.Time `json:"next_try,omitempty"`
	Report    string    `json:"report,omitempty"`
}
type Status struct {
	Version string    `json:"version"`
	SelfID  string    `json:"self_id"`
	Updated time.Time `json:"updated_at"`
	States  []State   `json:"targets"`
}
type Store struct{ Dir string }

func DefaultStore() (Store, error) {
	if p := os.Getenv("TSLINK_STATE_DIR"); p != "" {
		return Store{p}, nil
	}
	d, err := os.UserConfigDir()
	return Store{filepath.Join(d, Command)}, err
}
func (s Store) Config() (Config, error) {
	c := Config{Schema: 1}
	err := readJSON(filepath.Join(s.Dir, "config.json"), &c)
	if os.IsNotExist(err) {
		return c, nil
	}
	if err == nil && c.Schema != 1 {
		err = errors.New("unsupported configuration schema")
	}
	return c, err
}
func (s Store) Update(fn func(*Config) error) error {
	if err := os.MkdirAll(s.Dir, 0700); err != nil {
		return err
	}
	unlock, err := fileLock(filepath.Join(s.Dir, "config.lock"))
	if err != nil {
		return err
	}
	defer unlock()
	c, err := s.Config()
	if err != nil {
		return err
	}
	if err := fn(&c); err != nil {
		return err
	}
	return writeJSONFile(filepath.Join(s.Dir, "config.json"), c)
}
func (s Store) Status() (Status, error) {
	var v Status
	err := readJSON(filepath.Join(s.Dir, "status.json"), &v)
	return v, err
}
func (s Store) SaveStatus(v Status) error {
	return writeJSONFile(filepath.Join(s.Dir, "status.json"), v)
}
func readJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if len(data) > 2<<20 {
		return errors.New("state file too large")
	}
	return json.Unmarshal(data, v)
}
func writeJSONFile(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".state-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0600); err == nil {
		err = json.NewEncoder(f).Encode(v)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(name, path)
}
func (c Config) Authorizes(id string) bool {
	for _, p := range c.Allowed {
		if p == id {
			return true
		}
	}
	return false
}
func (c *Config) Allow(id string) {
	if !c.Authorizes(id) {
		c.Allowed = append(c.Allowed, id)
	}
}
func (c *Config) Find(selector string) (*Target, error) {
	for i := range c.Targets {
		if c.Targets[i].ID == selector || c.Targets[i].Name == selector {
			return &c.Targets[i], nil
		}
	}
	return nil, fmt.Errorf("目标 %q 尚未连接", selector)
}

type Heartbeat struct {
	SelfID string    `json:"self_id"`
	At     time.Time `json:"at"`
}

func (s Store) Pulse(id string) error {
	return writeJSONFile(filepath.Join(s.Dir, "heartbeat.json"), Heartbeat{id, time.Now().UTC()})
}
func (s Store) Online(id string) bool {
	var h Heartbeat
	return readJSON(filepath.Join(s.Dir, "heartbeat.json"), &h) == nil && h.SelfID == id && time.Since(h.At) >= 0 && time.Since(h.At) < 25*time.Second
}
