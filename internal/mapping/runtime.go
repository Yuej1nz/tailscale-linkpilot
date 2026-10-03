package mapping

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Configuration travels through an inherited anonymous pipe, not argv or an
// on-disk packet file. The control token is kept in a user-only runtime record.
type Config struct {
	Input     Input         `json:"input"`
	SessionID string        `json:"session_id"`
	Token     string        `json:"token"`
	Directory string        `json:"directory"`
	Tried     []uint16      `json:"tried_ports"`
	Prepare   time.Duration `json:"prepare_budget"`
	Lease     time.Duration `json:"lease"`
}

type Record struct {
	SessionID string `json:"session_id"`
	Socket    string `json:"socket"`
	Token     string `json:"token"`
}

type LocalSession struct {
	record Record
	http   *http.Client
}

func runtimeDirectory() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	// A short socket pathname avoids macOS's small sockaddr_un path limit.
	return filepath.Join(home, ".ts-direct-runtime"), nil
}

// Keep peer paths short enough for macOS Unix sockets. The full identities are
// checked in the live state, so the directory name is never an identity proof.
func peerDirectory(self, peer string) (string, error) {
	if self == "" || peer == "" || self == peer {
		return "", errors.New("carrier requires distinct stable node identities")
	}
	root, err := runtimeDirectory()
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256([]byte(self + "\x00" + peer))
	return filepath.Join(root, hex.EncodeToString(hash[:8])), nil
}

const MaxLocalSessions = 16

func prepareSessionDirectory(ctx context.Context, input Input) (string, error) {
	root, err := runtimeDirectory()
	if err != nil {
		return "", err
	}
	if err := privateDirectory(root, true); err != nil {
		return "", err
	}
	dir, err := peerDirectory(input.SelfID, input.PeerID)
	if err != nil {
		return "", err
	}
	if s, _, err := ActiveFor(ctx, input.SelfID, input.PeerID); err == nil {
		s.http.CloseIdleConnections()
		return "", errors.New("a local source session for this peer is already active")
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return "", err
	}
	live := 0
	if s, _, err := Active(ctx); err == nil {
		s.http.CloseIdleConnections()
		live++
	}
	for _, entry := range entries {
		if !entry.IsDir() || len(entry.Name()) != 16 {
			continue
		}
		if s, _, err := activeIn(ctx, filepath.Join(root, entry.Name())); err == nil {
			s.http.CloseIdleConnections()
			live++
		}
	}
	if live >= MaxLocalSessions {
		return "", fmt.Errorf("local carrier limit reached (%d); existing sessions were preserved", MaxLocalSessions)
	}
	if err := privateDirectory(dir, true); err != nil {
		return "", err
	}
	return dir, nil
}

func randomToken() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return hex.EncodeToString(buf)
}

func localSession(record Record) *LocalSession {
	t := &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", record.Socket)
	}}
	return &LocalSession{record: record, http: &http.Client{Transport: t, Timeout: 5 * time.Second}}
}

func (s *LocalSession) call(ctx context.Context, path string, input, result any) error {
	var buf bytes.Buffer
	if input != nil {
		if err := json.NewEncoder(&buf).Encode(input); err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://local"+path, &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.record.Token)
	resp, err := s.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("local session returned HTTP %d: %s", resp.StatusCode, data)
	}
	if result != nil {
		return json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(result)
	}
	return nil
}

func (s *LocalSession) State(ctx context.Context) (State, error) {
	var result State
	err := s.call(ctx, "/state", nil, &result)
	return result, err
}
func (s *LocalSession) Inject(ctx context.Context, req Injection) error {
	return s.call(ctx, "/inject", req, nil)
}
func (s *LocalSession) STUN(ctx context.Context) error   { return s.call(ctx, "/stun", nil, nil) }
func (s *LocalSession) Commit(ctx context.Context) error { return s.call(ctx, "/commit", nil, nil) }
func (s *LocalSession) Renew(ctx context.Context) error  { return s.call(ctx, "/renew", nil, nil) }
func (s *LocalSession) Stop(ctx context.Context) error {
	err := s.call(ctx, "/stop", nil, nil)
	s.http.CloseIdleConnections()
	// The independent bootstrap may already have removed this controller.
	// Only ENOENT is idempotent; cancellation, permission and replacement
	// authentication failures must remain visible to the caller.
	if ctx.Err() == nil && errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (s *LocalSession) Activate(ctx context.Context, physical netip.AddrPort) error {
	return s.call(ctx, "/activate", physical, nil)
}

func (s *LocalSession) AddPeer(ctx context.Context, endpoint netip.AddrPort) error {
	return s.call(ctx, "/peer", endpoint, nil)
}

func (s *LocalSession) AddObservedPeer(ctx context.Context, peer ObservedPeer) error {
	return s.call(ctx, "/observed-peer", peer, nil)
}

func (s *LocalSession) ConfigureProbe(ctx context.Context, config ProbeConfig) error {
	return s.call(ctx, "/probe/configure", config, nil)
}

func (s *LocalSession) Probe(ctx context.Context, endpoints []netip.AddrPort) error {
	return s.call(ctx, "/probe/send", endpoints, nil)
}

func (s *LocalSession) SelectProbe(ctx context.Context, endpoint netip.AddrPort) error {
	return s.call(ctx, "/probe/select", endpoint, nil)
}

func Active(ctx context.Context) (*LocalSession, State, error) {
	dir, err := runtimeDirectory()
	if err != nil {
		return nil, State{}, err
	}
	return activeIn(ctx, dir)
}

// ActiveFor also recognizes an older single-session worker without moving or
// restarting it. Another peer's legacy carrier is never returned or stopped.
func ActiveFor(ctx context.Context, self, peer string) (*LocalSession, State, error) {
	dir, err := peerDirectory(self, peer)
	if err != nil {
		return nil, State{}, err
	}
	if err := privateDirectory(filepath.Dir(dir), false); err != nil {
		return nil, State{}, err
	}
	s, state, err := activeIn(ctx, dir)
	if errors.Is(err, os.ErrNotExist) {
		s, state, err = Active(ctx)
	}
	if err != nil {
		return nil, State{}, err
	}
	if state.SelfID != self || state.PeerID != peer {
		s.http.CloseIdleConnections()
		return nil, State{}, errors.New("local carrier node identity mismatch")
	}
	return s, state, nil
}

func activeIn(ctx context.Context, dir string) (*LocalSession, State, error) {
	if err := privateDirectory(dir, false); err != nil {
		return nil, State{}, err
	}
	path := filepath.Join(dir, "active.json")
	if err := privateFile(path); err != nil {
		return nil, State{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, State{}, err
	}
	var record Record
	if err := json.Unmarshal(data, &record); err != nil || record.Socket != filepath.Join(dir, "control.sock") || len(record.Token) != 32 {
		return nil, State{}, errors.New("invalid private session record")
	}
	if err := privateSocket(record.Socket); err != nil {
		return nil, State{}, err
	}
	s := localSession(record)
	state, err := s.State(ctx)
	if err != nil || state.SessionID != record.SessionID {
		s.http.CloseIdleConnections()
		return nil, State{}, errors.New("no responsive matching carrier; previous runtime record may be stale")
	}
	return s, state, nil
}

// ServeWorker owns the actual socket for its entire lifetime. A parent crash
// before commit expires the preparation lease; commit retains a bounded lease.
// check is supplied by the native adapter to stop on account/network changes.
func ServeWorker(ctx context.Context, cfg Config, check func(context.Context, Input) error) error {
	if cfg.SessionID == "" || len(cfg.Token) != 32 || cfg.Prepare < time.Second || cfg.Prepare > 180*time.Second || cfg.Lease < time.Minute || cfg.Lease > 24*time.Hour || !cfg.Input.Native.IsValid() || !cfg.Input.Native.Addr().Is4() || len(cfg.Input.Peers) == 0 || len(cfg.Input.Peers) > 12 || len(cfg.Input.STUN) > 6 || cfg.Input.SelfDisco == [32]byte{} || cfg.Input.PeerDisco == [32]byte{} {
		return errors.New("invalid carrier preparation")
	}
	root, err := runtimeDirectory()
	peerDir, peerErr := peerDirectory(cfg.Input.SelfID, cfg.Input.PeerID)
	if err != nil || peerErr != nil || cfg.Directory != root && cfg.Directory != peerDir {
		return errors.New("worker runtime directory mismatch")
	}
	if err := privateDirectory(root, true); err != nil {
		return err
	}
	dir := cfg.Directory
	if err := privateDirectory(dir, true); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	conn, err := freshSocket(cfg.Input.Native.Addr(), cfg.Input.Native.Port(), cfg.Tried)
	if err != nil {
		return err
	}
	defer conn.Close()
	c := newSocketCarrier(conn, cfg.Input, cfg.SessionID)
	c.state.ExpiresAt = time.Now().Add(cfg.Prepare).UTC()
	socketPath := filepath.Join(dir, "control.sock")
	// The parent checked for a live session while holding the optimizer lock.
	// Never remove a responsive controller or follow another user's pathname.
	if _, err := os.Lstat(socketPath); err == nil {
		probe, dialErr := net.DialTimeout("unix", socketPath, 200*time.Millisecond)
		if dialErr == nil {
			_ = probe.Close()
			return errors.New("a local carrier is already running")
		}
		if err := privateSocket(socketPath); err != nil {
			return err
		}
		_ = os.Remove(socketPath)
	}
	l, err := net.Listen("unix", socketPath)
	if err != nil {
		return err
	}
	defer l.Close()
	if err := os.Chmod(socketPath, 0600); err != nil {
		return err
	}
	recordPath := filepath.Join(dir, "active.json")
	if _, err := os.Lstat(recordPath); err == nil {
		if err := privateFile(recordPath); err != nil {
			return err
		}
		_ = os.Remove(recordPath)
	}
	record := Record{SessionID: cfg.SessionID, Socket: socketPath, Token: cfg.Token}
	file, err := os.OpenFile(recordPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	err = json.NewEncoder(file).Encode(record)
	_ = file.Close()
	if err != nil {
		return err
	}
	defer os.Remove(recordPath)
	defer os.Remove(socketPath)
	stop := func(reason string) {
		c.mu.Lock()
		c.state.Stopped, c.state.StopReason = true, reason
		c.mu.Unlock()
		cancel()
	}
	var stunMu sync.Mutex
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer "+cfg.Token {
			http.Error(w, "local session authentication failed", http.StatusForbidden)
			return
		}
		var err error
		switch r.URL.Path {
		case "/state":
			_ = json.NewEncoder(w).Encode(c.snapshot())
			return
		case "/inject":
			var req Injection
			err = json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req)
			if err == nil {
				err = c.inject(req)
			}
		case "/stun":
			if !stunMu.TryLock() {
				err = errors.New("STUN already active")
			} else {
				probeCtx, done := context.WithTimeout(r.Context(), 1500*time.Millisecond)
				err = c.restun(probeCtx)
				done()
				stunMu.Unlock()
			}
		case "/commit":
			if err = check(r.Context(), cfg.Input); err == nil {
				c.mu.Lock()
				if !c.state.Activated || !c.state.Physical.IsValid() || c.state.Counters.DataIn == 0 || c.state.Counters.DataOut == 0 {
					err = errors.New("no real encrypted data through this session")
				} else {
					if !c.state.Committed {
						c.state.Committed = true
						c.state.ExpiresAt = time.Now().Add(cfg.Lease).UTC()
					}
				}
				c.mu.Unlock()
			}
		case "/renew":
			if err = check(r.Context(), cfg.Input); err == nil {
				c.mu.Lock()
				if c.state.Stopped || !c.state.Committed || !c.state.Activated || time.Now().After(c.state.ExpiresAt) {
					err = errors.New("only a live committed carrier can be renewed")
				} else {
					c.state.ExpiresAt = time.Now().Add(cfg.Lease).UTC()
				}
				c.mu.Unlock()
			}
		case "/activate":
			var expected netip.AddrPort
			err = json.NewDecoder(http.MaxBytesReader(w, r.Body, 512)).Decode(&expected)
			if err == nil {
				err = c.activate(expected)
			}
		case "/peer":
			var endpoint netip.AddrPort
			err = json.NewDecoder(http.MaxBytesReader(w, r.Body, 512)).Decode(&endpoint)
			if err == nil {
				err = c.addPeer(endpoint)
			}
		case "/observed-peer":
			var peer ObservedPeer
			err = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&peer)
			if err == nil {
				err = c.addObservedPeer(peer)
			}
		case "/probe/configure":
			var config ProbeConfig
			err = json.NewDecoder(http.MaxBytesReader(w, r.Body, 512)).Decode(&config)
			if err == nil {
				err = c.configureProbe(config)
			}
		case "/probe/send":
			var endpoints []netip.AddrPort
			err = json.NewDecoder(http.MaxBytesReader(w, r.Body, 512)).Decode(&endpoints)
			if err == nil {
				err = c.sendProbe(r.Context(), endpoints)
			}
		case "/probe/select":
			var endpoint netip.AddrPort
			err = json.NewDecoder(http.MaxBytesReader(w, r.Body, 512)).Decode(&endpoint)
			if err == nil {
				err = c.selectProbe(endpoint)
			}
		case "/stop":
			go func() { time.Sleep(50 * time.Millisecond); stop("stopped_by_owner") }()
		default:
			err = errors.New("unknown local operation")
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
	})
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: 5 * time.Second, BaseContext: func(net.Listener) context.Context { return ctx }}
	go func() {
		if err := srv.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
			stop("controller_failed")
		}
	}()
	defer srv.Close()
	go func() {
		if err := c.read(ctx); err != nil && ctx.Err() == nil {
			stop("udp_socket_failed")
		}
	}()
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
			state := c.snapshot()
			if time.Now().After(state.ExpiresAt) {
				stop("lease_expired")
				continue
			}
			checkCtx, done := context.WithTimeout(ctx, 3*time.Second)
			err := check(checkCtx, cfg.Input)
			done()
			if err != nil {
				stop("identity_or_network_changed")
			}
		}
	}
}

func freshSocket(ip netip.Addr, native uint16, tried []uint16) (*net.UDPConn, error) {
	used := map[uint16]bool{native: true}
	for _, port := range tried {
		used[port] = true
	}
	for i := 0; i < 32; i++ {
		conn, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, 0)))
		if err != nil {
			return nil, err
		}
		if !used[conn.LocalAddr().(*net.UDPAddr).AddrPort().Port()] {
			return conn, nil
		}
		_ = conn.Close()
	}
	return nil, errors.New("OS repeatedly allocated already tried source ports")
}
