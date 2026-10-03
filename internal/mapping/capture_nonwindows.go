//go:build !windows

package mapping

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Start uses the installed, fixed-purpose Mac helper when available. The legacy
// terminal workflow otherwise retains its transient sudo authorization.
func (NativeCapture) Start(ctx context.Context, in Input, deliver func(Injection)) (func() error, error) {
	ctx, cancel := context.WithCancel(ctx)
	started := false
	defer func() {
		if !started {
			cancel()
		}
	}()
	filter, err := captureFilter(in)
	if err != nil {
		return nil, err
	}
	user, err := user.Current()
	if err != nil || !regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`).MatchString(user.Username) {
		return nil, errors.New("capture requires a valid local user")
	}
	cmd := exec.CommandContext(ctx, "/usr/bin/sudo", "-n", "/usr/sbin/tcpdump", "-Z", user.Username, "-U", "-n", "-i", in.Interface, "-s", "2048", "-w", "-", filter)
	if runtime.GOOS == "darwin" {
		if ok, e := installedCaptureHelper(); e != nil {
			return nil, e
		} else if ok {
			deadline := time.Now().Add(180 * time.Second)
			if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
				deadline = d
			}
			data, e := json.Marshal(captureRequest{Input: captureOnlyInput(in), Deadline: deadline})
			if e != nil {
				return nil, e
			}
			cmd = exec.CommandContext(ctx, "/usr/bin/sudo", "-n", CaptureHelperPath, "capture-helper")
			cmd.Stdin = strings.NewReader(string(data))
		}
	}
	return startCapture(ctx, cancel, &started, cmd, in, deliver)
}

func captureFilter(in Input) (string, error) {
	if !regexp.MustCompile(`^en[0-9]+$`).MatchString(in.Interface) || !in.Native.IsValid() || !in.Native.Addr().Is4() || !in.Native.Addr().IsGlobalUnicast() || in.Native.Port() == 0 || len(in.Peers) < 1 || len(in.Peers) > 12 || in.SelfDisco == [32]byte{} || in.PeerDisco == [32]byte{} {
		return "", errors.New("invalid selected capture interface, key or endpoint")
	}
	hosts := make([]string, 0, len(in.Peers))
	seen := make(map[netip.Addr]bool)
	for _, ap := range in.Peers {
		if !ap.IsValid() || !ap.Addr().Is4() || !ap.Addr().IsGlobalUnicast() || ap.Port() == 0 {
			return "", errors.New("invalid peer capture address")
		}
		if !seen[ap.Addr()] {
			hosts = append(hosts, "host "+ap.Addr().String())
			seen[ap.Addr()] = true
		}
	}
	return fmt.Sprintf("ip and udp and ((src host %s and src port %d and (%s) and (%s)) or (dst host %s and dst port %d and (%s)))", in.Native.Addr(), in.Native.Port(), strings.Join(hosts, " or "), discoKeyFilter(in.SelfDisco), in.Native.Addr(), in.Native.Port(), discoKeyFilter(in.PeerDisco)), nil
}

func discoKeyFilter(key [32]byte) string {
	keyFilter := "udp[8:4] = 0x5453f09f and udp[12:2] = 0x92ac"
	for i := 0; i < 32; i += 4 {
		keyFilter += fmt.Sprintf(" and udp[%d:4] = 0x%08x", 14+i, binary.BigEndian.Uint32(key[i:i+4]))
	}
	return keyFilter
}

func startCapture(ctx context.Context, cancel context.CancelFunc, started *bool, cmd *exec.Cmd, in Input, deliver func(Injection)) (func() error, error) {
	cmd.Cancel = func() error { return cmd.Process.Signal(os.Interrupt) }
	cmd.WaitDelay = 2 * time.Second
	reader, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	// Wait for a valid pcap header, so missing privilege is not reported as a
	// working capture. A context deadline also covers a hung capture startup.
	parsed := make(chan error, 1)
	ready := make(chan struct{})
	var readiness sync.Once
	var errorMu sync.Mutex
	var captureError string
	markReady := func() { readiness.Do(func() { close(ready) }) }
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			errorMu.Lock()
			captureError = scanner.Text()
			if len(captureError) > 1024 {
				captureError = captureError[:1024]
			}
			errorMu.Unlock()
			// tcpdump may buffer the pcap global header until its first packet.
			// Its listening message confirms BPF is open before native probes.
			if strings.Contains(scanner.Text(), "listening on "+in.Interface+",") {
				markReady()
			}
		}
	}()
	go func() { parsed <- readPCAPReady(reader, in, deliver, markReady) }()
	var once sync.Once
	var stopped error
	stop := func() error {
		once.Do(func() {
			cancel()
			_ = cmd.Process.Signal(os.Interrupt)
			_ = reader.Close()
			stopped = cmd.Wait()
		})
		return stopped
	}
	// readPCAP announces header readiness using this wrapper instead of an
	// arbitrary sleep. This early read only confirms permission and link type.
	select {
	case <-ready:
		*started = true
		return stop, nil
	case err := <-parsed:
		_ = stop()
		errorMu.Lock()
		detail := captureError
		errorMu.Unlock()
		return nil, fmt.Errorf("native bootstrap capture unavailable; verify tslink install on Mac (legacy: sudo -v): %w; %s", err, detail)
	case <-ctx.Done():
		_ = stop()
		return nil, ctx.Err()
	case <-time.After(3 * time.Second):
		_ = stop()
		return nil, errors.New("native bootstrap capture startup timed out")
	}
}
