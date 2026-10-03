//go:build !windows

package mapping

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const CaptureHelperPath = "/Library/PrivilegedHelperTools/net.tslink.capture"
const captureRulePrefix = "/private/etc/sudoers.d/tslink-capture-"

type captureRequest struct {
	Input    Input     `json:"input"`
	Deadline time.Time `json:"deadline"`
}

func captureOnlyInput(in Input) Input {
	return Input{Interface: in.Interface, Native: in.Native, Peers: in.Peers, SelfDisco: in.SelfDisco, PeerDisco: in.PeerDisco}
}

func rootOwned(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("privileged helper path is not root-owned and protected: %s", path)
	}
	return nil
}

func installedCaptureHelper() (bool, error) {
	if _, err := os.Lstat(CaptureHelperPath); os.IsNotExist(err) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	for _, path := range []string{"/Library", filepath.Dir(CaptureHelperPath), CaptureHelperPath} {
		if err := rootOwned(path); err != nil {
			return false, err
		}
	}
	info, _ := os.Lstat(CaptureHelperPath)
	if !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return false, errors.New("invalid privileged helper executable")
	}
	return true, nil
}

func helperUser() (*user.User, error) {
	uid, err := strconv.Atoi(os.Getenv("SUDO_UID"))
	if runtime.GOOS != "darwin" || os.Geteuid() != 0 || err != nil || uid <= 0 {
		return nil, errors.New("Mac capture helper requires explicit sudo installation or its fixed capture permission")
	}
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil || u.Username != os.Getenv("SUDO_USER") || !regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`).MatchString(u.Username) {
		return nil, errors.New("invalid sudo caller")
	}
	return u, nil
}

// InstallCaptureHelper is invoked only by interactive sudo during installation.
// The persistent rule permits no other subcommand or arguments; the user-owned
// product binary is never executed with persistent root privileges.
func InstallCaptureHelper(ctx context.Context) error {
	u, err := helperUser()
	if err != nil {
		return err
	}
	captureRulePath := captureRulePrefix + u.Uid
	dir := filepath.Dir(CaptureHelperPath)
	if err = os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	for _, p := range []string{"/Library", dir, "/private", "/private/etc"} {
		if err = rootOwned(p); err != nil {
			return err
		}
	}
	if err = os.MkdirAll(filepath.Dir(captureRulePath), 0755); err != nil {
		return err
	}
	if err = rootOwned(filepath.Dir(captureRulePath)); err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	src, err := os.Open(exe)
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := os.CreateTemp(dir, ".tslink-capture-")
	if err != nil {
		return err
	}
	temp := dst.Name()
	defer os.Remove(temp)
	if _, err = io.Copy(dst, src); err == nil {
		err = dst.Chmod(0755)
	}
	if err == nil {
		err = dst.Sync()
	}
	closeErr := dst.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(temp, CaptureHelperPath); err != nil {
		return err
	}
	rule := fmt.Sprintf("# Tailscale LinkPilot: bounded discovery capture only; no extra arguments.\n%s ALL=(root) NOPASSWD: %s capture-helper\n", u.Username, CaptureHelperPath)
	f, err := os.CreateTemp(filepath.Dir(captureRulePath), ".tslink-rule-")
	if err != nil {
		return err
	}
	temp = f.Name()
	defer os.Remove(temp)
	if _, err = f.WriteString(rule); err == nil {
		err = f.Chmod(0440)
	}
	closeErr = f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	output, err := exec.CommandContext(ctx, "/usr/sbin/visudo", "-cf", temp).CombinedOutput()
	if err != nil {
		return fmt.Errorf("capture sudo rule validation: %w: %s", err, output)
	}
	return os.Rename(temp, captureRulePath)
}

func validateCaptureRequest(req captureRequest, now time.Time, addresses []netip.Prefix) (string, error) {
	if !req.Deadline.After(now) || req.Deadline.After(now.Add(180*time.Second)) {
		return "", errors.New("capture deadline outside 180-second bound")
	}
	filter, err := captureFilter(req.Input)
	if err != nil {
		return "", err
	}
	local := false
	for _, p := range addresses {
		local = local || p.Addr() == req.Input.Native.Addr()
	}
	if !local {
		return "", errors.New("capture source does not belong to selected physical interface")
	}
	return filter, nil
}

// RunCaptureHelper accepts public discovery keys/endpoints only. Neither shell
// arguments, executable paths, file names nor filters are supplied by the caller.
func RunCaptureHelper(ctx context.Context, input io.Reader, out, errOut io.Writer) error {
	u, err := helperUser()
	if err != nil {
		return err
	}
	if ok, err := installedCaptureHelper(); err != nil || !ok {
		return errors.New("protected capture helper is not installed")
	}
	exe, err := os.Executable()
	if err != nil || exe != CaptureHelperPath {
		return errors.New("capture must run from the protected installed executable")
	}
	type decoded struct {
		req captureRequest
		err error
	}
	ch := make(chan decoded, 1)
	go func() {
		data, e := io.ReadAll(io.LimitReader(input, 32769))
		var req captureRequest
		if len(data) > 32768 {
			e = errors.New("oversized capture request")
		}
		if e == nil {
			d := json.NewDecoder(strings.NewReader(string(data)))
			d.DisallowUnknownFields()
			e = d.Decode(&req)
			if e == nil {
				var extra any
				if d.Decode(&extra) != io.EOF {
					e = errors.New("trailing capture request data")
				}
			}
		}
		ch <- decoded{req, e}
	}()
	var req captureRequest
	select {
	case v := <-ch:
		req, err = v.req, v.err
	case <-time.After(3 * time.Second):
		return errors.New("capture request timed out")
	case <-ctx.Done():
		return ctx.Err()
	}
	if err != nil {
		return err
	}
	iface, err := net.InterfaceByName(req.Input.Interface)
	if err != nil {
		return err
	}
	if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
		return errors.New("capture interface is not physical and up")
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return err
	}
	prefixes := []netip.Prefix{}
	for _, a := range addrs {
		if p, e := netip.ParsePrefix(a.String()); e == nil {
			prefixes = append(prefixes, p)
		}
	}
	filter, err := validateCaptureRequest(req, time.Now(), prefixes)
	if err != nil {
		return err
	}
	// One root capture at a time. The lock cannot be redirected by the caller.
	fd, err := unix.Open(CaptureHelperPath+".lock", unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return errors.New("capture helper already in use")
	}
	defer unix.Flock(fd, unix.LOCK_UN)
	ctx, cancel := context.WithDeadline(ctx, req.Deadline)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/sbin/tcpdump", "-Z", u.Username, "-U", "-n", "-i", req.Input.Interface, "-s", "2048", "-c", "4096", "-w", "-", filter)
	cmd.Stdout, cmd.Stderr = out, errOut
	cmd.Cancel = func() error { return cmd.Process.Signal(os.Interrupt) }
	cmd.WaitDelay = 2 * time.Second
	return cmd.Run()
}
