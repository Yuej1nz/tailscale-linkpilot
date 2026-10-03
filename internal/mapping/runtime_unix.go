//go:build darwin || linux

package mapping

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

func owned(info os.FileInfo) bool {
	s, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(s.Uid) == os.Getuid()
}

func privateDirectory(path string, create bool) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) && create {
		if err := os.Mkdir(path, 0700); err != nil {
			return err
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm() != 0700 || !owned(info) {
		return errors.New("runtime directory must be a non-symlink owned directory with mode 0700")
	}
	return nil
}

func privateFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || !owned(info) {
		return errors.New("runtime record must be a non-symlink owned file with mode 0600")
	}
	return nil
}

func privateSocket(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0600 || !owned(info) {
		return errors.New("runtime socket must be an owned socket with mode 0600")
	}
	return nil
}

func Spawn(ctx context.Context, input Input, tried []uint16, prepare, lease time.Duration) (Session, error) {
	dir, err := prepareSessionDirectory(ctx, input)
	if err != nil {
		return nil, err
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	read, write, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer read.Close()
	defer write.Close()
	logPath := filepath.Join(dir, "last-worker.log")
	if _, err := os.Lstat(logPath); err == nil {
		if err := privateFile(logPath); err != nil {
			return nil, err
		}
	}
	log, err := os.OpenFile(logPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	defer log.Close()
	cmd := exec.Command(exe, "session-worker")
	cmd.ExtraFiles = []*os.File{read}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Stdin = nil
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	cfg := Config{Input: input, SessionID: randomToken(), Token: randomToken(), Directory: dir, Tried: append([]uint16(nil), tried...), Prepare: prepare, Lease: lease}
	if err := json.NewEncoder(write).Encode(cfg); err != nil {
		_ = cmd.Process.Kill()
		return nil, err
	}
	_ = write.Close()
	deadline := time.NewTimer(4 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case err := <-done:
			data, _ := os.ReadFile(logPath)
			if len(data) > 512 {
				data = data[:512]
			}
			return nil, errors.New("local carrier exited before readiness: " + string(data) + " (" + errorText(err) + ")")
		case <-ctx.Done():
			_ = cmd.Process.Kill()
			return nil, ctx.Err()
		case <-deadline.C:
			_ = cmd.Process.Kill()
			return nil, errors.New("local carrier readiness timed out")
		case <-tick.C:
			s, state, err := ActiveFor(ctx, input.SelfID, input.PeerID)
			if err == nil && state.SessionID == cfg.SessionID {
				return s, nil
			}
		}
	}
}

func errorText(err error) string {
	if err == nil {
		return "exit 0"
	}
	return err.Error()
}

func ReadWorkerConfig() (Config, error) {
	file := os.NewFile(3, "private-carrier-config")
	if file == nil {
		return Config{}, errors.New("worker requires inherited configuration pipe")
	}
	defer file.Close()
	var cfg Config
	err := json.NewDecoder(io.LimitReader(file, 32<<10)).Decode(&cfg)
	return cfg, err
}
