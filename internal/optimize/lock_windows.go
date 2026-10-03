//go:build windows

package optimize

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// The kernel releases this lock on crashes; no stale PID file can strand a run.
func Lock() (func(), error) {
	dir, err := os.UserCacheDir()
	if err != nil {
		return nil, err
	}
	dir = filepath.Join(dir, "ts-direct")
	return lockDirectory(dir)
}

func lockDirectory(dir string) (func(), error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, "optimizer.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &windows.Overlapped{}); err != nil {
		_ = f.Close()
		return nil, errors.New("another optimizer session is active on this device")
	}
	return func() { _ = f.Close() }, nil
}
