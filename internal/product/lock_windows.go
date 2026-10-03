package product

import (
	"errors"
	"golang.org/x/sys/windows"
	"os"
)

func fileLock(path string) (func(), error) {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	if e = windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &windows.Overlapped{}); e != nil {
		f.Close()
		return nil, errors.New("another product operation is active")
	}
	return func() { f.Close() }, nil
}
