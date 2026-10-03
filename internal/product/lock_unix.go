//go:build darwin || linux

package product

import (
	"errors"
	"golang.org/x/sys/unix"
	"os"
)

func fileLock(path string) (func(), error) {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	if e = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		f.Close()
		return nil, errors.New("another product operation is active")
	}
	return func() { f.Close() }, nil
}
