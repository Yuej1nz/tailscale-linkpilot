//go:build darwin || linux || windows

package optimize

import "testing"

func TestDeviceLockIsExclusiveAndReleased(t *testing.T) {
	dir := t.TempDir()
	first, err := lockDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	if second, err := lockDirectory(dir); err == nil {
		second()
		first()
		t.Fatal("concurrent optimizer accepted")
	}
	first()
	third, err := lockDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	third()
}
