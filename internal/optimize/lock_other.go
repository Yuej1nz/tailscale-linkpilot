//go:build !darwin && !linux && !windows

package optimize

import "errors"

func Lock() (func(), error) {
	return nil, errors.New("optimizer execution is implemented only for macOS and Linux assistants")
}
