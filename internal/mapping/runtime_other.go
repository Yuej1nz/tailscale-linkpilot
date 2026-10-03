//go:build !darwin && !linux && !windows

package mapping

import (
	"context"
	"errors"
	"time"
)

func privateDirectory(string, bool) error {
	return errors.New("local carrier unavailable on this platform")
}
func privateFile(string) error   { return errors.New("local carrier unavailable on this platform") }
func privateSocket(string) error { return errors.New("local carrier unavailable on this platform") }
func Spawn(context.Context, Input, []uint16, time.Duration, time.Duration) (Session, error) {
	return nil, errors.New("local carrier unavailable on this platform")
}
func ReadWorkerConfig() (Config, error) {
	return Config{}, errors.New("local carrier unavailable on this platform")
}
