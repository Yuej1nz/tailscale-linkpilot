//go:build windows

package mapping

import (
	"context"
	"errors"
	"io"
)

func InstallCaptureHelper(context.Context) error { return errors.New("capture helper is macOS-only") }
func RunCaptureHelper(context.Context, io.Reader, io.Writer, io.Writer) error {
	return errors.New("capture helper is macOS-only")
}
