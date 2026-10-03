package cli

import (
	"context"
	"fmt"
	"github.com/Yuej1nz/tailscale-linkpilot/internal/mapping"
	"github.com/Yuej1nz/tailscale-linkpilot/internal/product"
	"io"
	"os"
)

func RunProduct(ctx context.Context, args []string, out, errOut io.Writer) int {
	if len(args) == 1 && (args[0] == "capture-helper" || args[0] == "install-capture") {
		var err error
		if args[0] == "capture-helper" {
			err = mapping.RunCaptureHelper(ctx, os.Stdin, out, errOut)
		} else {
			err = mapping.InstallCaptureHelper(ctx)
		}
		if err != nil {
			fmt.Fprintln(errOut, err)
			return 1
		}
		return 0
	}
	// Carrier workers keep the tested legacy protocol; the public interface uses
	// product commands and delegates all automatic runs to one background owner.
	if len(args) > 0 && args[0] == "session-worker" {
		return runSessionWorker(ctx, args[1:], errOut)
	}
	return product.Run(ctx, args, out, errOut)
}
