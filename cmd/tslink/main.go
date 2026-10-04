package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/Yuej1nz/tailscale-linkpilot/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(cli.RunProduct(ctx, os.Args[1:], os.Stdout, os.Stderr))
}
