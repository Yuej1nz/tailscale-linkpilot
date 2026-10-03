package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"runtime"
	"time"

	"github.com/Yuej1nz/tailscale-linkpilot/internal/adapter"
	"github.com/Yuej1nz/tailscale-linkpilot/internal/diagnostic"
	"github.com/Yuej1nz/tailscale-linkpilot/internal/mapping"
)

func runSessionWorker(ctx context.Context, args []string, errOut io.Writer) int {
	if len(args) != 0 || runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		fmt.Fprintln(errOut, "session-worker is an internal desktop command")
		return 2
	}
	cfg, err := mapping.ReadWorkerConfig()
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	a := adapter.New("", cfg.Input.CLI)
	check := func(ctx context.Context, in mapping.Input) error {
		s, err := a.Snapshot(ctx)
		if err != nil {
			return err
		}
		if s.BackendState != "Running" || s.Self.ID != in.SelfID || s.NetworkGeneration != in.Generation {
			return errors.New("native identity or network changed")
		}
		if _, err := diagnostic.ResolvePeer(s, in.PeerID); err != nil {
			return errors.New("selected peer is no longer authorized by the native client")
		}
		addresses, err := a.NativeEndpoints(ctx)
		if err != nil {
			return err
		}
		for _, value := range addresses {
			if value == in.Native.String() {
				return nil
			}
		}
		return errors.New("native UDP endpoint changed")
	}
	if err := check(ctx, cfg.Input); err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	if err := mapping.ServeWorker(ctx, cfg, check); err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	return 0
}

func runSession(ctx context.Context, args []string, out, errOut io.Writer) int {
	if len(args) != 1 || args[0] != "status" && args[0] != "stop" {
		fmt.Fprintln(errOut, "用法: ts-direct session status | stop")
		return 2
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	s, state, err := mapping.Active(ctx)
	if err != nil {
		fmt.Fprintln(errOut, "当前没有可响应的本地 UDP 会话:", err)
		return 1
	}
	if args[0] == "stop" {
		if err := s.Stop(ctx); err != nil {
			fmt.Fprintln(errOut, err)
			return 1
		}
		fmt.Fprintln(out, "本地 UDP 会话已请求停止；原生 Tailscale 将重新选择路径。")
		return 0
	}
	e := json.NewEncoder(out)
	e.SetIndent("", "  ")
	if err := e.Encode(state); err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	return 0
}
