package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"runtime"
	"time"

	"github.com/Yuej1nz/tailscale-linkpilot/internal/adapter"
	"github.com/Yuej1nz/tailscale-linkpilot/internal/diagnostic"
	"github.com/Yuej1nz/tailscale-linkpilot/internal/model"
	"github.com/Yuej1nz/tailscale-linkpilot/internal/optimize"
)

func runOptimize(ctx context.Context, args []string, out, errOut io.Writer) int {
	f := flag.NewFlagSet("optimize", flag.ContinueOnError)
	f.SetOutput(errOut)
	peer := f.String("peer", "", "已安装助手的 Tailscale 对端")
	once := f.Bool("once", false, "执行一轮有界优化")
	coordinator := f.String("coordinator", "", "对端 Tailscale IP:port，默认自动选择")
	budget := f.Duration("budget", 120*time.Second, "总时限（20s 至 180s）")
	hold := f.Duration("hold", 20*time.Second, "三次业务复测间的观察窗口（0s 至 60s）")
	rebinds := f.Int("rebinds", 2, "最多重新绑定次数（0 至 2）")
	count := f.Int("count", 6, "每轮双向路径探测数（1 至 8）")
	allow := f.Bool("allow-rebind", true, "允许重新绑定 本机 UDP socket；不选择新端口")
	sessions := f.Int("source-sessions", 3, "最多搜索不同的本地 UDP 会话（0 至 3）；0 禁用；Mac 搜索需要 sudo -v，Windows 搜索需要管理员权限")
	lease := f.Duration("session-lease", 30*time.Minute, "成功会话的最长保留时间（1m 至 24h），换网或切换账户时提前停止")
	asJSON := f.Bool("json", false, "输出 JSON")
	output := f.String("output", "", "保存报告到新文件")
	socket := f.String("socket", "", "指定本机 Tailscale IPC")
	tsCLI := f.String("tailscale", "", "指定 Tailscale CLI")
	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if f.NArg() != 0 || *peer == "" || !*once || *budget < 20*time.Second || *budget > 180*time.Second || *hold < 0 || *hold > 60*time.Second || *hold+15*time.Second > *budget || *rebinds < 0 || *rebinds > 2 || *count < 1 || *count > 8 || *sessions < 0 || *sessions > 3 || *lease < time.Minute || *lease > 24*time.Hour {
		fmt.Fprintln(errOut, "需要 --peer 和 --once；请检查预算、保持窗口和重试范围")
		return 2
	}
	if runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		fmt.Fprintln(errOut, "optimize 支持 macOS 和 Windows；服务器请运行 assist")
		return 2
	}
	unlock, err := optimize.Lock()
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	defer unlock()
	r := optimize.Run(ctx, adapter.New(*socket, *tsCLI), optimize.Options{Peer: *peer, Coordinator: *coordinator, Budget: *budget, Hold: *hold, Rebinds: *rebinds, Count: *count, AllowRebind: *allow, Version: Version, SourceSessions: *sessions, SessionLease: *lease})
	if *output != "" {
		if err := saveReport(*output, r); err != nil {
			fmt.Fprintln(errOut, err)
			return 1
		}
	}
	if *asJSON {
		e := json.NewEncoder(out)
		e.SetIndent("", "  ")
		if err := e.Encode(r); err != nil {
			fmt.Fprintln(errOut, err)
			return 1
		}
	} else {
		fmt.Fprintf(out, "优化结果: %s\n双向直连与业务复测通过: %t | 三次业务复测通过: %t\n持久配置修改: %t | 运行时刷新: %t\n", r.Outcome, r.DirectVerified, r.ApplicationVerified, r.PersistentChanges, r.RuntimeChanges)
		for _, trial := range r.SourceTrials {
			if trial.State != nil {
				fmt.Fprintf(out, "会话 %d: 本地 %s；映射观测 %d 次\n", trial.Index, trial.State.Local, len(trial.State.Mappings))
			}
			if trial.PairedError != "" {
				fmt.Fprintf(errOut, "双方会话未启用: %s\n", trial.PairedError)
			}
			if trial.Error != "" {
				fmt.Fprintf(errOut, "会话 %d 未通过: %s\n", trial.Index, trial.Error)
			}
		}
		if r.Error != "" {
			fmt.Fprintln(errOut, r.Error)
		}
	}
	if !r.DirectVerified {
		return 1
	}
	return 0
}

func runAssist(ctx context.Context, args []string, out, errOut io.Writer) int {
	f := flag.NewFlagSet("assist", flag.ContinueOnError)
	f.SetOutput(errOut)
	peer := f.String("peer", "", "允许协调的唯一 Tailscale 对端")
	listen := f.String("listen", "", "绑定本机 Tailscale IP:port，默认自动选择")
	duration := f.Duration("duration", 30*time.Minute, "服务期限（1m 至 24h），0 表示持续运行")
	sudoRestun := f.Bool("sudo-restun", false, "Linux 助手可使用已授权的固定 sudo restun 命令，不提示密码")
	output := f.String("output", "", "保存启动身份与监听信息到新文件")
	socket := f.String("socket", "", "指定本机 Tailscale IPC")
	tsCLI := f.String("tailscale", "", "指定 Tailscale CLI")
	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *peer == "" || f.NArg() != 0 || *duration < 0 || (*duration > 0 && *duration < time.Minute) || *duration > 24*time.Hour {
		fmt.Fprintln(errOut, "请指定 --peer 和有效的服务期限")
		return 2
	}
	if *duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *duration)
		defer cancel()
	}
	backend := adapter.New(*socket, *tsCLI)
	if *sudoRestun && runtime.GOOS != "linux" {
		fmt.Fprintln(errOut, "--sudo-restun 仅用于 Linux 助手")
		return 2
	}
	backend.AllowSudoRestun = *sudoRestun
	a, err := optimize.NewAssistant(ctx, backend, *peer)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	if *listen == "" {
		ip, err := diagnostic.TargetIP(&model.Peer{Node: a.Self})
		if err != nil {
			fmt.Fprintln(errOut, err)
			return 1
		}
		*listen = net.JoinHostPort(ip.String(), fmt.Sprint(optimize.DefaultPort))
	}
	l, err := a.Listen(*listen)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	defer l.Close()
	ready := struct {
		Kind              string `json:"kind"`
		Listen            string `json:"listen"`
		SelfID            string `json:"self_id"`
		PeerID            string `json:"allowed_peer_id"`
		PersistentChanges bool   `json:"persistent_configuration_changes"`
	}{"assist_ready", l.Addr().String(), a.Self.ID, a.Peer.ID, false}
	if *output != "" {
		if err := saveReport(*output, ready); err != nil {
			fmt.Fprintln(errOut, err)
			return 1
		}
	}
	_ = json.NewEncoder(out).Encode(ready)
	if err := a.Serve(ctx, l); err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	return 0
}
