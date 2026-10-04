package product

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Yuej1nz/tailscale-linkpilot/internal/adapter"
	"github.com/Yuej1nz/tailscale-linkpilot/internal/diagnostic"
	"github.com/Yuej1nz/tailscale-linkpilot/internal/model"
)

func Run(ctx context.Context, args []string, out, errOut io.Writer) int {
	s, err := DefaultStore()
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	// A single global flag also works after the subcommand in service arguments.
	for i := 0; i < len(args); {
		if args[i] == "--state-dir" {
			if i+1 >= len(args) {
				fmt.Fprintln(errOut, "--state-dir requires a directory")
				return 2
			}
			s.Dir = args[i+1]
			args = append(args[:i], args[i+2:]...)
		} else {
			i++
		}
	}
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" {
		fmt.Fprintln(out, Name+"（适用于 Tailscale 的第三方工具）\n\ntslink install                 安装本机后台服务\ntslink start                   启动后台，已运行时保持不变\ntslink stop                    停止后台，保留配置\ntslink restart                 重启后台并验证健康\ntslink connect <设备>          启用自动优化\ntslink connect --all           自动跟踪本机可见的全部节点\ntslink status                  查看后台与连接状态\ntslink optimize <设备>         立即优化\ntslink pause|resume <设备>     暂停或恢复自动优化\ntslink pause|resume --all      暂停或恢复整个本机调度\ntslink disconnect <设备>       停止优化关系并从全节点模式排除\ntslink disconnect --all       停止全部本机目标和自动发现\ntslink doctor                  检查运行条件\ntslink version\n\n未部署或未授权的对端：connect <设备> --ssh <SSH登录目标>\n全节点模式不批量部署或授权对端；完整发布包提供跨平台对端程序。")
		return 0
	}
	cmd := args[0]
	if cmd == "start" || cmd == "stop" || cmd == "restart" {
		if len(args) != 1 {
			fmt.Fprintln(errOut, "用法：tslink "+cmd)
			return 2
		}
		if err = manageService(ctx, s, cmd, out); err != nil {
			fmt.Fprintln(errOut, err)
			return 1
		}
		return 0
	}
	if cmd == "version" {
		fmt.Fprintln(out, Name+" "+Version)
		return 0
	}
	if cmd == "daemon" {
		if err = Daemon(ctx, s); err != nil {
			// Windows tasks do not capture stderr. Keep startup/exit failures
			// available to the user without depending on Task Scheduler history.
			if runtime.GOOS == "windows" {
				if f, e := os.OpenFile(filepath.Join(s.Dir, "daemon.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600); e == nil {
					fmt.Fprintln(f, time.Now().UTC().Format(time.RFC3339), err)
					f.Close()
				}
			}
			fmt.Fprintln(errOut, err)
			return 1
		}
		return 0
	}
	if cmd == "status" {
		return status(s, args[1:], out, errOut)
	}
	a := adapter.New("", "")
	snap, err := a.Snapshot(ctx)
	if err != nil {
		fmt.Fprintln(errOut, "Tailscale 未就绪:", err)
		return 1
	}
	if snap.BackendState != "Running" || snap.Self.ID == "" {
		fmt.Fprintln(errOut, "请先登录并启动 Tailscale")
		return 1
	}
	if cmd == "doctor" {
		cfg, _ := s.Config()
		_, e := s.Status()
		fmt.Fprintf(out, "Tailscale: %s\n本机: %s (%s)\n配置目录: %s\n后台在线: %t\n已授权设备: %d\n", snap.Client.Version, snap.Self.Name, snap.Self.ID, s.Dir, e == nil && s.Online(cfg.SelfID), len(cfg.Allowed))
		return 0
	}
	if cmd == "install" {
		f := flag.NewFlagSet("install", flag.ContinueOnError)
		f.SetOutput(errOut)
		allow := f.String("allow", "", "允许协调的设备，多个设备用逗号分隔")
		restun := f.Bool("sudo-restun", false, "Linux 使用已有授权的固定 sudo restun")
		if err = f.Parse(args[1:]); err != nil {
			return flagExit(err)
		}
		if f.NArg() != 0 {
			return 2
		}
		ids := []string{}
		for _, selector := range strings.Split(*allow, ",") {
			if selector == "" {
				continue
			}
			p, e := diagnostic.ResolvePeer(snap, selector)
			if e != nil {
				fmt.Fprintln(errOut, e)
				return 1
			}
			ids = append(ids, p.ID)
		}
		started := time.Now().UTC()
		if err = s.Update(func(c *Config) error {
			if c.SelfID != "" && c.SelfID != snap.Self.ID {
				return errors.New("配置属于另一 Tailscale 身份，请使用独立 --state-dir")
			}
			c.SelfID = snap.Self.ID
			return nil
		}); err == nil {
			err = Install(ctx, s, ids, *restun)
		}
		if err != nil {
			fmt.Fprintln(errOut, err)
			return 1
		}
		if err = waitReady(ctx, s, 20*time.Second, started); err != nil {
			fmt.Fprintln(errOut, "服务已登记，但启动验证失败:", err)
			return 1
		}
		fmt.Fprintln(out, Name+" 后台已启动。下一步：tslink connect <设备>")
		return 0
	}

	if cmd == "authorize" || cmd == "revoke" {
		if len(args) != 2 {
			return 2
		}
		p, e := diagnostic.ResolvePeer(snap, args[1])
		if e != nil {
			fmt.Fprintln(errOut, e)
			return 1
		}
		e = s.Update(func(c *Config) error {
			if c.SelfID != snap.Self.ID {
				return errors.New("尚未安装或本机身份不匹配")
			}
			if cmd == "authorize" {
				c.Allow(p.ID)
			} else {
				kept := c.Allowed[:0]
				for _, id := range c.Allowed {
					if id != p.ID {
						kept = append(kept, id)
					}
				}
				c.Allowed = kept
			}
			return nil
		})
		if e != nil {
			fmt.Fprintln(errOut, e)
			return 1
		}
		fmt.Fprintf(out, "%s: %s，后台无需重启。\n", p.Name, cmd)
		return 0
	}
	if cmd == "connect" {
		if len(args) >= 2 && args[1] == "--all" {
			return connectAll(ctx, s, snap, args[1:], out, errOut)
		}
		if len(args) < 2 || strings.HasPrefix(args[1], "-") {
			fmt.Fprintln(errOut, "tslink connect <设备> [--ssh <登录目标>]")
			return 2
		}
		f := flag.NewFlagSet("connect", flag.ContinueOnError)
		f.SetOutput(errOut)
		ssh := f.String("ssh", "", "用于自动部署或授权对端的 SSH 登录目标")
		if err = f.Parse(args[2:]); err != nil {
			return flagExit(err)
		}
		if f.NArg() != 0 {
			return 2
		}
		p, e := diagnostic.ResolvePeer(snap, args[1])
		if e != nil {
			fmt.Fprintln(errOut, e)
			return 1
		}
		if e = s.Update(func(c *Config) error {
			if c.SelfID != "" && c.SelfID != snap.Self.ID {
				return errors.New("本机身份与配置不匹配")
			}
			c.SelfID = snap.Self.ID
			c.include(p.ID)
			c.Allow(p.ID)
			if t, e := c.Find(p.ID); e == nil {
				t.Enabled = true
				t.Automatic = false
				t.Requested = time.Now().UnixNano()
			} else {
				c.Targets = append(c.Targets, Target{ID: p.ID, Name: p.Name, Enabled: true, Requested: time.Now().UnixNano()})
			}
			return nil
		}); e != nil {
			fmt.Fprintln(errOut, e)
			return 1
		}
		_, e = s.Status()
		if e != nil || !s.Online(snap.Self.ID) {
			cfg, _ := s.Config()
			if e = Install(ctx, s, nil, cfg.SudoRestun); e != nil {
				fmt.Fprintln(errOut, e)
				return 1
			}
		}
		discoveryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		_, info, e := Discover(discoveryCtx, p.Node)
		cancel()
		if (e != nil || !info.Authorized) && *ssh != "" {
			fmt.Fprintln(out, "正在通过指定的 SSH 管理连接安装或授权对端……")
			if e = Deploy(ctx, *ssh, snap.Self.ID); e != nil {
				fmt.Fprintln(errOut, e)
				return 1
			}
			discoveryCtx, cancel = context.WithTimeout(ctx, 8*time.Second)
			_, info, e = Discover(discoveryCtx, p.Node)
			cancel()
		}
		if e != nil || !info.Authorized {
			fmt.Fprintf(errOut, "已保存 %s，但对端部署或授权尚未完成。\n使用 tslink connect %s --ssh <SSH登录目标>，或在对端执行 tslink install --allow %s\n", p.Name, p.Name, snap.Self.ID)
			if e != nil {
				fmt.Fprintln(errOut, e)
			}
			return 1
		}
		fmt.Fprintf(out, "%s 已启用自动优化。后台会确认中继、尝试打洞并在失败后退避。\n", p.Name)
		return 0
	}
	if cmd == "pause" || cmd == "resume" || cmd == "disconnect" || cmd == "optimize" {
		if len(args) != 2 {
			return 2
		}
		if cmd == "optimize" {
			v, e := s.Status()
			if e != nil || v.Version != Version || !s.Online(snap.Self.ID) {
				fmt.Fprintln(errOut, "后台离线或版本不匹配，请执行 tslink install 后再优化")
				return 1
			}
		}
		var id string
		var request int64
		err = s.Update(func(c *Config) error {
			if c.SelfID != snap.Self.ID {
				return errors.New("尚未安装或本机身份不匹配")
			}
			var e error
			id, request, e = applyTargetCommand(c, cmd, args[1], time.Now().UnixNano())
			return e
		})
		if err != nil {
			fmt.Fprintln(errOut, err)
			return 1
		}
		if cmd == "optimize" {
			return waitOptimization(ctx, s, id, request, out, errOut)
		}
		fmt.Fprintf(out, "%s: %s 已保存，后台将应用。\n", args[1], cmd)
		return 0
	}
	fmt.Fprintln(errOut, "未知命令:", cmd)
	return 2
}

func connectAll(ctx context.Context, s Store, snap *model.Report, args []string, out, errOut io.Writer) int {
	if len(args) != 1 || args[0] != "--all" {
		fmt.Fprintln(errOut, "tslink connect --all（不接受批量 SSH 部署参数）")
		return 2
	}
	if err := s.Update(func(c *Config) error {
		if c.SelfID != "" && c.SelfID != snap.Self.ID {
			return errors.New("本机身份与配置不匹配")
		}
		c.SelfID = snap.Self.ID
		c.AllPeers = true
		c.reconcile(snap)
		return nil
	}); err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	state, err := s.Status()
	if err != nil || !s.Online(snap.Self.ID) || state.Version != Version {
		cfg, err := s.Config()
		if err != nil {
			fmt.Fprintln(errOut, err)
			return 1
		}
		started := time.Now().UTC()
		if err := Install(ctx, s, nil, cfg.SudoRestun); err != nil {
			fmt.Fprintln(errOut, err)
			return 1
		}
		if err := waitReady(ctx, s, 20*time.Second, started); err != nil {
			fmt.Fprintln(errOut, "全节点配置已保存，但后台启动验证失败:", err)
			return 1
		}
	}
	c, err := s.Config()
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	fmt.Fprintf(out, "已启用本机全节点模式，当前跟踪 %d 个目标，排除 %d 个节点。\n", len(c.Targets), len(c.Excluded))
	fmt.Fprintln(out, "后台按通信需求串行优化；新节点自动纳入，不自动授予协调权限或部署对端。使用 tslink status 查看结果。")
	if c.Paused {
		fmt.Fprintln(out, "本机调度仍处于暂停状态，使用 tslink resume --all 恢复。")
	}
	return 0
}
func flagExit(err error) int {
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	return 2
}
func waitReady(ctx context.Context, s Store, timeout time.Duration, started time.Time) error {
	cfg, err := s.Config()
	if err != nil || cfg.SelfID == "" {
		return errors.New("本机配置未就绪，请执行 tslink install")
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	for {
		state, e := s.Status()
		var pulse Heartbeat
		_ = readJSON(filepath.Join(s.Dir, "heartbeat.json"), &pulse)
		if e == nil && state.Version == Version && state.SelfID == cfg.SelfID && s.Online(cfg.SelfID) && pulse.At.After(started) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return errors.New("后台未发布健康状态")
		case <-tick.C:
		}
	}
}
func waitOptimization(ctx context.Context, s Store, id string, request int64, out, errOut io.Writer) int {
	deadline := time.NewTimer(210 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	fmt.Fprintln(out, "已请求优化，等待后台结果……")
	for {
		v, e := s.Status()
		if e == nil {
			for _, st := range v.States {
				if st.ID != id || st.LastOptimization == nil || st.LastOptimization.Request != request {
					continue
				}
				result := st.LastOptimization
				fmt.Fprintf(out, "%s: %s\n", st.Name, result.Outcome)
				if result.Error != "" {
					fmt.Fprintln(errOut, result.Error)
				}
				if result.Report != "" {
					fmt.Fprintln(out, "报告:", result.Report)
				}
				if result.DirectVerified {
					return 0
				}
				return 1
			}
		}
		select {
		case <-ctx.Done():
			return 1
		case <-deadline.C:
			fmt.Fprintln(errOut, "等待超时，请使用 tslink status 查看后台")
			return 1
		case <-tick.C:
		}
	}
}
func status(s Store, args []string, out, errOut io.Writer) int {
	if len(args) > 1 || (len(args) == 1 && args[0] != "--json") {
		return 2
	}
	c, err := s.Config()
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	v, e := s.Status()
	online := e == nil && s.Online(c.SelfID)
	if len(args) == 1 {
		data, e := json.MarshalIndent(struct {
			Online bool   `json:"daemon_online"`
			Status Status `json:"status"`
			Config Config `json:"config"`
		}{online, v, c}, "", "  ")
		if e != nil {
			return 1
		}
		fmt.Fprintln(out, string(data))
		return 0
	}
	fmt.Fprintf(out, "%s %s\n后台在线: %t\n", Name, Version, online)
	fmt.Fprintf(out, "全节点模式: %t | 调度暂停: %t | 排除节点: %d\n", c.AllPeers, c.Paused, len(c.Excluded))
	if len(c.Targets) == 0 {
		if c.AllPeers {
			fmt.Fprintln(out, "当前没有可见的未排除目标，后台将继续发现节点。")
		} else {
			fmt.Fprintln(out, "尚未选择目标：tslink connect <设备> 或 tslink connect --all")
		}
	}
	for _, t := range c.Targets {
		phase := "等待后台"
		latency := 0.0
		detail := ""
		path := "unknown"
		if !t.Enabled || c.Paused {
			phase = "paused"
		}
		if online {
			for _, st := range v.States {
				if st.ID == t.ID {
					phase = st.Phase
					latency = st.LatencyMS
					detail = st.Error
					if st.Path != "" {
						path = st.Path
					}
				}
			}
		}
		fmt.Fprintf(out, "%s  %s  %.1f ms  最后检测路径: %s  自动优化: %t\n", t.Name, phase, latency, path, t.Enabled && !c.Paused)
		if detail != "" {
			fmt.Fprintln(out, "  "+detail)
		}
		if online {
			for _, st := range v.States {
				if st.ID == t.ID && st.LastOptimization != nil {
					fmt.Fprintf(out, "  上次优化验收: %t | %s\n", st.LastOptimization.DirectVerified, st.LastOptimization.Outcome)
				}
			}
		}
	}
	if !online {
		fmt.Fprintln(errOut, "后台离线或状态过期，请执行 tslink install")
		return 1
	}
	return 0
}
