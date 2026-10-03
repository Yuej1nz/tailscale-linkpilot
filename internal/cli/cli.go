package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/Yuej1nz/tailscale-linkpilot/internal/adapter"
	"github.com/Yuej1nz/tailscale-linkpilot/internal/diagnostic"
	"github.com/Yuej1nz/tailscale-linkpilot/internal/model"
)

const Version = "0.4.0-windows-client"

func Run(ctx context.Context, args []string, out, errOut io.Writer) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		fmt.Fprintln(out, "ts-direct: Tailscale 诊断与 Mac / Windows 直连恢复工具\n\n命令: status | diagnose | plan | optimize | assist | session | version\noptimize --peer <对端> --once：Mac / Windows 动态会话搜索与业务验证；对端运行 assist。\nsession status | stop：查看或停止保留的本地 UDP 会话。\n用法: ts-direct <命令> --help")
		return 0
	}
	command := args[0]
	if command == "session-worker" {
		return runSessionWorker(ctx, args[1:], errOut)
	}
	if command == "session" {
		return runSession(ctx, args[1:], out, errOut)
	}
	if command == "optimize" {
		return runOptimize(ctx, args[1:], out, errOut)
	}
	if command == "assist" {
		return runAssist(ctx, args[1:], out, errOut)
	}
	if command == "version" {
		fmt.Fprintln(out, Version)
		return 0
	}
	if command != "status" && command != "diagnose" && command != "plan" {
		fmt.Fprintln(errOut, "未知或尚未实现的命令:", command)
		return 2
	}
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(errOut)
	peer := flags.String("peer", "", "对端节点 ID、设备名或 Tailscale IP")
	asJSON := flags.Bool("json", false, "输出结构化 JSON")
	output := flags.String("output", "", "保存报告到新文件；不覆盖已有文件")
	socket := flags.String("socket", "", "指定本机 Tailscale IPC 地址")
	tsCLI := flags.String("tailscale", "", "Tailscale CLI 路径，默认自动寻找")
	timeout := flags.Duration("timeout", 3*time.Second, "单次探测超时（200ms 至 10s）")
	budget := flags.Duration("budget", 20*time.Second, "总时限（1s 至 60s）")
	count := flags.Int("count", 3, "disco 探测次数（1 至 10）")
	wireguard := flags.Bool("wireguard", true, "diagnose 同时执行一次 TSMP 探测")
	fromReport := flags.String("from-report", "", "plan 从已有 JSON 报告生成建议，不连接客户端")
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(errOut, "不接受位置参数；请使用 --peer")
		return 2
	}
	if *budget < time.Second || *budget > 60*time.Second {
		fmt.Fprintln(errOut, "--budget 必须在 1s 至 60s 之间")
		return 2
	}
	if *fromReport != "" && command != "plan" {
		fmt.Fprintln(errOut, "--from-report 仅用于 plan")
		return 2
	}
	if command != "status" && *peer == "" {
		fmt.Fprintln(errOut, "请指定 --peer")
		return 2
	}
	ctx, cancel := context.WithTimeout(ctx, *budget)
	defer cancel()
	var r *model.Report
	var err error
	if *fromReport != "" {
		r, err = readReport(*fromReport)
		if err == nil {
			err = diagnostic.Plan(r, *peer)
			r.Warnings = append(r.Warnings, "loaded_report; no_new_probes_performed")
		}
	} else {
		a := adapter.New(*socket, *tsCLI)
		if command == "diagnose" {
			r, err = diagnostic.Diagnose(ctx, a, diagnostic.Options{Peer: *peer, Count: *count, Timeout: *timeout, Budget: *budget, WireGuard: *wireguard})
		} else {
			r, err = diagnostic.Status(ctx, a, *peer)
			if err == nil && command == "plan" {
				err = diagnostic.Plan(r, *peer)
			}
		}
	}
	if err != nil {
		r = &model.Report{SchemaVersion: model.SchemaVersion, Kind: command, CollectedAt: time.Now().UTC(), Error: &model.Problem{Code: "command_failed", Message: err.Error()}}
		if *output != "" {
			if saveErr := saveReport(*output, r); saveErr != nil {
				fmt.Fprintln(errOut, "失败报告保存失败:", saveErr)
			}
		}
		if *asJSON {
			_ = json.NewEncoder(out).Encode(r)
		} else {
			fmt.Fprintln(errOut, "诊断未完成:", err)
		}
		return 1
	}
	if *output != "" {
		if err := saveReport(*output, r); err != nil {
			fmt.Fprintln(errOut, "报告保存失败:", err)
			return 1
		}
	}
	if *asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(r); err != nil {
			fmt.Fprintln(errOut, err)
			return 1
		}
	} else {
		render(out, r)
	}
	if command == "diagnose" && (r.Summary == nil || r.Summary.DiscoverySuccesses == 0) {
		return 1
	}
	return 0
}

func readReport(path string) (*model.Report, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 4*1024*1024+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 4*1024*1024 {
		return nil, errors.New("report exceeds 4 MiB")
	}
	var r model.Report
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}
	if r.Error != nil {
		return nil, errors.New("saved report contains a command error")
	}
	return &r, nil
}

func saveReport(path string, r any) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(append(data, '\n'))
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil {
		_ = os.Remove(path)
		return errors.Join(writeErr, closeErr)
	}
	return nil
}

func render(w io.Writer, r *model.Report) {
	fmt.Fprintf(w, "本机: %s | Tailscale %s | %s\n", r.Self.Name, r.Client.Version, r.BackendState)
	fmt.Fprintf(w, "采集方式: %s | 主动探测: %t | 修改配置: %t\n", r.Client.Transport, r.ActiveProbes, r.ConfigurationChanges)
	for _, p := range r.Peers {
		path := p.Path.ReportedType
		if path == "" {
			path = "unknown"
		}
		fmt.Fprintf(w, "对端: %s (%s) | 控制连接在线: %t | 报告路径: %s（未主动验证）\n", p.Name, p.ID, p.Online, path)
	}
	if r.Summary != nil {
		fmt.Fprintf(w, "本轮路径探测: %d/%d 次收到可识别回复\n", r.Summary.DiscoverySuccesses, r.Summary.DiscoveryAttempts)
		if p := r.Summary.LastProbePath; p != nil {
			fmt.Fprintf(w, "最后一次探测: %s | 外层: %s | 端点: %s | 公网路径证明: %s\n", p.Type, p.UnderlayFamily, p.Endpoint, p.NetworkScope)
		}
		fmt.Fprintf(w, "WireGuard 可达性: %s | 应用验证: %s\n", r.Summary.WireGuardReachability, r.Summary.ApplicationVerification)
		for _, p := range r.Probes {
			if p.Error != nil {
				fmt.Fprintf(w, "%s: %s (%s)\n", p.Kind, p.Error.Code, p.Error.Message)
			}
		}
	}
	if r.Plan != nil {
		fmt.Fprintln(w, "建议预览（本次不执行）:")
		for _, a := range r.Plan.Actions {
			fmt.Fprintf(w, "- %s: %s\n", a.ID, a.Reason)
		}
	}
	for _, s := range r.Warnings {
		fmt.Fprintln(w, "提示:", s)
	}
}
