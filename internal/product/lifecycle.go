package product

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unicode/utf16"
)

type serviceControl interface {
	Running(context.Context) (bool, error)
	Start(context.Context) error
	Stop(context.Context) error
}

type nativeService struct {
	platform, home, domain string
	store                  Store
	run                    func(context.Context, string, ...string) ([]byte, error)
}

func serviceOutput(ctx context.Context, name string, args ...string) ([]byte, error) {
	data, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return data, fmt.Errorf("%s: %w: %.1024s", name, err, data)
	}
	return data, nil
}

func manageService(ctx context.Context, s Store, operation string, out io.Writer) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	abs, err := filepath.Abs(s.Dir)
	if err != nil {
		return err
	}
	s.Dir = abs
	if _, err := os.Stat(s.Dir); err != nil {
		return errors.New("尚未安装后台服务，请先执行 tslink install")
	}
	unlock, err := fileLock(filepath.Join(s.Dir, "service-control.lock"))
	if err != nil {
		return err
	}
	defer unlock()
	ctx, cancel := context.WithTimeout(ctx, 55*time.Second)
	defer cancel()
	native := nativeService{platform: runtime.GOOS, home: home, domain: fmt.Sprintf("gui/%d", os.Getuid()), store: s, run: serviceOutput}
	if err := native.checkRegistration(); err != nil {
		return err
	}
	return controlService(ctx, s, operation, &native, out)
}

// Service commands never install, grant permissions, or modify target choices.
// The native manager confirms process state; a fresh heartbeat confirms health.
func controlService(ctx context.Context, s Store, operation string, native serviceControl, out io.Writer) error {
	if operation != "start" && operation != "stop" && operation != "restart" {
		return errors.New("unknown service operation")
	}
	if operation != "stop" {
		cfg, err := s.Config()
		if err != nil || cfg.SelfID == "" {
			return errors.New("尚未安装或本机配置损坏，请执行 tslink install")
		}
	}
	running, err := native.Running(ctx)
	if err != nil {
		return err
	}
	if operation == "start" && running {
		if err := waitReady(ctx, s, 20*time.Second, time.Time{}); err != nil {
			return fmt.Errorf("后台进程已运行，但健康验证失败；可执行 tslink restart，更新程序后请执行 tslink install: %w", err)
		}
		fmt.Fprintln(out, Name+" 后台已在运行，无需重复启动。")
		return nil
	}
	if operation == "stop" || operation == "restart" {
		// Stop also clears queued Windows retries. It is safe when already stopped.
		if err := native.Stop(ctx); err != nil {
			return err
		}
		if err := waitServiceStopped(ctx, native, s); err != nil {
			return err
		}
	} else if err := waitServiceStopped(ctx, native, s); err != nil {
		return err
	}
	// Discard a heartbeat from the previous process only after the OS confirms
	// that process is gone. Otherwise stop/start could report stale success.
	if err := os.Remove(filepath.Join(s.Dir, "heartbeat.json")); err != nil && !os.IsNotExist(err) {
		return err
	}
	if operation == "stop" {
		fmt.Fprintln(out, Name+" 后台已停止，目标与授权配置已保留。")
		return nil
	}
	started := time.Now().UTC()
	if err := native.Start(ctx); err != nil {
		return err
	}
	if err := waitReady(ctx, s, 20*time.Second, started); err != nil {
		return fmt.Errorf("服务已请求启动，但健康验证失败，请检查 daemon.log 或系统服务日志: %w", err)
	}
	if running, err := native.Running(ctx); err != nil || !running {
		return errors.New("后台发布状态后已退出，请检查服务日志")
	}
	fmt.Fprintln(out, Name+" 后台已启动，健康验证通过。使用 tslink status 查看状态。")
	return nil
}

func waitServiceStopped(ctx context.Context, native serviceControl, s Store) error {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	for {
		running, err := native.Running(ctx)
		if err != nil {
			return err
		}
		if !running {
			// launchctl can remove a job before its old process finishes exiting.
			// Wait for its daemon lock too, avoiding port conflicts and old cleanup
			// erasing the new process's heartbeat during restart.
			unlock, err := fileLock(filepath.Join(s.Dir, "daemon.lock"))
			if err == nil {
				unlock()
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("后台停止未完成: %w", ctx.Err())
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func (n *nativeService) checkRegistration() error {
	var path string
	switch n.platform {
	case "linux":
		path = filepath.Join(n.home, ".config", "systemd", "user", "tslink.service")
	case "darwin":
		path = filepath.Join(n.home, "Library", "LaunchAgents", "net.tslink.agent.plist")
	case "windows":
		return nil // Each COM operation verifies the task's arguments before use.
	default:
		return errors.New("unsupported service platform")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("后台服务未安装，请执行 tslink install: %w", err)
	}
	if n.platform == "linux" {
		if strings.Contains(string(data), "--state-dir "+systemdQuote(n.store.Dir)+"\n") {
			return nil
		}
	} else {
		args, err := launchAgentArguments(data)
		if err != nil {
			return err
		}
		if len(args) == 4 && args[1] == "daemon" && args[2] == "--state-dir" && filepath.Clean(args[3]) == filepath.Clean(n.store.Dir) {
			return nil
		}
	}
	return errors.New("已登记服务使用另一配置目录；请使用其 --state-dir，或执行 tslink install 登记当前目录")
}

func launchAgentArguments(data []byte) ([]string, error) {
	d := xml.NewDecoder(strings.NewReader(string(data)))
	key := ""
	for {
		t, err := d.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil, errors.New("LaunchAgent 缺少 ProgramArguments")
			}
			return nil, err
		}
		start, ok := t.(xml.StartElement)
		if !ok {
			continue
		}
		if start.Name.Local == "key" {
			if err := d.DecodeElement(&key, &start); err != nil {
				return nil, err
			}
		} else if start.Name.Local == "array" && key == "ProgramArguments" {
			var array struct {
				Values []string `xml:"string"`
			}
			if err := d.DecodeElement(&array, &start); err != nil {
				return nil, err
			}
			return array.Values, nil
		}
	}
}

func (n *nativeService) Running(ctx context.Context) (bool, error) {
	switch n.platform {
	case "linux":
		data, err := n.run(ctx, "systemctl", "--user", "show", "tslink.service", "-p", "LoadState", "-p", "ActiveState")
		if err != nil {
			return false, err
		}
		if !strings.Contains(string(data), "LoadState=loaded\n") {
			return false, errors.New("后台服务未加载，请执行 tslink install")
		}
		return strings.Contains(string(data), "ActiveState=active\n") || strings.Contains(string(data), "ActiveState=activating\n") || strings.Contains(string(data), "ActiveState=deactivating\n"), nil
	case "darwin":
		data, err := n.run(ctx, "launchctl", "print", n.domain+"/net.tslink.agent")
		if err == nil {
			// Loaded KeepAlive jobs count as active even between process launches.
			return true, nil
		}
		if strings.Contains(string(data), "Could not find service") {
			return false, nil
		}
		return false, err
	case "windows":
		data, err := n.windows(ctx, "query")
		if err != nil {
			return false, err
		}
		var state struct {
			State int `json:"state"`
		}
		if err := json.Unmarshal(data, &state); err != nil {
			return false, fmt.Errorf("读取 Windows 后台状态: %w", err)
		}
		if state.State < 1 || state.State > 4 {
			return false, errors.New("Windows 返回未知的后台任务状态")
		}
		return state.State == 4, nil
	}
	return false, errors.New("unsupported service platform")
}

func (n *nativeService) Start(ctx context.Context) error {
	switch n.platform {
	case "linux":
		_, err := n.run(ctx, "systemctl", "--user", "start", "tslink.service")
		return err
	case "darwin":
		_, err := n.run(ctx, "launchctl", "bootstrap", n.domain, filepath.Join(n.home, "Library", "LaunchAgents", "net.tslink.agent.plist"))
		return err
	case "windows":
		_, err := n.windows(ctx, "start")
		return err
	}
	return errors.New("unsupported service platform")
}

func (n *nativeService) Stop(ctx context.Context) error {
	switch n.platform {
	case "linux":
		_, err := n.run(ctx, "systemctl", "--user", "stop", "tslink.service")
		return err
	case "darwin":
		running, err := n.Running(ctx)
		if err != nil || !running {
			return err
		}
		_, err = n.run(ctx, "launchctl", "bootout", n.domain+"/net.tslink.agent")
		return err
	case "windows":
		_, err := n.windows(ctx, "stop")
		return err
	}
	return errors.New("unsupported service platform")
}

// COM works without the ScheduledTasks CIM provider, which can be unavailable
// on otherwise functional Windows installations. Operations stay user-scoped.
func (n *nativeService) windows(ctx context.Context, operation string) ([]byte, error) {
	code := `$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
trap {[Console]::Error.WriteLine($_.Exception.Message);exit 1}
$scheduler=New-Object -ComObject 'Schedule.Service';$scheduler.Connect()
try {$task=$scheduler.GetFolder('\').GetTask('Tailscale LinkPilot')} catch {throw 'Background task unavailable: run tslink install first'}
$action=$task.Definition.Actions.Item(1)
if($task.Definition.Actions.Count -ne 1 -or $action.Arguments -cne ` + psQuote("daemon --state-dir \""+n.store.Dir+"\"") + `){throw 'Registered task uses another state directory; use its --state-dir or run tslink install'}
`
	switch operation {
	case "query":
		code += `[pscustomobject]@{state=$task.State}|ConvertTo-Json -Compress`
	case "start":
		code += `if($task.State -ne 4){$task.Stop(0);$null=$task.Run($null)}`
	case "stop":
		code += `$task.Stop(0)`
	default:
		return nil, errors.New("invalid Windows service operation")
	}
	words := utf16.Encode([]rune(code))
	raw := make([]byte, len(words)*2)
	for i, v := range words {
		raw[i*2], raw[i*2+1] = byte(v), byte(v>>8)
	}
	return n.run(ctx, "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(raw))
}
