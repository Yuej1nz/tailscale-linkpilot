package product

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"unicode/utf16"
)

func quote(s string) string   { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }
func psQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
func powershell(ctx context.Context, code string) error {
	code = "$ProgressPreference='SilentlyContinue'; [Console]::OutputEncoding=[System.Text.Encoding]::UTF8; " + code
	words := utf16.Encode([]rune(code))
	raw := make([]byte, len(words)*2)
	for i, v := range words {
		raw[i*2] = byte(v)
		raw[i*2+1] = byte(v >> 8)
	}
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-EncodedCommand", base64.StdEncoding.EncodeToString(raw))
	data, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("Windows service setup: %w: %s", err, data)
	}
	return nil
}
func Install(ctx context.Context, s Store, allow []string, sudoRestun bool) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.Dir, 0700); err != nil {
		return err
	}
	if err := s.Update(func(c *Config) error {
		for _, id := range allow {
			c.Allow(id)
		}
		c.SudoRestun = c.SudoRestun || sudoRestun
		return nil
	}); err != nil {
		return err
	}
	switch runtime.GOOS {
	case "linux":
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		dir := filepath.Join(home, ".config", "systemd", "user")
		if err = os.MkdirAll(dir, 0700); err != nil {
			return err
		}
		// systemd does not use shell quoting; escape only for its argument grammar.
		unit := fmt.Sprintf("[Unit]\nDescription=%s\nStartLimitIntervalSec=60\nStartLimitBurst=5\n\n[Service]\nExecStart=%s daemon --state-dir %s\nRestart=on-failure\nRestartSec=5\nUMask=0077\n\n[Install]\nWantedBy=default.target\n", Name, systemdQuote(exe), systemdQuote(s.Dir))
		if err = writeText(filepath.Join(dir, "tslink.service"), unit); err != nil {
			return err
		}
		if err = command(ctx, "systemctl", "--user", "daemon-reload"); err != nil {
			return err
		}
		if err = command(ctx, "systemctl", "--user", "enable", "tslink.service"); err != nil {
			return err
		}
		return command(ctx, "systemctl", "--user", "restart", "tslink.service")
	case "windows":

		home, e := os.UserHomeDir()
		if e != nil {
			return e
		}
		shortcutDir := filepath.Join(home, "bin")
		if e = os.MkdirAll(shortcutDir, 0700); e != nil {
			return e
		}
		shortcut := "@echo off\r\nchcp 65001 >nul\r\n\"" + strings.ReplaceAll(exe, "%", "%%") + "\" %*\r\n"
		if e = writeText(filepath.Join(shortcutDir, "tslink.cmd"), shortcut); e != nil {
			return e
		}
		// The task uses the currently logged-in user's existing elevated token. No
		// password is stored; it restarts at login and remains after this terminal.
		args := "daemon --state-dir \"" + s.Dir + "\""
		code := `$ErrorActionPreference='Stop'
$principal=[Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Run tslink install as administrator'}

$bin=Join-Path $env:USERPROFILE 'bin'
$path=[Environment]::GetEnvironmentVariable('Path','User')
$paths=@($path -split ';' | Where-Object { $_ })
if(-not ($paths | Where-Object {[Environment]::ExpandEnvironmentVariables($_).TrimEnd('\') -ieq $bin})){
 [Environment]::SetEnvironmentVariable('Path',(($paths+$bin)-join ';'),'User')
}
$user=[Security.Principal.WindowsIdentity]::GetCurrent().Name
$a=New-ScheduledTaskAction -Execute ` + psQuote(exe) + ` -Argument ` + psQuote(args) + `
$t=New-ScheduledTaskTrigger -AtLogOn -User $user
$p=New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest
$settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 5 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName 'Tailscale LinkPilot' -Action $a -Trigger $t -Principal $p -Settings $settings -Force | Out-Null
$rule=Get-NetFirewallRule -DisplayName 'Tailscale LinkPilot coordination' -ErrorAction SilentlyContinue
if($rule){$rule | Remove-NetFirewallRule}
New-NetFirewallRule -DisplayName 'Tailscale LinkPilot coordination' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 45829 -RemoteAddress '100.64.0.0/10','fd7a:115c:a1e0::/48' -Program ` + psQuote(exe) + ` | Out-Null
Stop-ScheduledTask -TaskName 'Tailscale LinkPilot' -ErrorAction SilentlyContinue
Start-ScheduledTask -TaskName 'Tailscale LinkPilot'
`
		return powershell(ctx, code)
	case "darwin":
		home, e := os.UserHomeDir()
		if e != nil {
			return e
		}
		binDir := filepath.Join(home, "bin")
		if e = os.MkdirAll(binDir, 0700); e != nil {
			return e
		}
		entry := filepath.Join(binDir, "tslink")
		if entry != exe {
			data, e := os.ReadFile(exe)
			if e != nil {
				return e
			}
			f, e := os.CreateTemp(binDir, ".tslink-")
			if e != nil {
				return e
			}
			temp := f.Name()
			defer os.Remove(temp)
			if _, e = f.Write(data); e == nil {
				e = f.Chmod(0700)
			}
			ce := f.Close()
			if e == nil {
				e = ce
			}
			if e != nil {
				return e
			}
			if e = os.Rename(temp, entry); e != nil {
				return e
			}
			exe = entry
		}
		// Terminal.app opens a login shell. Keep PATH changes confined to this
		// user, and preserve any existing shell configuration.
		profile := ".zprofile"
		if filepath.Base(os.Getenv("SHELL")) == "bash" {
			profile = ".bash_profile"
		}
		pathFile := filepath.Join(home, profile)
		line := "export PATH=\"$HOME/bin:$PATH\""
		old, e := os.ReadFile(pathFile)
		if e != nil && !os.IsNotExist(e) {
			return e
		}
		if !strings.Contains(string(old), line) {
			f, e := os.OpenFile(pathFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
			if e != nil {
				return e
			}
			_, e = f.WriteString("\n# Tailscale LinkPilot\n" + line + "\n")
			ce := f.Close()
			if e == nil {
				e = ce
			}
			if e != nil {
				return e
			}
		}
		// First install/update uses interactive sudo once to create a root-owned
		// fixed-purpose helper and an exact-command rule. No password is saved.
		setup := exec.CommandContext(ctx, "/usr/bin/sudo", exe, "install-capture")
		setup.Stdin, setup.Stdout, setup.Stderr = os.Stdin, os.Stdout, os.Stderr
		if e := setup.Run(); e != nil {
			return fmt.Errorf("Mac capture installation: %w", e)
		}
		dir := filepath.Join(home, "Library", "LaunchAgents")
		if e = os.MkdirAll(dir, 0700); e != nil {
			return e
		}
		plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>Label</key><string>net.tslink.agent</string>
<key>ProgramArguments</key><array><string>%s</string><string>daemon</string><string>--state-dir</string><string>%s</string></array>
<key>RunAtLoad</key><true/><key>KeepAlive</key><true/><key>ThrottleInterval</key><integer>10</integer>
<key>StandardOutPath</key><string>%s</string><key>StandardErrorPath</key><string>%s</string>
</dict></plist>`, xmlEscape(exe), xmlEscape(s.Dir), xmlEscape(filepath.Join(s.Dir, "daemon.log")), xmlEscape(filepath.Join(s.Dir, "daemon.log")))
		path := filepath.Join(dir, "net.tslink.agent.plist")
		if e = writeText(path, plist); e != nil {
			return e
		}
		domain := fmt.Sprintf("gui/%d", os.Getuid())
		_ = command(ctx, "launchctl", "bootout", domain+"/net.tslink.agent")
		return command(ctx, "launchctl", "bootstrap", domain, path)
	}
	return errors.New("unsupported service platform")
}
func systemdQuote(s string) string {
	return "\"" + strings.NewReplacer("\\", "\\\\", "\"", "\\\"", "%", "%%").Replace(s) + "\""
}
func xmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\"", "&quot;").Replace(s)
}
func writeText(path, data string) error { return os.WriteFile(path, []byte(data), 0600) }
func command(ctx context.Context, name string, args ...string) error {
	data, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w: %.1024s", name, err, data)
	}
	return nil
}
