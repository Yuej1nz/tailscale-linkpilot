package product

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

var sshTarget = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.@-]{0,253}$`)

// Deploy uses an explicitly selected SSH management identity and a local
// platform binary. It never guesses passwords or trusts an unauthenticated
// download to install privileged code.
func Deploy(ctx context.Context, target, selfID string) error {
	if !sshTarget.MatchString(target) {
		return errors.New("invalid SSH target")
	}

	// Existing installations accept a new peer by updating the local allowlist.
	// Do not restart a shared coordinator just to onboard another machine.
	registration := `if [ -x "$HOME/.local/bin/tslink" ]; then "$HOME/.local/bin/tslink" authorize ` + quote(selfID) + `; elif [ -x "$HOME/bin/tslink" ]; then "$HOME/bin/tslink" authorize ` + quote(selfID) + `; else exit 44; fi`
	data, e := exec.CommandContext(ctx, "ssh", target, registration).CombinedOutput()
	if e == nil {
		return nil
	}
	if exit, ok := e.(*exec.ExitError); !ok || exit.ExitCode() != 44 {
		return fmt.Errorf("remote authorization: %w: %.1024s", e, data)
	}
	out, err := exec.CommandContext(ctx, "ssh", target, "uname -s; uname -m").Output()
	if err != nil {
		return fmt.Errorf("SSH management access required: %w", err)
	}
	words := strings.Fields(string(out))
	if len(words) != 2 {
		return errors.New("unrecognized remote platform")
	}
	platform := ""
	switch words[0] {
	case "Linux":
		platform = "linux"
	case "Darwin":
		platform = "darwin"
	default:
		return errors.New("automatic SSH deployment currently supports Linux and macOS targets")
	}
	arch := ""
	switch words[1] {
	case "x86_64":
		arch = "amd64"
	case "aarch64", "arm64":
		arch = "arm64"
	default:
		return errors.New("unsupported remote architecture")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	filename := "tslink-" + platform + "-" + arch
	choices := []string{filepath.Join(filepath.Dir(exe), filename), filepath.Join(filepath.Dir(exe), "delivery", filename)}
	artifact := ""
	for _, p := range choices {
		if info, e := os.Stat(p); e == nil && info.Mode().IsRegular() {
			artifact = p
			break
		}
	}
	if artifact == "" {
		return fmt.Errorf("platform bundle missing %s; install full release bundle", filename)
	}
	if err = command(ctx, "ssh", target, `mkdir -p "$HOME/.local/bin"`); err != nil {
		return err
	}
	tmp := ".local/bin/tslink.upload"
	if err = command(ctx, "scp", artifact, target+":"+tmp); err != nil {
		return err
	}
	// The self ID comes from the native snapshot, but still quote it as data.
	code := `chmod 700 "$HOME/.local/bin/tslink.upload" && mv "$HOME/.local/bin/tslink.upload" "$HOME/.local/bin/tslink" && "$HOME/.local/bin/tslink" install --allow ` + quote(selfID)
	return command(ctx, "ssh", target, code)
}
