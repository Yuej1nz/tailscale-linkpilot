package mapping

import (
	"context"
	"encoding/json"
	"errors"
	"golang.org/x/sys/windows"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"
)

func currentSID() (string, error) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", err
	}
	return u.User.Sid.String(), nil
}
func privateACL(path string) error {
	sid, err := currentSID()
	if err != nil {
		return err
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	if owner.String() != sid && owner.String() != "S-1-5-18" && owner.String() != "S-1-5-32-544" {
		return errors.New("runtime path has foreign owner")
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if acl == nil {
		return errors.New("runtime path has unrestricted ACL")
	}
	for i := uint16(0); i < acl.AceCount; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, uint32(i), &ace); err != nil {
			return err
		}
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return errors.New("unsupported runtime ACE")
		}
		allowed := (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
		if allowed != sid && allowed != "S-1-5-18" {
			return errors.New("runtime ACL grants access to another principal")
		}
	}
	return nil
}
func privateDirectory(path string, create bool) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) && create {
		sid, e := currentSID()
		if e != nil {
			return e
		}
		sd, e := windows.SecurityDescriptorFromString("O:" + sid + "D:P(A;OICI;FA;;;" + sid + ")(A;OICI;FA;;;SY)")
		if e != nil {
			return e
		}
		name, e := windows.UTF16PtrFromString(path)
		if e != nil {
			return e
		}
		sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
		if e = windows.CreateDirectory(name, &sa); e != nil {
			return e
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("invalid runtime directory")
	}
	return privateACL(path)
}
func privateFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("invalid runtime file")
	}
	return privateACL(path)
}
func privateSocket(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSocket == 0 {
		return errors.New("invalid runtime socket")
	}
	return privateACL(path)
}

func Spawn(ctx context.Context, input Input, tried []uint16, prepare, lease time.Duration) (Session, error) {
	dir, err := prepareSessionDirectory(ctx, input)
	if err != nil {
		return nil, err
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	read, write, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer read.Close()
	defer write.Close()
	logPath := filepath.Join(dir, "last-worker.log")
	if _, err := os.Lstat(logPath); err == nil {
		if err := privateFile(logPath); err != nil {
			return nil, err
		}
	}
	log, err := os.OpenFile(logPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	defer log.Close()
	newCommand := func(flags uint32) *exec.Cmd {
		cmd := exec.Command(exe, "session-worker")
		cmd.Stdin = read
		cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: flags, HideWindow: true}
		cmd.Stdout, cmd.Stderr = log, log
		return cmd
	}
	// Interactive SSH needs a detached carrier; a permanent scheduled-task
	// owner may forbid breakaway and can safely own the carrier itself.
	cmd := newCommand(0x01000208)
	err = cmd.Start()
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) && os.Getenv("TSLINK_MANAGED_WORKER") == "1" {
		cmd = newCommand(0x208)
		err = cmd.Start()
	}
	if err != nil {
		return nil, err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	cfg := Config{Input: input, SessionID: randomToken(), Token: randomToken(), Directory: dir, Tried: append([]uint16(nil), tried...), Prepare: prepare, Lease: lease}
	if err := json.NewEncoder(write).Encode(cfg); err != nil {
		_ = cmd.Process.Kill()
		return nil, err
	}
	_ = write.Close()
	deadline := time.NewTimer(4 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case err := <-done:
			data, _ := os.ReadFile(logPath)
			if len(data) > 512 {
				data = data[:512]
			}
			return nil, errors.New("local carrier exited before readiness: " + string(data) + " (" + errorText(err) + ")")
		case <-ctx.Done():
			_ = cmd.Process.Kill()
			return nil, ctx.Err()
		case <-deadline.C:
			_ = cmd.Process.Kill()
			return nil, errors.New("local carrier readiness timed out")
		case <-tick.C:
			s, state, err := ActiveFor(ctx, input.SelfID, input.PeerID)
			if err == nil && state.SessionID == cfg.SessionID {
				return s, nil
			}
		}
	}
}

func errorText(err error) string {
	if err == nil {
		return "exit 0"
	}
	return err.Error()
}

func ReadWorkerConfig() (Config, error) {
	file := os.Stdin
	if file == nil {
		return Config{}, errors.New("worker requires inherited configuration pipe")
	}
	defer file.Close()
	var cfg Config
	err := json.NewDecoder(io.LimitReader(file, 32<<10)).Decode(&cfg)
	return cfg, err
}
