package mapping

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"sync"
	"unsafe"
)

// Start captures only during bootstrap, on the selected physical IPv4 interface.
// IP-level mode avoids promiscuous capture; unrelated packets are never persisted.
func (NativeCapture) Start(ctx context.Context, in Input, deliver func(Injection)) (func() error, error) {
	if !in.Native.IsValid() || !in.Native.Addr().Is4() || len(in.Peers) == 0 {
		return nil, errors.New("invalid capture endpoint")
	}
	var data windows.WSAData
	if err := windows.WSAStartup(0x202, &data); err != nil {
		return nil, err
	}
	fd, err := windows.Socket(windows.AF_INET, windows.SOCK_RAW, windows.IPPROTO_IP)
	if err != nil {
		windows.WSACleanup()
		return nil, fmt.Errorf("raw capture requires an administrator session: %w", err)
	}
	fail := func(err error) (func() error, error) { windows.Closesocket(fd); windows.WSACleanup(); return nil, err }
	if err = windows.Bind(fd, &windows.SockaddrInet4{Addr: in.Native.Addr().As4()}); err != nil {
		return fail(err)
	}
	mode := uint32(3)
	var returned uint32
	if err = windows.WSAIoctl(fd, 0x98000001, (*byte)(unsafe.Pointer(&mode)), 4, nil, 0, &returned, nil, 0); err != nil {
		return fail(fmt.Errorf("enable IP-level capture: %w", err))
	}
	ctx, cancel := context.WithCancel(ctx)
	var once sync.Once
	closed := make(chan struct{})
	closeSocket := func() { once.Do(func() { cancel(); windows.Closesocket(fd) }) }
	go func() { <-ctx.Done(); closeSocket() }()
	go func() {
		defer close(closed)
		defer windows.WSACleanup()
		defer closeSocket()
		buf := make([]byte, 65535)
		for {
			n, _, err := windows.Recvfrom(fd, buf, 0)
			if err != nil {
				return
			}
			if packet, ok := capturedDiscovery(buf[:n], 12, in); ok {
				deliver(packet)
			}
		}
	}()
	return func() error { closeSocket(); <-closed; return nil }, nil
}
