//go:build !windows

package adapter

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

func (c *Client) physicalRoute(ctx context.Context, peer netip.AddrPort) (string, netip.Addr, error) {
	route, err := c.Runner(ctx, "/sbin/route", []string{"-n", "get", peer.Addr().String()})
	if err != nil {
		return "", netip.Addr{}, fmt.Errorf("physical route unavailable: %w", err)
	}
	match := regexp.MustCompile(`(?m)^\s*interface:\s*(en[0-9]+)\s*$`).FindSubmatch(route)
	if len(match) != 2 {
		return "", netip.Addr{}, errors.New("selected route is not a supported physical Mac en interface")
	}
	iface := string(match[1])
	localRaw, err := c.Runner(ctx, "/usr/sbin/ipconfig", []string{"getifaddr", iface})
	if err != nil {
		return "", netip.Addr{}, err
	}
	localIP, err := netip.ParseAddr(strings.TrimSpace(string(localRaw)))
	if err != nil || !localIP.Is4() || localIP.IsLoopback() || localIP.IsUnspecified() {
		return "", netip.Addr{}, errors.New("physical IPv4 address unavailable")
	}

	return iface, localIP, nil
}
