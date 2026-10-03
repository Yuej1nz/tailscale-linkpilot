package adapter

import (
	"context"
	"errors"
	"net"
	"net/netip"
)

func (c *Client) physicalRoute(ctx context.Context, peer netip.AddrPort) (string, netip.Addr, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "udp4", peer.String())
	if err != nil {
		return "", netip.Addr{}, err
	}
	defer conn.Close()
	ip := conn.LocalAddr().(*net.UDPAddr).AddrPort().Addr()
	if !ip.Is4() || ip.IsLoopback() || ip.IsUnspecified() {
		return "", netip.Addr{}, errors.New("physical IPv4 unavailable")
	}
	interfaces, err := c.ReadInterfaces()
	if err != nil {
		return "", netip.Addr{}, err
	}
	for _, iface := range interfaces {
		if !iface.Up || iface.Loopback {
			continue
		}
		for _, s := range iface.Prefixes {
			p, e := netip.ParsePrefix(s)
			if e == nil && p.Addr() == ip {
				return iface.Name, ip, nil
			}
		}
	}
	return "", netip.Addr{}, errors.New("selected route has no current physical interface")
}
