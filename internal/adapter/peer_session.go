package adapter

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"runtime"
	"sort"
	"strconv"

	"github.com/Yuej1nz/tailscale-linkpilot/internal/mapping"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
)

// PeerSessionInput never requests privileged debug metadata. The native WhoIs
// record authenticates the selected peer's discovery key and public IPs. The
// peer supplies our public header key, which remains only a routing hint;
// activation still requires a native authenticated roundtrip.
func (c *Client) PeerSessionInput(ctx context.Context, address, peerID string, mapped []netip.AddrPort, selfPublic, peerPublic [32]byte) (mapping.Input, error) {
	var in mapping.Input
	if runtime.GOOS != "linux" {
		return in, errors.New("paired assistant currently supports Linux with a public physical IPv4 address")
	}
	lc, ok := c.Local.(interface {
		WhoIs(context.Context, string) (*apitype.WhoIsResponse, error)
	})
	if !ok {
		return in, errors.New("native peer authentication unavailable")
	}
	w, err := lc.WhoIs(ctx, address)
	if err != nil || w == nil || w.Node == nil || string(w.Node.StableID) != peerID || w.Node.DiscoKey.Raw32() != peerPublic {
		return in, errors.New("paired session discovery identity mismatch")
	}
	if selfPublic == ([32]byte{}) || len(mapped) == 0 || len(mapped) > 6 {
		return in, errors.New("paired session has invalid public metadata")
	}
	ips := map[netip.Addr]bool{}
	for _, ap := range w.Node.Endpoints {
		if usableIPv4(ap) && !ap.Addr().IsPrivate() {
			ips[ap.Addr()] = true
		}
	}
	for _, ap := range mapped {
		if !usableIPv4(ap) || !ips[ap.Addr()] {
			return in, errors.New("mapped IP is not advertised by the authenticated peer")
		}
	}
	// Connect chooses an OS route without transmitting any datagram.
	route, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(mapped[0]))
	if err != nil {
		return in, err
	}
	ip := route.LocalAddr().(*net.UDPAddr).AddrPort().Addr()
	_ = route.Close()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() {
		return in, errors.New("paired assistant requires a public physical IPv4 source; private/NAT server support is not implemented")
	}
	snap, err := c.Snapshot(ctx)
	if err != nil {
		return in, err
	}
	if snap.BackendState != "Running" {
		return in, errors.New("native client is not Running")
	}
	iface := ""
	for _, x := range snap.Interfaces {
		if !x.Up {
			continue
		}
		for _, p := range x.Prefixes {
			prefix, e := netip.ParsePrefix(p)
			if e == nil && prefix.Addr() == ip {
				iface = x.Name
			}
		}
	}
	if iface == "" {
		return in, errors.New("selected server source is not a current interface address")
	}
	native, err := c.NativeEndpoints(ctx)
	if err != nil {
		return in, err
	}
	for _, v := range native {
		ap, e := netip.ParseAddrPort(v)
		if e == nil && ap.Addr() == ip {
			if in.Native.IsValid() && in.Native.Port() != ap.Port() {
				return in, errors.New("native server port is ambiguous")
			}
			in.Native = ap
		}
	}
	if !in.Native.IsValid() {
		return in, errors.New("native server endpoint missing on physical interface")
	}
	in.SelfID = snap.Self.ID
	in.PeerID = peerID
	in.Generation = snap.NetworkGeneration
	in.Interface = iface
	in.SelfDisco = selfPublic
	in.PeerDisco = peerPublic
	in.Peers = append([]netip.AddrPort(nil), mapped...)
	if maps, ok := c.Local.(interface {
		CurrentDERPMap(context.Context) (*tailcfg.DERPMap, error)
	}); ok {
		if dm, e := maps.CurrentDERPMap(ctx); e == nil && dm != nil {
			ids := make([]int, 0, len(dm.Regions))
			for id := range dm.Regions {
				ids = append(ids, id)
			}
			sort.Ints(ids)
			if status, e := c.Local.Status(ctx); e == nil && status != nil && status.Self != nil {
				for i, id := range ids {
					if region := dm.Regions[id]; region != nil && region.RegionCode == status.Self.Relay {
						ids = append([]int{id}, append(ids[:i], ids[i+1:]...)...)
						break
					}
				}
			}
			for _, id := range ids {
				region := dm.Regions[id]
				if region == nil {
					continue
				}
				for _, node := range region.Nodes {
					if node == nil || node.STUNPort < 0 {
						continue
					}
					port := node.STUNPort
					if port == 0 {
						port = 3478
					}
					ap, e := netip.ParseAddrPort(node.IPv4 + ":" + strconv.Itoa(port))
					if e == nil && usableIPv4(ap) && len(in.STUN) < 6 {
						in.STUN = append(in.STUN, ap)
					}
				}
			}
		}
	}
	return in, nil
}
