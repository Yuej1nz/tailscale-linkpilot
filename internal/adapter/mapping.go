package adapter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"time"

	"github.com/Yuej1nz/tailscale-linkpilot/internal/mapping"
	"tailscale.com/tailcfg"
)

// MappingInput is rebuilt for every new socket. Only public keys and addresses
// of the selected, authenticated peer leave the native netmap parser.
func (c *Client) MappingInput(ctx context.Context, peerID string, refreshed []string, rotation int) (mapping.Input, error) {
	var result mapping.Input
	s, err := c.Snapshot(ctx)
	if err != nil {
		return result, err
	}
	if s.BackendState != "Running" || s.Self.ID == "" || c.CLIPath == "" {
		return result, errors.New("mapping search requires an active native client and its CLI")
	}
	raw, err := c.discoveryMetadata(ctx)
	if err != nil {
		return result, fmt.Errorf("selected peer discovery metadata unavailable: %w", err)
	}
	var nm struct {
		SelfNode *tailcfg.Node
		Peers    []*tailcfg.Node
	}
	if err := json.Unmarshal(raw, &nm); err != nil || nm.SelfNode == nil || string(nm.SelfNode.StableID) != s.Self.ID || nm.SelfNode.DiscoKey.IsZero() {
		return result, errors.New("native discovery metadata identity or format mismatch")
	}
	var peer *tailcfg.Node
	for _, node := range nm.Peers {
		if node != nil && string(node.StableID) == peerID {
			if peer != nil {
				return result, errors.New("ambiguous discovery metadata")
			}
			peer = node
		}
	}
	if peer == nil || peer.DiscoKey.IsZero() {
		return result, errors.New("selected peer has no authenticated discovery metadata")
	}
	result = mapping.Input{SelfID: s.Self.ID, PeerID: peerID, Generation: s.NetworkGeneration, SelfDisco: nm.SelfNode.DiscoKey.Raw32(), PeerDisco: peer.DiscoKey.Raw32(), CLI: c.CLIPath}
	seen := make(map[netip.AddrPort]bool)
	values := append([]string(nil), refreshed...)
	for _, known := range s.Peers {
		if known.ID == peerID && known.Path.Endpoint != "" {
			// A native observed peer endpoint is an additional candidate even
			// when it is stale; reachability is verified separately this run.
			values = append(values, known.Path.Endpoint)
		}
	}
	for _, ap := range peer.Endpoints {
		values = append(values, ap.String())
	}
	for _, value := range values {
		ap, e := netip.ParseAddrPort(value)
		if e == nil && usableIPv4(ap) {
			seen[ap] = true
		}
	}
	for ap := range seen {
		result.Peers = append(result.Peers, ap)
	}
	sort.Slice(result.Peers, func(i, j int) bool {
		a, b := result.Peers[i], result.Peers[j]
		if a.Addr().IsPrivate() != b.Addr().IsPrivate() {
			return !a.Addr().IsPrivate()
		}
		return a.Compare(b) < 0
	})
	if len(result.Peers) > 12 {
		result.Peers = result.Peers[:12]
	}
	if len(result.Peers) == 0 {
		return result, errors.New("no native IPv4 peer candidates; carrier does not support IPv6 yet")
	}
	// Read the selected physical route rather than assuming en0, a LAN prefix,
	// a public address or any previously successful source port.
	iface, localIP, err := c.physicalRoute(ctx, result.Peers[0])
	if err != nil {
		return result, err
	}
	result.Interface = iface
	endpoints, err := c.NativeEndpoints(ctx)
	if err != nil {
		return result, err
	}
	for _, value := range endpoints {
		ap, _ := netip.ParseAddrPort(value)
		if ap.Addr() == localIP {
			if result.Native.IsValid() && result.Native.Port() != ap.Port() {
				return result, errors.New("native physical UDP port is ambiguous")
			}
			result.Native = ap
		}
	}
	if !result.Native.IsValid() {
		return result, errors.New("native client has no endpoint on the selected physical interface")
	}
	// Do not copy discovery traffic to private container/VPN addresses that
	// cannot be on this selected physical LAN.
	filtered := result.Peers[:0]
	for _, ap := range result.Peers {
		localLAN := false
		for _, iface := range s.Interfaces {
			if iface.Name != result.Interface || !iface.Up {
				continue
			}
			for _, value := range iface.Prefixes {
				prefix, e := netip.ParsePrefix(value)
				if e == nil && prefix.Contains(ap.Addr()) {
					localLAN = true
				}
			}
		}
		if !ap.Addr().IsPrivate() || localLAN {
			filtered = append(filtered, ap)
		}
	}
	result.Peers = filtered
	if len(result.Peers) == 0 {
		return result, errors.New("no peer candidates on a supported physical path")
	}
	var derps *tailcfg.DERPMap
	if lc, ok := c.Local.(interface {
		CurrentDERPMap(context.Context) (*tailcfg.DERPMap, error)
	}); ok {
		derps, _ = lc.CurrentDERPMap(ctx)
	}
	if derps == nil {
		data, e := c.Runner(ctx, c.CLIPath, []string{"debug", "derp-map"})
		if e != nil || json.Unmarshal(data, &derps) != nil || derps == nil {
			return result, errors.New("native STUN server map unavailable")
		}
	}
	var all []netip.AddrPort
	ids := make([]int, 0, len(derps.Regions))
	for id := range derps.Regions {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	// The home region is learned from the native status, not hardcoded.
	if status, e := c.Local.Status(ctx); e == nil && status != nil && status.Self != nil {
		for i, id := range ids {
			if region := derps.Regions[id]; region != nil && region.RegionCode == status.Self.Relay {
				ids = append([]int{id}, append(ids[:i], ids[i+1:]...)...)
				break
			}
		}
	}
	for _, id := range ids {
		region := derps.Regions[id]
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
			if e == nil && usableIPv4(ap) {
				all = append(all, ap)
			}
		}
	}
	if len(all) == 0 {
		return result, errors.New("native map contains no usable IPv4 STUN servers")
	}
	start := (rotation * 5) % len(all)
	for i := 0; i < len(all) && i < 6; i++ {
		result.STUN = append(result.STUN, all[(start+i)%len(all)])
	}
	return result, nil
}

func usableIPv4(ap netip.AddrPort) bool {
	a := ap.Addr()
	return ap.IsValid() && ap.Port() != 0 && a.Is4() && a.IsGlobalUnicast() && !a.IsLoopback() && !netip.MustParsePrefix("100.64.0.0/10").Contains(a)
}

// Use the same read-only action as the official CLI without launching the
// macOS GUI/Swift executable. Never cache metadata across network generations.
func (c *Client) discoveryMetadata(ctx context.Context) ([]byte, error) {
	readCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if api, ok := c.Local.(interface {
		DebugResultJSON(context.Context, string) (any, error)
	}); ok {
		value, err := api.DebugResultJSON(readCtx, "current-netmap")
		if err == nil {
			return json.Marshal(value)
		}
		// A supported API failing must remain visible. Launching the known
		// crashing executable is not a recovery for invalid or unavailable data.
		return nil, fmt.Errorf("native LocalAPI current-netmap read failed: %w", err)
	}
	args := []string{"debug", "netmap"}
	if c.Socket != "" {
		args = append([]string{"--socket", c.Socket}, args...)
	}
	return c.Runner(readCtx, c.CLIPath, args)
}
