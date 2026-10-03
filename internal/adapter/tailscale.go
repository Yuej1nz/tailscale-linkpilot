package adapter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"tailscale.com/client/local"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"

	"github.com/Yuej1nz/tailscale-linkpilot/internal/model"
)

type LocalAPI interface {
	Status(context.Context) (*ipnstate.Status, error)
	Ping(context.Context, netip.Addr, tailcfg.PingType) (*ipnstate.PingResult, error)
}

type Client struct {
	Local           LocalAPI
	CLIPath         string
	Socket          string
	Runner          func(context.Context, string, []string) ([]byte, error)
	ReadInterfaces  func() ([]model.Interface, error)
	AllowSudoRestun bool
}

func New(socket, cliPath string) *Client {
	if cliPath == "" {
		cliPath = findCLI()
	}
	return &Client{
		Local:   &local.Client{Socket: socket, UseSocketOnly: socket != ""},
		CLIPath: cliPath, Socket: socket,
		Runner: func(ctx context.Context, path string, args []string) ([]byte, error) {
			return exec.CommandContext(ctx, path, args...).Output()
		},
		ReadInterfaces: readInterfaces,
	}
}

func findCLI() string {
	if p, err := exec.LookPath("tailscale"); err == nil {
		return p
	}
	var candidates []string
	switch runtime.GOOS {
	case "darwin":
		candidates = []string{"/Applications/Tailscale.app/Contents/MacOS/Tailscale", "/usr/local/bin/tailscale", "/opt/homebrew/bin/tailscale"}
	case "windows":
		for _, env := range []string{"ProgramFiles", "ProgramW6432"} {
			if p := os.Getenv(env); p != "" {
				candidates = append(candidates, filepath.Join(p, "Tailscale", "tailscale.exe"))
			}
		}
	}
	for _, p := range candidates {
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			return p
		}
	}
	return ""
}

func readInterfaces() ([]model.Interface, error) {
	list, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	result := make([]model.Interface, 0, len(list))
	for _, v := range list {
		item := model.Interface{Name: v.Name, Up: v.Flags&net.FlagUp != 0, Loopback: v.Flags&net.FlagLoopback != 0, Prefixes: []string{}}
		addrs, err := v.Addrs()
		if err != nil {
			return nil, fmt.Errorf("interface %s: %w", v.Name, err)
		}
		for _, addr := range addrs {
			if p, err := netip.ParsePrefix(addr.String()); err == nil {
				item.Prefixes = append(item.Prefixes, p.String())
			}
		}
		sort.Strings(item.Prefixes)
		result = append(result, item)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, nil
}

func (c *Client) Snapshot(ctx context.Context) (*model.Report, error) {
	// Reserve part of the caller's budget for a CLI fallback.
	apiCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	s, apiErr := c.Local.Status(apiCtx)
	cancel()
	transport := "localapi"
	if apiErr != nil && c.CLIPath != "" && ctx.Err() == nil {
		args := []string{"status", "--json"}
		if c.Socket != "" {
			args = append([]string{"--socket", c.Socket}, args...)
		}
		data, err := c.Runner(ctx, c.CLIPath, args)
		if err != nil {
			return nil, fmt.Errorf("LocalAPI unavailable (%v); CLI status failed: %w", apiErr, err)
		}
		s = nil // Do not merge a partial API response with the fallback's snapshot.
		if err := json.Unmarshal(data, &s); err != nil {
			return nil, fmt.Errorf("invalid CLI status: %w", err)
		}
		transport = "cli_status"
	} else if apiErr != nil {
		return nil, apiErr
	}
	if s == nil {
		return nil, errors.New("client returned an empty status")
	}
	if s.Version == "" || s.BackendState == "" {
		return nil, errors.New("status contract is missing version or backend state")
	}
	now := time.Now().UTC()
	r := &model.Report{
		SchemaVersion: model.SchemaVersion, Kind: "status", CollectedAt: now,
		BackendState: s.BackendState, Interfaces: []model.Interface{}, Peers: []model.Peer{},
		Client: model.Client{Version: s.Version, Platform: runtime.GOOS, Variant: variant(c.CLIPath), Transport: transport, CLIPath: c.CLIPath,
			Capabilities: map[string]model.Capability{
				"status":                {State: "verified", Reason: "structured_status_read"},
				"discovery_probe":       {State: "not_tested", Reason: "LocalAPI_probe_requires_an_explicit_diagnosis"},
				"wireguard_probe":       {State: "not_tested", Reason: "TSMP_requires_an_explicit_diagnosis"},
				"configuration_changes": {State: "not_implemented", Reason: "diagnostic_release"},
				"socket_control":        {State: "not_implemented", Reason: "preferred_port_selection_not_implemented"},
				"runtime_recovery":      {State: "not_tested", Reason: "native_restun_rebind_require_an_optimizer_session"},
				"source_session_search": {State: "not_tested", Reason: "macos_local_encrypted_carrier_requires_route_metadata_capture_permission_and_business_verification"},
			}},
	}
	if transport != "localapi" {
		r.Warnings = append(r.Warnings, "localapi_unavailable; passive_status_uses_cli")
	}
	interfaces, err := c.ReadInterfaces()
	if err != nil {
		r.Warnings = append(r.Warnings, "interfaces_unavailable:"+err.Error())
	} else {
		r.Interfaces = interfaces
	}
	r.NetworkGeneration = model.NetworkGeneration(r.Interfaces)
	if s.Self != nil {
		r.Self = node(s.Self)
	}
	if s.Self == nil || s.Self.ID == "" {
		r.Warnings = append(r.Warnings, "local_node_identity_unavailable")
	}
	for _, p := range s.Peer {
		if p == nil {
			continue
		}
		path := model.UnknownPath(now, "status_only")
		if !p.LastWrite.IsZero() {
			last := p.LastWrite.UTC()
			path.LastTrafficAt = &last
		}
		switch {
		case p.CurAddr != "" && p.PeerRelay != "":
			path.Notes = append(path.Notes, "conflicting_reported_path_fields")
		case p.CurAddr != "":
			candidate := model.DirectPath(p.CurAddr, r.Interfaces, now)
			path = candidate
			path.ReportedType, path.Type, path.Verification = candidate.Type, "unknown", "status_only"
			if !p.LastWrite.IsZero() {
				last := p.LastWrite.UTC()
				path.LastTrafficAt = &last
			}
		case p.PeerRelay != "":
			path.ReportedType, path.Relay = "peer_relay", p.PeerRelay
		case p.Active && p.Relay != "":
			path.ReportedType, path.Relay = "derp", p.Relay
		}
		if !p.Active || p.LastWrite.IsZero() || now.Sub(p.LastWrite) > 30*time.Second {
			path.Verification = "status_only_stale_or_inactive"
		}
		r.Peers = append(r.Peers, model.Peer{Node: node(p), Online: p.Online, Active: p.Active, RxBytes: p.RxBytes, TxBytes: p.TxBytes, Path: path})
	}
	sort.Slice(r.Peers, func(i, j int) bool { return r.Peers[i].ID < r.Peers[j].ID })
	return r, nil
}

func node(p *ipnstate.PeerStatus) model.Node {
	n := model.Node{ID: string(p.ID), Name: p.HostName, DNSName: strings.TrimSuffix(p.DNSName, "."), OS: p.OS, IPs: []string{}}
	for _, ip := range p.TailscaleIPs {
		n.IPs = append(n.IPs, ip.String())
	}
	return n
}

func variant(cliPath string) string {
	switch runtime.GOOS {
	case "darwin":
		if strings.Contains(cliPath, ".app/") {
			return "macos_app; distribution_not_identified"
		}
		return "macos_daemon_or_unknown"
	case "linux":
		return "linux_daemon"
	case "windows":
		return "windows_service_or_daemon"
	default:
		return "unverified_platform"
	}
}

func (c *Client) Ping(ctx context.Context, target netip.Addr, kind string) (model.PingResult, error) {
	pingType := tailcfg.PingDisco
	if kind == "tsmp" {
		pingType = tailcfg.PingTSMP
	}
	p, err := c.Local.Ping(ctx, target, pingType)
	if err != nil {
		return model.PingResult{}, err
	}
	if p == nil {
		return model.PingResult{}, errors.New("empty probe response")
	}
	return model.PingResult{IP: p.IP, NodeIP: p.NodeIP, Endpoint: p.Endpoint, PeerRelay: p.PeerRelay, DERPRegionID: p.DERPRegionID, DERPRegionCode: p.DERPRegionCode, LatencySeconds: p.LatencySeconds, Err: p.Err}, nil
}
