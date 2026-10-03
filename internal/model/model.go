package model

import (
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"sort"
	"strings"
	"time"
)

const SchemaVersion = 1

type Capability struct {
	State  string `json:"state"`
	Reason string `json:"reason"`
}

type Client struct {
	Version      string                `json:"version"`
	Platform     string                `json:"platform"`
	Variant      string                `json:"variant"`
	Transport    string                `json:"transport"`
	CLIPath      string                `json:"cli_path,omitempty"`
	Capabilities map[string]Capability `json:"capabilities"`
}

type Node struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	DNSName string   `json:"dns_name"`
	OS      string   `json:"os"`
	IPs     []string `json:"tailscale_ips"`
}

type Interface struct {
	Name     string   `json:"name"`
	Up       bool     `json:"up"`
	Loopback bool     `json:"loopback"`
	Prefixes []string `json:"prefixes"`
}

type Path struct {
	Type           string     `json:"type"`
	ReportedType   string     `json:"reported_type,omitempty"`
	UnderlayFamily string     `json:"underlay_family"`
	NetworkScope   string     `json:"network_scope"`
	AddressScope   string     `json:"endpoint_address_scope"`
	Endpoint       string     `json:"endpoint,omitempty"`
	Relay          string     `json:"relay,omitempty"`
	Verification   string     `json:"verification"`
	ObservedAt     time.Time  `json:"observed_at"`
	LastTrafficAt  *time.Time `json:"last_traffic_at,omitempty"`
	Notes          []string   `json:"notes,omitempty"`
}

type Peer struct {
	Node
	Online  bool  `json:"control_online"`
	Active  bool  `json:"active_reported"`
	RxBytes int64 `json:"rx_bytes,omitempty"`
	TxBytes int64 `json:"tx_bytes,omitempty"`
	Path    Path  `json:"path"`
}

type Probe struct {
	Kind       string    `json:"kind"`
	Target     string    `json:"target"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	Success    bool      `json:"success"`
	LatencyMS  float64   `json:"latency_ms,omitempty"`
	Path       *Path     `json:"path,omitempty"`
	Error      *Problem  `json:"error,omitempty"`
}

type Problem struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type Summary struct {
	DiscoverySuccesses      int    `json:"discovery_successes"`
	DiscoveryAttempts       int    `json:"discovery_attempts"`
	LastProbePath           *Path  `json:"last_probe_path,omitempty"`
	WireGuardReachability   string `json:"wireguard_reachability"`
	ApplicationVerification string `json:"application_verification"`
	Statement               string `json:"statement"`
}

type Action struct {
	ID                   string `json:"id"`
	Reason               string `json:"reason"`
	Implemented          bool   `json:"implemented"`
	ActiveProbe          bool   `json:"active_probe"`
	MutatesConfiguration bool   `json:"mutates_configuration"`
}

type Plan struct {
	Mode                 string   `json:"mode"`
	ConfigurationChanges bool     `json:"configuration_changes"`
	Actions              []Action `json:"actions"`
}

type Report struct {
	SchemaVersion        int         `json:"schema_version"`
	Kind                 string      `json:"kind"`
	CollectedAt          time.Time   `json:"collected_at"`
	Client               Client      `json:"client"`
	BackendState         string      `json:"backend_state"`
	Self                 Node        `json:"self"`
	NetworkGeneration    string      `json:"network_generation"`
	Interfaces           []Interface `json:"interfaces"`
	Peers                []Peer      `json:"peers"`
	Target               *Node       `json:"target,omitempty"`
	ActiveProbes         bool        `json:"active_probes"`
	ConfigurationChanges bool        `json:"configuration_changes"`
	Probes               []Probe     `json:"probes,omitempty"`
	Summary              *Summary    `json:"summary,omitempty"`
	Plan                 *Plan       `json:"plan,omitempty"`
	Warnings             []string    `json:"warnings,omitempty"`
	Error                *Problem    `json:"error,omitempty"`
}

// PingResult is the narrow adapter contract. No credentials or user profiles
// from the upstream API enter this model.
type PingResult struct {
	IP             string
	NodeIP         string
	Endpoint       string
	PeerRelay      string
	DERPRegionID   int
	DERPRegionCode string
	LatencySeconds float64
	Err            string
}

func UnknownPath(now time.Time, verification string) Path {
	return Path{Type: "unknown", UnderlayFamily: "unknown", NetworkScope: "unknown", AddressScope: "unknown", Verification: verification, ObservedAt: now}
}

// DirectPath verifies endpoint syntax, not whether it traversed the Internet.
func DirectPath(endpoint string, interfaces []Interface, now time.Time) Path {
	p := UnknownPath(now, "discovery_roundtrip")
	ap, err := netip.ParseAddrPort(endpoint)
	if err != nil || ap.Port() == 0 || ap.Addr().IsUnspecified() || ap.Addr().IsMulticast() {
		p.Notes = []string{"invalid_direct_endpoint"}
		return p
	}
	p.Type, p.Endpoint = "direct", ap.String()
	addr := ap.Addr().Unmap()
	if addr.Is4() {
		p.UnderlayFamily = "ipv4"
	} else {
		p.UnderlayFamily = "ipv6"
	}
	switch {
	case addr.IsLoopback():
		p.AddressScope, p.NetworkScope = "loopback", "local"
	case addr.IsLinkLocalUnicast():
		p.AddressScope, p.NetworkScope = "link_local", "local"
	case addr.IsPrivate():
		p.AddressScope = "private"
	case netip.MustParsePrefix("100.64.0.0/10").Contains(addr):
		p.AddressScope = "shared_address_space"
	case addr.IsGlobalUnicast():
		p.AddressScope = "global"
	default:
		p.AddressScope = "other"
	}
	if p.NetworkScope == "unknown" {
		p.Notes = append(p.Notes, "address_scope_does_not_prove_network_path")
	}
	for _, iface := range interfaces {
		if !iface.Up {
			continue
		}
		for _, value := range iface.Prefixes {
			prefix, err := netip.ParsePrefix(value)
			if err == nil && prefix.Contains(addr) {
				p.Notes = append(p.Notes, "matches_local_interface_prefix:"+iface.Name)
				return p
			}
		}
	}
	return p
}

// DiscoveryPath never infers DERP usage from the peer's home DERP alone.
func DiscoveryPath(r PingResult, interfaces []Interface, now time.Time) Path {
	n := 0
	if r.Endpoint != "" {
		n++
	}
	if r.PeerRelay != "" {
		n++
	}
	if r.DERPRegionID > 0 {
		n++
	}
	if n != 1 || r.DERPRegionID < 0 {
		p := UnknownPath(now, "insufficient_evidence")
		p.Notes = []string{"missing_or_conflicting_path_fields"}
		return p
	}
	if r.Endpoint != "" {
		return DirectPath(r.Endpoint, interfaces, now)
	}
	p := UnknownPath(now, "discovery_roundtrip")
	if r.PeerRelay != "" {
		p.Type, p.Relay = "peer_relay", r.PeerRelay
	} else {
		p.Type, p.Relay = "derp", r.DERPRegionCode
	}
	return p
}

func NetworkGeneration(interfaces []Interface) string {
	var lines []string
	for _, v := range interfaces {
		if !v.Up || v.Loopback {
			continue
		}
		prefixes := append([]string(nil), v.Prefixes...)
		sort.Strings(prefixes)
		lines = append(lines, v.Name+"="+strings.Join(prefixes, ","))
	}
	sort.Strings(lines)
	h := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(h[:8])
}
