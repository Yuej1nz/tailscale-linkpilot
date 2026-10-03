// Package mapping searches fresh UDP sessions without changing Tailscale's
// configuration. A local carrier forwards only the selected peer's existing
// encrypted packets; it never owns or reads a WireGuard/discovery private key.
package mapping

import (
	"context"
	"net/netip"
	"time"
)

type Input struct {
	SelfID     string           `json:"self_id"`
	PeerID     string           `json:"peer_id"`
	Generation string           `json:"network_generation"`
	Interface  string           `json:"interface"`
	Native     netip.AddrPort   `json:"native_endpoint"`
	SelfDisco  [32]byte         `json:"self_disco_public"`
	PeerDisco  [32]byte         `json:"peer_disco_public"`
	Peers      []netip.AddrPort `json:"peer_endpoints"`
	STUN       []netip.AddrPort `json:"stun_servers"`
	CLI        string           `json:"tailscale_cli"`
}

type Observation struct {
	Server    netip.AddrPort `json:"observer"`
	Mapped    netip.AddrPort `json:"mapped_endpoint"`
	At        time.Time      `json:"observed_at"`
	SessionID string         `json:"session_id"`
}

// ObservedPeer is supplied only by the local owner after authenticating the
// coordinator and matching its node and session. It is a candidate, not proof
// that the endpoint can carry authenticated traffic.
type ObservedPeer struct {
	PeerID      string      `json:"peer_id"`
	SessionID   string      `json:"session_id"`
	Observation Observation `json:"observation"`
}

type Counters struct {
	BootstrapOut uint64 `json:"bootstrap_out"`
	BootstrapIn  uint64 `json:"bootstrap_in"`
	NativeOut    uint64 `json:"native_out"`
	PeerIn       uint64 `json:"peer_in"`
	DataOut      uint64 `json:"encrypted_data_bytes_out"`
	DataIn       uint64 `json:"encrypted_data_bytes_in"`
	Dropped      uint64 `json:"dropped"`
}

type State struct {
	SessionID        string         `json:"session_id"`
	SelfID           string         `json:"self_id"`
	PeerID           string         `json:"peer_id"`
	Generation       string         `json:"network_generation"`
	Local            netip.AddrPort `json:"local_endpoint"`
	Physical         netip.AddrPort `json:"physical_peer_endpoint"`
	OutboundPhysical netip.AddrPort `json:"physical_send_endpoint,omitempty"`
	Mappings         []Observation  `json:"mappings"`
	Counters         Counters       `json:"counters"`
	Prevalidation    *ProbeState    `json:"prevalidation,omitempty"`
	Committed        bool           `json:"committed"`
	Activated        bool           `json:"data_forwarding_activated"`
	FrozenPhysical   bool           `json:"physical_endpoint_frozen"`
	ExpiresAt        time.Time      `json:"expires_at"`
	Stopped          bool           `json:"stopped"`
	StopReason       string         `json:"stop_reason,omitempty"`
}

// ProbeConfig is transient authenticated control-plane material. Key must never
// be copied into State or persisted in a run report.
type ProbeConfig struct {
	ID              string `json:"id"`
	Key             []byte `json:"key"`
	LifetimeSeconds int    `json:"lifetime_seconds"`
	Role            string `json:"role"`
}

type ProbeResult struct {
	Target    netip.AddrPort `json:"target"`
	ReplyFrom netip.AddrPort `json:"reply_from"`
	At        time.Time      `json:"at"`
	RTTMS     float64        `json:"rtt_ms"`
}

// ProbeState describes transport evidence only. A roundtrip does not prove
// native Tailscale authentication or authorize encrypted data forwarding.
type ProbeState struct {
	ID               string         `json:"id"`
	ExpiresAt        time.Time      `json:"expires_at"`
	SentRequests     uint64         `json:"sent_requests"`
	RequestsReceived uint64         `json:"requests_received"`
	RepliesSent      uint64         `json:"replies_sent"`
	RepliesReceived  uint64         `json:"replies_received"`
	Dropped          uint64         `json:"dropped"`
	Bursts           int            `json:"bursts"`
	Results          []ProbeResult  `json:"results"`
	Selected         netip.AddrPort `json:"selected_target"`
}

// ProbeSession is optional so existing carriers can retain their previous
// behavior. All methods operate on the same owned UDP socket as Session.
type ProbeSession interface {
	ConfigureProbe(context.Context, ProbeConfig) error
	Probe(context.Context, []netip.AddrPort) error
	SelectProbe(context.Context, netip.AddrPort) error
}

type Injection struct {
	Direction string         `json:"direction"`
	Peer      netip.AddrPort `json:"peer_endpoint"`
	Packet    []byte         `json:"encrypted_packet"`
}

// Session operations are local, user-owned IPC. No remote input can choose an
// executable, interface or file path for a privileged operation.
type Session interface {
	State(context.Context) (State, error)
	Inject(context.Context, Injection) error
	STUN(context.Context) error
	Activate(context.Context, netip.AddrPort) error
	Commit(context.Context) error
	Stop(context.Context) error
}

type Capture interface {
	Start(context.Context, Input, func(Injection)) (func() error, error)
}
