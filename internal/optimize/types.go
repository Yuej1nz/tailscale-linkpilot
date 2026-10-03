// Package optimize implements a bounded, configuration-free recovery session
// between the existing macOS GUI client and an authenticated tailnet assistant.
package optimize

import (
	"context"
	"time"

	"github.com/Yuej1nz/tailscale-linkpilot/internal/diagnostic"
	"github.com/Yuej1nz/tailscale-linkpilot/internal/mapping"
	"github.com/Yuej1nz/tailscale-linkpilot/internal/model"
)

const DefaultPort = 45827
const ProtocolVersion = 1

type Backend interface {
	diagnostic.Adapter
	DebugAction(context.Context, string) error
	WhoIsID(context.Context, string) (string, error)
	NativeEndpoints(context.Context) ([]string, error)
}

type Hello struct {
	ExistingSourceSession     string     `json:"existing_source_session,omitempty"`
	Protocol                  int        `json:"protocol"`
	Self                      model.Node `json:"self"`
	Version                   string     `json:"client_version"`
	PairedSessions            bool       `json:"paired_sessions,omitempty"`
	UDPPrevalidation          bool       `json:"udp_prevalidation,omitempty"`
	UDPOrderedPrevalidation   bool       `json:"udp_ordered_prevalidation,omitempty"`
	AutonomousNativeBootstrap bool       `json:"autonomous_native_bootstrap,omitempty"`
}

type RoundRequest struct {
	AttemptID       string `json:"attempt_id"`
	Refresh         bool   `json:"refresh"`
	Count           int    `json:"count"`
	SourceSessionID string `json:"source_session_id,omitempty"`
}

type EndpointSnapshot struct {
	ObservedAt time.Time `json:"observed_at"`
	Generation string    `json:"network_generation"`
	Source     string    `json:"source"`
	Addresses  []string  `json:"addresses"`
	Error      string    `json:"error,omitempty"`
}

type Action struct {
	Side       string    `json:"side"`
	Name       string    `json:"name"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	Error      string    `json:"error,omitempty"`
}

type RoundResponse struct {
	AttemptID     string           `json:"attempt_id"`
	Action        *Action          `json:"action,omitempty"`
	Endpoints     EndpointSnapshot `json:"endpoints"`
	Report        *model.Report    `json:"report,omitempty"`
	Error         string           `json:"error,omitempty"`
	SourceSession *mapping.State   `json:"source_session,omitempty"`
}

type Trial struct {
	Name           string           `json:"name"`
	AttemptID      string           `json:"attempt_id"`
	Actions        []Action         `json:"actions,omitempty"`
	Local          *model.Report    `json:"local,omitempty"`
	Remote         *RoundResponse   `json:"remote,omitempty"`
	LocalEndpoints EndpointSnapshot `json:"local_endpoints"`
	Error          string           `json:"error,omitempty"`
}

type EchoRequest struct {
	AttemptID string `json:"attempt_id"`
	Challenge string `json:"challenge"`
	Data      []byte `json:"data"`
}

type EchoResponse struct {
	AttemptID string `json:"attempt_id"`
	Challenge string `json:"challenge"`
	Digest    string `json:"digest"`
	Data      []byte `json:"data"`
}

type Verification struct {
	Generation           string      `json:"network_generation"`
	At                   time.Time   `json:"at"`
	ApplicationOK        bool        `json:"application_ok"`
	PayloadBytes         int         `json:"payload_bytes"`
	ApplicationMS        float64     `json:"application_ms"`
	LocalPath            *model.Path `json:"local_path,omitempty"`
	RemotePath           *model.Path `json:"remote_path,omitempty"`
	DirectBothWays       bool        `json:"direct_both_ways"`
	Error                string      `json:"error,omitempty"`
	CarrierDataRoundTrip bool        `json:"carrier_data_roundtrip,omitempty"`
	CarrierDataOut       uint64      `json:"carrier_data_bytes_out,omitempty"`
	CarrierDataIn        uint64      `json:"carrier_data_bytes_in,omitempty"`
	RemoteCarrierDataOut uint64      `json:"remote_carrier_data_bytes_out,omitempty"`
	RemoteCarrierDataIn  uint64      `json:"remote_carrier_data_bytes_in,omitempty"`
}

type SourceTrial struct {
	NativeBootstrap            *NativeBootstrapState  `json:"native_bootstrap,omitempty"`
	RemoteNativeBootstrap      *NativeBootstrapState  `json:"remote_native_bootstrap,omitempty"`
	RemoteNativeBootstrapError string                 `json:"remote_native_bootstrap_error,omitempty"`
	PrevalidationOrder         *PrevalidationOrder    `json:"prevalidation_order,omitempty"`
	UDPPrevalidation           string                 `json:"udp_prevalidation,omitempty"`
	UDPPrevalidationError      string                 `json:"udp_prevalidation_error,omitempty"`
	CoordinatedCandidates      []CoordinatedCandidate `json:"coordinated_candidates,omitempty"`
	Index                      int                    `json:"index"`
	Input                      *mapping.Input         `json:"candidates,omitempty"`
	State                      *mapping.State         `json:"session,omitempty"`
	STUNError                  string                 `json:"stun_error,omitempty"`
	Error                      string                 `json:"error,omitempty"`
	Cleanup                    string                 `json:"cleanup,omitempty"`
	RemoteState                *mapping.State         `json:"remote_session,omitempty"`
	PairedError                string                 `json:"paired_session_error,omitempty"`
}

// PrevalidationOrder records the control-plane barrier. Remote and local wall
// times are separate observations, not an assertion that their clocks agree.
type PrevalidationOrder struct {
	PrimeDirection              string    `json:"prime_direction"`
	RemotePrimeSentAt           time.Time `json:"remote_prime_sent_at"`
	LocalPrimeACKAt             time.Time `json:"local_prime_ack_at"`
	LocalFirstRequestAt         time.Time `json:"local_first_request_at"`
	LocalFirstRequestAfterACKMS float64   `json:"local_first_request_after_ack_ms"`
}

type Report struct {
	SchemaVersion       int            `json:"schema_version"`
	Kind                string         `json:"kind"`
	ProgramVersion      string         `json:"program_version"`
	StartedAt           time.Time      `json:"started_at"`
	FinishedAt          time.Time      `json:"finished_at"`
	Self                model.Node     `json:"self"`
	Target              model.Node     `json:"target"`
	Coordinator         string         `json:"coordinator"`
	Outcome             string         `json:"outcome"`
	Optimized           bool           `json:"optimized"`
	DirectVerified      bool           `json:"direct_verified"`
	ApplicationVerified bool           `json:"application_verified"`
	HoldSeconds         float64        `json:"hold_seconds"`
	Trials              []Trial        `json:"trials"`
	Verification        []Verification `json:"verification"`
	PersistentChanges   bool           `json:"persistent_configuration_changes"`
	RuntimeChanges      bool           `json:"runtime_changes"`
	Cleanup             string         `json:"cleanup"`
	Limitations         []string       `json:"limitations"`
	Error               string         `json:"error,omitempty"`
	SourceTrials        []SourceTrial  `json:"source_session_trials,omitempty"`
	Carrier             *mapping.State `json:"retained_local_carrier,omitempty"`
	RemoteCarrier       *mapping.State `json:"retained_remote_carrier,omitempty"`
}

type Options struct {
	Peer           string
	Coordinator    string
	Budget         time.Duration
	Hold           time.Duration
	Rebinds        int
	Count          int
	AllowRebind    bool
	Version        string
	SourceSessions int
	SessionLease   time.Duration
	Capture        mapping.Capture
	SpawnSession   func(context.Context, mapping.Input, []uint16, time.Duration, time.Duration) (mapping.Session, error)
	ActiveSession  func(context.Context) (mapping.Session, mapping.State, error)
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
