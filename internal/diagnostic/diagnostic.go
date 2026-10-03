package diagnostic

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/Yuej1nz/tailscale-linkpilot/internal/model"
)

type Adapter interface {
	Snapshot(context.Context) (*model.Report, error)
	Ping(context.Context, netip.Addr, string) (model.PingResult, error)
}

type Options struct {
	Peer      string
	Count     int
	Timeout   time.Duration
	Budget    time.Duration
	WireGuard bool
}

func ResolvePeer(r *model.Report, selector string) (*model.Peer, error) {
	value := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(selector)), ".")
	if value == "" {
		return nil, errors.New("--peer is required")
	}
	var matches []*model.Peer
	for i := range r.Peers {
		p := &r.Peers[i]
		dns := strings.TrimSuffix(strings.ToLower(p.DNSName), ".")
		match := value == strings.ToLower(p.ID) || value == strings.ToLower(p.Name) || (dns != "" && (value == dns || value == strings.Split(dns, ".")[0]))
		for _, ip := range p.IPs {
			match = match || value == strings.ToLower(ip)
		}
		if match {
			matches = append(matches, p)
		}
	}
	if len(matches) == 0 {
		return nil, fmt.Errorf("peer %q is not in the local peer list; use a node ID, name, or assigned Tailscale IP", selector)
	}
	if len(matches) > 1 {
		return nil, fmt.Errorf("peer %q is ambiguous; use the unique node ID or Tailscale IP", selector)
	}
	if matches[0].ID == "" {
		return nil, errors.New("peer has no stable node identity")
	}
	return matches[0], nil
}

func TargetIP(p *model.Peer) (netip.Addr, error) {
	for _, s := range p.IPs {
		if ip, err := netip.ParseAddr(s); err == nil && ip.Is4() {
			return ip, nil
		}
	}
	for _, s := range p.IPs {
		if ip, err := netip.ParseAddr(s); err == nil {
			return ip, nil
		}
	}
	return netip.Addr{}, errors.New("peer has no valid assigned Tailscale IP")
}

func Status(ctx context.Context, a Adapter, selector string) (*model.Report, error) {
	r, err := a.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	r.Kind = "status"
	if selector != "" {
		peer, err := ResolvePeer(r, selector)
		if err != nil {
			return nil, err
		}
		n := peer.Node
		r.Target = &n
		r.Peers = []model.Peer{*peer}
	}
	return r, nil
}

func Diagnose(ctx context.Context, a Adapter, opts Options) (*model.Report, error) {
	if opts.Count < 1 || opts.Count > 10 {
		return nil, errors.New("--count must be between 1 and 10")
	}
	if opts.Timeout < 200*time.Millisecond || opts.Timeout > 10*time.Second {
		return nil, errors.New("--timeout must be between 200ms and 10s")
	}
	if opts.Budget < time.Second || opts.Budget > 60*time.Second {
		return nil, errors.New("--budget must be between 1s and 60s")
	}
	ctx, cancel := context.WithTimeout(ctx, opts.Budget)
	defer cancel()
	r, err := a.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	if r.BackendState != "Running" {
		return nil, fmt.Errorf("Tailscale backend is %s, not Running", r.BackendState)
	}
	peer, err := ResolvePeer(r, opts.Peer)
	if err != nil {
		return nil, err
	}
	ip, err := TargetIP(peer)
	if err != nil {
		return nil, err
	}
	n := peer.Node
	r.Kind, r.Target, r.Peers = "diagnose", &n, []model.Peer{*peer}
	r.Summary = &model.Summary{WireGuardReachability: "not_tested", ApplicationVerification: "not_tested"}
	for i := 0; i < opts.Count && ctx.Err() == nil; i++ {
		r.ActiveProbes = true
		p := probe(ctx, a, ip, *peer, "disco", opts.Timeout, r.Interfaces)
		r.Probes = append(r.Probes, p)
		r.Summary.DiscoveryAttempts++
		if p.Success {
			r.Summary.DiscoverySuccesses++
		}
		// A later timeout must not leave the previous success as current proof.
		if p.Path != nil {
			r.Summary.LastProbePath = p.Path
		} else {
			unknown := model.UnknownPath(p.FinishedAt, "last_probe_failed")
			r.Summary.LastProbePath = &unknown
		}
		if i+1 < opts.Count {
			select {
			case <-ctx.Done():
			case <-time.After(250 * time.Millisecond):
			}
		}
	}
	if opts.WireGuard && ctx.Err() == nil {
		r.ActiveProbes = true
		p := probe(ctx, a, ip, *peer, "tsmp", opts.Timeout, r.Interfaces)
		r.Probes = append(r.Probes, p)
		if p.Success {
			r.Summary.WireGuardReachability = "verified_by_tsmp"
		} else {
			r.Summary.WireGuardReachability = "not_verified"
		}
	}
	if ctx.Err() != nil {
		r.Warnings = append(r.Warnings, "diagnosis_budget_exhausted_or_cancelled")
	}
	if r.Summary.DiscoverySuccesses > 0 {
		r.Client.Capabilities["discovery_probe"] = model.Capability{State: "verified", Reason: "LocalAPI_probe_returned_for_selected_peer"}
	}
	if r.Summary.WireGuardReachability == "verified_by_tsmp" {
		r.Client.Capabilities["wireguard_probe"] = model.Capability{State: "verified", Reason: "TSMP_returned_for_selected_peer"}
	}
	r.Summary.Statement = "Discovery proves the probe's path at its timestamp; TSMP tests WireGuard reachability. Application traffic and Internet traversal are not independently verified."
	return r, nil
}

func probe(ctx context.Context, a Adapter, ip netip.Addr, peer model.Peer, kind string, timeout time.Duration, interfaces []model.Interface) model.Probe {
	p := model.Probe{Kind: kind, Target: ip.String(), StartedAt: time.Now().UTC()}
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	raw, err := a.Ping(probeCtx, ip, kind)
	contextErr := probeCtx.Err()
	cancel()
	p.FinishedAt = time.Now().UTC()
	if err != nil || raw.Err != "" {
		code, message := "probe_failed", raw.Err
		if err != nil {
			message = err.Error()
		}
		if errors.Is(err, context.DeadlineExceeded) || contextErr == context.DeadlineExceeded {
			code = "probe_timeout"
		}
		if errors.Is(err, context.Canceled) || contextErr == context.Canceled {
			code = "cancelled"
		}
		p.Error = &model.Problem{Code: code, Message: message}
		return p
	}
	if raw.IP != "" && raw.IP != ip.String() {
		p.Error = &model.Problem{Code: "identity_mismatch", Message: "probe response targets a different IP"}
		return p
	}
	belongs := false
	for _, s := range peer.IPs {
		belongs = belongs || raw.NodeIP == s
	}
	if !belongs {
		p.Error = &model.Problem{Code: "identity_mismatch", Message: "probe response has no matching peer node IP"}
		return p
	}
	p.LatencyMS = raw.LatencySeconds * 1000
	if kind == "disco" {
		path := model.DiscoveryPath(raw, interfaces, p.FinishedAt)
		p.Path = &path
		if path.Type == "unknown" {
			p.Error = &model.Problem{Code: "insufficient_path_evidence", Message: "round trip returned without an unambiguous valid path"}
			return p
		}
	}
	p.Success = true
	return p
}

// Plan only describes actions. It never calls the adapter or executes changes.
func Plan(r *model.Report, selector string) error {
	if r.SchemaVersion != model.SchemaVersion {
		return errors.New("unsupported report schema")
	}
	peer, err := ResolvePeer(r, selector)
	if err != nil {
		return err
	}
	if r.Target != nil && len(r.Probes) > 0 && r.Target.ID != peer.ID {
		return errors.New("saved probes belong to a different peer")
	}
	n := peer.Node
	r.Target = &n
	r.Peers = []model.Peer{*peer}
	r.Kind = "plan"
	r.ActiveProbes = false
	r.ConfigurationChanges = false
	p := &model.Plan{Mode: "preview_only", Actions: []model.Action{}}
	r.Plan = p
	if r.BackendState != "Running" {
		p.Actions = append(p.Actions, model.Action{ID: "check_client_state", Reason: "Tailscale is not Running"})
		return nil
	}
	path := peer.Path
	if r.Summary != nil && r.Summary.LastProbePath != nil {
		path = *r.Summary.LastProbePath
	}
	if path.Type == "direct" && time.Since(path.ObservedAt) >= 0 && time.Since(path.ObservedAt) <= 30*time.Second {
		p.Actions = append(p.Actions, model.Action{ID: "preserve_current_path", Reason: "recent discovery confirmed a direct path; avoid configuration churn", Implemented: true})
	} else {
		p.Actions = append(p.Actions, model.Action{ID: "diagnose_peer", Reason: "fresh active path evidence is required", Implemented: true, ActiveProbe: true})
		p.Actions = append(p.Actions, model.Action{ID: "compare_candidates_and_routes", Reason: "identify missing candidates, timing, and route differences before selecting a recovery strategy"})
	}
	p.Actions = append(p.Actions, model.Action{ID: "verify_application_path", Reason: "discovery and TSMP do not establish application success or sustained direct transport"})
	return nil
}
