package optimize

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/Yuej1nz/tailscale-linkpilot/internal/diagnostic"
	"github.com/Yuej1nz/tailscale-linkpilot/internal/mapping"
	"github.com/Yuej1nz/tailscale-linkpilot/internal/model"
)

type rpc struct {
	previousSource            string // authenticated hello snapshot; consumed only by serial source search
	base                      string
	http                      *http.Client
	paired                    bool
	prevalidation             bool
	orderedPrevalidation      bool
	autonomousNativeBootstrap bool
	sourceMu                  sync.RWMutex
	sourceID                  string
}

func (r *rpc) setSource(id string) { r.sourceMu.Lock(); r.sourceID = id; r.sourceMu.Unlock() }
func (r *rpc) getSource() string   { r.sourceMu.RLock(); defer r.sourceMu.RUnlock(); return r.sourceID }

func (r *rpc) call(ctx context.Context, path string, input, output any) error {
	method := http.MethodGet
	var body io.Reader
	if input != nil {
		method = http.MethodPost
		data, err := json.Marshal(input)
		if err != nil {
			return err
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, r.base+path, body)
	if err != nil {
		return err
	}
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := r.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, (4<<20)+1))
	if err != nil {
		return err
	}
	if len(data) > 4<<20 {
		return errors.New("assistant response exceeds limit")
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("assistant returned HTTP %d: %.240s", resp.StatusCode, data)
	}
	return json.Unmarshal(data, output)
}

func randomHex(n int) string {
	data := make([]byte, n)
	if _, err := rand.Read(data); err != nil {
		panic(err)
	}
	return hex.EncodeToString(data)
}

func lastPath(r *model.Report) *model.Path {
	if r == nil || r.Summary == nil {
		return nil
	}
	return r.Summary.LastProbePath
}

func directBoth(t Trial) bool {
	if t.Error != "" || t.Remote == nil || t.Remote.Error != "" {
		return false
	}
	a, b := lastPath(t.Local), lastPath(t.Remote.Report)
	return a != nil && b != nil && a.Type == "direct" && b.Type == "direct"
}

func coordinated(ctx context.Context, a Backend, client *rpc, self, peer model.Node, name string, count int, refresh bool) Trial {
	return coordinatedWithLocal(ctx, a, client, self, peer, name, count, refresh, nil)
}

func coordinatedWithLocal(ctx context.Context, a Backend, client *rpc, self, peer model.Node, name string, count int, refresh bool, onLocal func(*model.Report) error) Trial {
	t := Trial{Name: name, AttemptID: randomHex(16)}
	if refresh {
		x := action(ctx, a, "local", "restun")
		t.Actions = append(t.Actions, x)
	}
	ch := make(chan RoundResponse, 1)
	go func() {
		var remote RoundResponse
		err := client.call(ctx, "/v1/probe", RoundRequest{AttemptID: t.AttemptID, Refresh: refresh, Count: count, SourceSessionID: client.getSource()}, &remote)
		if err != nil {
			remote.Error = err.Error()
		}
		ch <- remote
	}()
	if err := sleep(ctx, 500*time.Millisecond); err != nil {
		t.Error = err.Error()
	}
	var err error
	t.Local, err = diagnostic.Diagnose(ctx, a, diagnostic.Options{Peer: peer.ID, Count: count, Timeout: 2 * time.Second, Budget: 20 * time.Second, WireGuard: true})
	if err != nil {
		t.Error = err.Error()
	}
	if onLocal != nil && t.Local != nil {
		if err := onLocal(t.Local); err != nil {
			t.Error = err.Error()
		}
	}
	select {
	case remote := <-ch:
		t.Remote = &remote
		if remote.Error == "" && (remote.AttemptID != t.AttemptID || remote.Report == nil || remote.Report.Self.ID != peer.ID || remote.Report.Target == nil || remote.Report.Target.ID != self.ID) {
			t.Remote.Error = "assistant response identity or attempt mismatch"
		}
	case <-ctx.Done():
		t.Error = ctx.Err().Error()
	}
	gen := ""
	if t.Local != nil {
		gen = t.Local.NetworkGeneration
		if t.Local.Self.ID != self.ID {
			t.Error = "local identity changed"
		}
	}
	t.LocalEndpoints = endpoints(ctx, a, gen)
	return t
}

func validateCoordinator(peer model.Node, address string) (string, error) {
	if address == "" {
		ip, err := diagnostic.TargetIP(&model.Peer{Node: peer})
		if err != nil {
			return "", err
		}
		address = net.JoinHostPort(ip.String(), fmt.Sprint(DefaultPort))
	}
	ap, err := netip.ParseAddrPort(address)
	if err != nil || ap.Port() == 0 || !hasIP(peer.IPs, ap.Addr().String()) {
		return "", errors.New("coordinator must be an assigned Tailscale IP:port of the selected peer")
	}
	return ap.String(), nil
}

func Run(ctx context.Context, a Backend, opts Options) (result *Report) {
	r := &Report{SchemaVersion: 1, Kind: "optimize", ProgramVersion: opts.Version, StartedAt: time.Now().UTC(), Outcome: "failed", Cleanup: "no_persistent_configuration_changes",
		Limitations: []string{"source-session search uses a local encrypted UDP carrier, not a native GUI preferred-port setting; successful sessions require the retained local process", "STUN observations are destination-specific; discovery plus encrypted application data decides success", "direct_verified on a native path is correlated sampling; carrier paths additionally require encrypted data in both directions during each business round", "rebind affects this Mac's native UDP sockets; no remote rebind or service restart", "a bounded search cannot guarantee direct connectivity on arbitrary networks"}}
	defer func() { r.FinishedAt = time.Now().UTC() }()
	if opts.Budget < 20*time.Second || opts.Budget > 180*time.Second || opts.Hold < 0 || opts.Hold > 60*time.Second || opts.Hold+15*time.Second > opts.Budget || opts.Rebinds < 0 || opts.Rebinds > 2 || opts.Count < 1 || opts.Count > 8 || opts.SourceSessions < 0 || opts.SourceSessions > 3 || opts.SourceSessions > 0 && (opts.SessionLease < time.Minute || opts.SessionLease > 24*time.Hour) {
		r.Error = "invalid optimizer budget, hold, count, or rebind limit"
		return r
	}
	ctx, cancel := context.WithTimeout(ctx, opts.Budget)
	defer cancel()
	s, err := a.Snapshot(ctx)
	if err != nil {
		r.Error = err.Error()
		return r
	}
	if s.BackendState != "Running" || s.Self.ID == "" {
		r.Error = "local Tailscale identity is not Running"
		return r
	}
	p, err := diagnostic.ResolvePeer(s, opts.Peer)
	if err != nil {
		r.Error = err.Error()
		return r
	}
	r.Self, r.Target = s.Self, p.Node
	address, err := validateCoordinator(p.Node, opts.Coordinator)
	if err != nil {
		r.Error = err.Error()
		return r
	}
	r.Coordinator = address
	id, err := a.WhoIsID(ctx, address)
	if err != nil || id != p.ID {
		r.Error = "coordinator node authentication failed"
		return r
	}
	client := &rpc{base: "http://" + address, http: &http.Client{Transport: &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext, DisableKeepAlives: true}, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("assistant redirects are forbidden") }}}
	defer client.http.CloseIdleConnections()
	var hello Hello
	if err := client.call(ctx, "/v1/hello", nil, &hello); err != nil {
		r.Error = err.Error()
		return r
	}
	if hello.Protocol != ProtocolVersion || hello.Self.ID != p.ID {
		r.Error = "assistant protocol or node identity mismatch"
		return r
	}
	client.previousSource = hello.ExistingSourceSession
	client.paired = hello.PairedSessions
	client.prevalidation = hello.UDPPrevalidation
	client.orderedPrevalidation = hello.UDPOrderedPrevalidation
	client.autonomousNativeBootstrap = hello.AutonomousNativeBootstrap
	baseline := coordinated(ctx, a, client, r.Self, p.Node, "baseline", 2, false)
	r.Trials = append(r.Trials, baseline)
	if baseline.Error != "" || baseline.Remote == nil || baseline.Remote.Error != "" {
		r.Error = "baseline coordination failed; no recovery action executed"
		r.Outcome = "coordination_failed"
		return r
	}
	wasDirect := directBoth(baseline)
	var carrier mapping.Session
	carrier = activeForPeer(ctx, opts, r.Self, p.Node, baseline.Local.NetworkGeneration)
	retained := false
	defer func() {
		if carrier != nil && !retained {
			r.Cleanup = stopSession(carrier)
		}
	}()
	if !wasDirect {
		refresh := coordinated(ctx, a, client, r.Self, p.Node, "refresh_and_coordinated_probe", opts.Count, true)
		r.RuntimeChanges = true
		r.Trials = append(r.Trials, refresh)
		for i := 0; !directBoth(r.Trials[len(r.Trials)-1]) && opts.AllowRebind && i < opts.Rebinds && ctx.Err() == nil; i++ {
			x := action(ctx, a, "local", "rebind")
			if x.Error != "" {
				r.Trials = append(r.Trials, Trial{Name: "rebind_unavailable", Actions: []Action{x}, Error: x.Error})
				break
			}
			if err := sleep(ctx, time.Second); err != nil {
				break
			}
			t := coordinated(ctx, a, client, r.Self, p.Node, fmt.Sprintf("rebind_and_refresh_%d", i+1), opts.Count, true)
			t.Actions = append([]Action{x}, t.Actions...)
			r.Trials = append(r.Trials, t)
		}
		if !directBoth(r.Trials[len(r.Trials)-1]) && opts.SourceSessions > 0 && ctx.Err() == nil {
			if carrier != nil {
				_ = stopSession(carrier)
				carrier = nil
			}
			carrier = searchSource(ctx, a, client, r, opts)
		}
	}
	allDirect, allApp := true, true
	verifyStart := time.Now()
	for i := 0; i < 3; i++ {
		if i > 0 {
			if err := sleep(ctx, opts.Hold/2); err != nil {
				r.Error = err.Error()
				break
			}
		}
		v := verifyWithCarrier(ctx, a, client, r.Self, p.Node, carrier)
		r.Verification = append(r.Verification, v)
		allDirect = allDirect && v.DirectBothWays && (carrier == nil || v.CarrierDataRoundTrip)
		allApp = allApp && v.ApplicationOK
		if ctx.Err() != nil {
			r.Error = ctx.Err().Error()
			break
		}
	}
	r.HoldSeconds = time.Since(verifyStart).Seconds()
	r.ApplicationVerified = len(r.Verification) == 3 && allApp
	r.DirectVerified = len(r.Verification) == 3 && allDirect && allApp
	// Network changes during the run invalidate the common observation window.
	for _, trial := range r.Trials {
		if trial.Local != nil && trial.Local.NetworkGeneration != baseline.Local.NetworkGeneration {
			r.DirectVerified = false
			r.Error = "network changed during optimization; run again on the current network"
		}
	}
	r.Optimized = !wasDirect && r.DirectVerified
	for _, v := range r.Verification {
		if v.Generation != baseline.Local.NetworkGeneration {
			r.DirectVerified = false
			r.Optimized = false
			r.Error = "network changed during verification; run again on the current network"
		}
	}
	if carrier != nil && r.DirectVerified {
		if err := carrier.Commit(ctx); err != nil {
			r.DirectVerified, r.Optimized = false, false
			r.Error = "carrier retention failed: " + err.Error()
		} else if state, err := carrier.State(ctx); err != nil {
			r.DirectVerified, r.Optimized = false, false
			r.Error = "carrier retention could not be confirmed: " + err.Error()
		} else {
			r.Carrier = &state
			if pair, ok := carrier.(*pairedSession); ok {
				remote := pair.remote.State
				r.RemoteCarrier = &remote
			}
			r.Cleanup = "local_carrier_retained_until_lease_or_network_change"
			retained = true
		}
	}
	switch {
	case r.DirectVerified && r.Carrier != nil && wasDirect:
		r.Outcome = "direct_via_local_session_preserved"
	case r.DirectVerified && r.Carrier != nil:
		r.Outcome = "direct_via_new_local_session"
	case r.DirectVerified && wasDirect:
		r.Outcome = "already_direct_preserved"
	case r.DirectVerified:
		r.Outcome = "direct_after_recovery"
	case r.ApplicationVerified:
		r.Outcome = "relay_or_unproven_path_application_available"
	default:
		r.Outcome = "connectivity_or_verification_failed"
	}
	return r
}

func verify(ctx context.Context, a Backend, client *rpc, self, peer model.Node) Verification {
	return verifyWithCarrier(ctx, a, client, self, peer, nil)
}

func verifyWithCarrier(ctx context.Context, a Backend, client *rpc, self, peer model.Node, carrier mapping.Session) Verification {
	v := Verification{At: time.Now().UTC(), PayloadBytes: 64 << 10}
	before, beforeErr := carrierState(ctx, carrier)
	var beforeRemote mapping.State
	var beforeRemoteErr error
	if pair, ok := carrier.(*pairedSession); ok {
		beforeRemote, beforeRemoteErr = pair.remoteState(ctx)
	}
	data := make([]byte, v.PayloadBytes)
	if _, err := rand.Read(data); err != nil {
		v.Error = err.Error()
		return v
	}
	request := EchoRequest{AttemptID: randomHex(16), Challenge: randomHex(32), Data: data}
	var response EchoResponse
	start := time.Now()
	appCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	err := client.call(appCtx, "/v1/echo", request, &response)
	cancel()
	v.ApplicationMS = float64(time.Since(start).Microseconds()) / 1000
	h := sha256.Sum256(data)
	v.ApplicationOK = err == nil && response.AttemptID == request.AttemptID && response.Challenge == request.Challenge && response.Digest == hex.EncodeToString(h[:]) && bytes.Equal(response.Data, data)
	if err != nil {
		v.Error = err.Error()
	} else if !v.ApplicationOK {
		v.Error = "application payload or challenge mismatch"
	}
	if carrier != nil {
		after, afterErr := carrierState(ctx, carrier)
		if beforeErr == nil && afterErr == nil && before.SessionID == after.SessionID && before.Generation == after.Generation && after.Counters.DataOut >= before.Counters.DataOut && after.Counters.DataIn >= before.Counters.DataIn {
			v.CarrierDataOut = after.Counters.DataOut - before.Counters.DataOut
			v.CarrierDataIn = after.Counters.DataIn - before.Counters.DataIn
			v.CarrierDataRoundTrip = v.ApplicationOK && v.CarrierDataOut >= uint64(v.PayloadBytes) && v.CarrierDataIn >= uint64(v.PayloadBytes)
		}
	}
	t := coordinated(ctx, a, client, self, peer, "verification", 1, false)
	if t.Local != nil {
		v.Generation = t.Local.NetworkGeneration
	}
	v.LocalPath = lastPath(t.Local)
	if t.Remote != nil {
		v.RemotePath = lastPath(t.Remote.Report)
	}
	v.DirectBothWays = directBoth(t)
	if carrier != nil {
		state, err := carrierState(ctx, carrier)
		v.CarrierDataRoundTrip = v.CarrierDataRoundTrip && err == nil && selectedCarrier(t, state)
		if _, ok := carrier.(*pairedSession); ok {
			var afterRemote *mapping.State
			if t.Remote != nil {
				afterRemote = t.Remote.SourceSession
			}
			remotePath := lastPath(func() *model.Report {
				if t.Remote != nil {
					return t.Remote.Report
				}
				return nil
			}())
			valid := beforeRemoteErr == nil && afterRemote != nil && afterRemote.SessionID == beforeRemote.SessionID && afterRemote.Activated && afterRemote.Counters.DataOut >= beforeRemote.Counters.DataOut && afterRemote.Counters.DataIn >= beforeRemote.Counters.DataIn && remotePath != nil && remotePath.Endpoint == afterRemote.Local.String()
			if valid {
				v.RemoteCarrierDataOut = afterRemote.Counters.DataOut - beforeRemote.Counters.DataOut
				v.RemoteCarrierDataIn = afterRemote.Counters.DataIn - beforeRemote.Counters.DataIn
			}
			v.CarrierDataRoundTrip = v.CarrierDataRoundTrip && valid && v.RemoteCarrierDataOut >= uint64(v.PayloadBytes) && v.RemoteCarrierDataIn >= uint64(v.PayloadBytes)
		}
	}
	if t.Error != "" {
		v.Error += "; " + t.Error
	}
	if t.Remote != nil && t.Remote.Error != "" {
		v.Error += "; " + t.Remote.Error
	}
	return v
}
