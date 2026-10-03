package adapter

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"

	"tailscale.com/client/tailscale/apitype"
)

// These optional actions are deliberately separate from the diagnostic API.
// In particular, rebind does not select a new port or change preferences.
func (c *Client) DebugAction(ctx context.Context, action string) error {
	if action != "restun" && action != "rebind" {
		return errors.New("unsupported optimizer action")
	}
	lc, ok := c.Local.(interface {
		DebugAction(context.Context, string) error
	})
	if !ok {
		return errors.New("optimizer control is unavailable")
	}
	err := lc.DebugAction(ctx, action)
	if err == nil || action != "restun" || !c.AllowSudoRestun || ctx.Err() != nil {
		return err
	}
	// The administrator may authorize exactly this command in sudoers. There
	// is no password prompt, shell, peer-supplied argument, or sudo rebind.
	data, sudoErr := c.Runner(ctx, "/usr/bin/sudo", []string{"-n", "/usr/bin/tailscale", "debug", "restun"})
	if sudoErr != nil {
		return fmt.Errorf("native restun failed (%v); fixed privileged refresh failed: %v: %.240s", err, sudoErr, data)
	}
	return nil
}

func (c *Client) WhoIsID(ctx context.Context, remote string) (string, error) {
	// LocalAPI is intentionally narrow for diagnostics. Optimizer construction
	// uses the real SDK client, whose WhoIs authenticates the TCP source node.
	lc, ok := c.Local.(interface {
		WhoIs(context.Context, string) (*apitype.WhoIsResponse, error)
	})
	if !ok {
		return "", errors.New("node authentication is unavailable")
	}
	w, err := lc.WhoIs(ctx, remote)
	if err != nil {
		return "", err
	}
	if w == nil || w.Node == nil || w.Node.StableID == "" {
		return "", errors.New("node authentication returned no stable identity")
	}
	return string(w.Node.StableID), nil
}

func (c *Client) NativeEndpoints(ctx context.Context) ([]string, error) {
	s, err := c.Local.Status(ctx)
	if err != nil {
		return nil, err
	}
	if s == nil || s.Self == nil {
		return nil, errors.New("local identity is unavailable")
	}
	seen := make(map[string]bool)
	for _, value := range s.Self.Addrs {
		ap, err := netip.ParseAddrPort(value)
		if err == nil && ap.Port() != 0 && !ap.Addr().IsUnspecified() && !ap.Addr().IsMulticast() {
			seen[ap.String()] = true
		}
	}
	var endpoints []string
	for value := range seen {
		endpoints = append(endpoints, value)
	}
	sort.Strings(endpoints)
	return endpoints, nil
}
