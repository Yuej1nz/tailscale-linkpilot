package product

import (
	"errors"
	"sort"

	"github.com/Yuej1nz/tailscale-linkpilot/internal/model"
)

func applyTargetCommand(c *Config, command, selector string, now int64) (string, int64, error) {
	if selector == "--all" {
		switch command {
		case "pause":
			c.Paused = true
		case "resume":
			c.Paused = false
		case "disconnect":
			c.AllPeers, c.Paused = false, false
			c.Targets, c.Excluded = nil, nil
		default:
			return "", 0, errors.New("optimize 请指定单个设备；全节点模式会按通信需求自动优化")
		}
		return "", 0, nil
	}
	t, err := c.Find(selector)
	if err != nil {
		return "", 0, err
	}
	id := t.ID
	switch command {
	case "pause":
		t.Enabled = false
	case "resume":
		t.Enabled = true
	case "optimize":
		if !t.Enabled || c.Paused {
			return "", 0, errors.New("目标或调度已暂停，请先 resume")
		}
		t.Requested = now
		return id, now, nil
	case "disconnect":
		c.exclude(id)
		kept := c.Targets[:0]
		for _, target := range c.Targets {
			if target.ID != id {
				kept = append(kept, target)
			}
		}
		c.Targets = kept
		allowed := c.Allowed[:0]
		for _, peer := range c.Allowed {
			if peer != id {
				allowed = append(allowed, peer)
			}
		}
		c.Allowed = allowed
	default:
		return "", 0, errors.New("unknown target command")
	}
	return id, 0, nil
}

func (c Config) excludes(id string) bool {
	for _, v := range c.Excluded {
		if v == id {
			return true
		}
	}
	return false
}

func (c *Config) include(id string) {
	kept := c.Excluded[:0]
	for _, v := range c.Excluded {
		if v != id {
			kept = append(kept, v)
		}
	}
	c.Excluded = kept
}

func (c *Config) exclude(id string) {
	if c.AllPeers && !c.excludes(id) {
		c.Excluded = append(c.Excluded, id)
	}
}

// Reconciliation selects only the native client's visible nodes. It never
// grants incoming authorization or creates an immediate optimization request.
// Explicit targets survive disappearance; automatically selected ones do not.
func (c *Config) reconcile(s *model.Report) bool {
	if !c.AllPeers || c.SelfID == "" || c.SelfID != s.Self.ID || s.BackendState != "Running" {
		return false
	}
	visible := map[string]model.Peer{}
	for _, p := range s.Peers {
		if p.ID != "" && p.ID != c.SelfID && !c.excludes(p.ID) {
			visible[p.ID] = p
		}
	}
	changed := false
	kept := make([]Target, 0, len(c.Targets)+len(visible))
	for _, t := range c.Targets {
		p, ok := visible[t.ID]
		if t.Automatic && !ok {
			changed = true
			continue
		}
		if ok {
			if p.Name != "" && t.Name != p.Name {
				t.Name = p.Name
				changed = true
			}
			delete(visible, t.ID)
		}
		kept = append(kept, t)
	}
	ids := make([]string, 0, len(visible))
	for id := range visible {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		name := visible[id].Name
		if name == "" {
			name = id
		}
		kept = append(kept, Target{ID: id, Name: name, Enabled: true, Automatic: true})
		changed = true
	}
	if changed {
		c.Targets = kept
	}
	return changed
}
