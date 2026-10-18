package leash

import (
	"slices"
	"time"

	"github.com/vettid/vettid-agent/internal/pairing"
)

// Info is what leash.connection_info returns (AGENT-PLAN §4.1;
// VAULT-MESSAGING §10.11: the agent's own grants and vault.status),
// built from what the connector holds: it sends nothing to the vault.
// Times are absent when not known.
type Info struct {
	VaultID  string `json:"vault_id"`
	DeviceID string `json:"device_id"`
	Name     string `json:"name"`
	// LastContact is when a message from the vault was last received by
	// this process.
	LastContact *time.Time `json:"last_contact,omitempty"`
	// AccessSession is "active", "none" or "unknown", with its end when
	// known.
	AccessSession      string     `json:"access_session"`
	AccessSessionUntil *time.Time `json:"access_session_until,omitempty"`
	// Suspended: the vault paused this agent after repeated refused
	// requests (§10.11); its grants are listed but none is usable.
	Suspended bool        `json:"suspended"`
	Grants    []GrantInfo `json:"grants"`
	// GrantsAsOf is when the vault last sent the grants;
	// GrantsConfirmed says they were listed in the current access
	// session (otherwise they are as last saved or received).
	GrantsAsOf      *time.Time `json:"grants_as_of,omitempty"`
	GrantsConfirmed bool       `json:"grants_confirmed"`
}

// GrantInfo is one grant as shown (AGENT-PLAN §4.1: scope, approval,
// limits, expiry, connections). Tag names and delegations are not
// shown.
type GrantInfo struct {
	GrantID     string     `json:"grant_id"`
	Scope       string     `json:"scope"`
	Approval    string     `json:"approval"`
	PerHour     uint64     `json:"per_hour,omitempty"`
	PerDay      uint64     `json:"per_day,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	Connections []string   `json:"connections,omitempty"`
	// StatusUntil is the end of the grant's current status statement
	// (absent when it has none: then it cannot be presented until one
	// is fetched).
	StatusUntil *time.Time `json:"status_until,omitempty"`
}

func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}

// infos returns the grants unexpired at now, with their statements'
// ends when stmts is given.
func infos(gs []*Grant, stmts map[string]*statement, now time.Time) []GrantInfo {
	out := []GrantInfo{}
	for _, g := range gs {
		if g.expired(now) {
			continue
		}
		gi := GrantInfo{GrantID: g.ID, Scope: g.Scope, Approval: g.Approval, PerHour: g.PerHour, PerDay: g.PerDay,
			ExpiresAt: timePtr(g.ExpiresAt), Connections: slices.Clone(g.Connections)}
		if st := stmts[g.ID]; st != nil && now.Before(st.notAfter) {
			gi.StatusUntil = timePtr(st.notAfter)
		}
		out = append(out, gi)
	}
	return out
}

// ConnectionInfo returns the data of leash.connection_info (the MCP tool
// is A3.3's). Grants a vault said are not in force are left out, and so
// are expired ones; while suspended, statements are not shown.
func (m *Manager) ConnectionInfo() Info {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	in := Info{VaultID: m.o.VaultID, DeviceID: m.o.DeviceID, Name: m.o.Name, Suspended: m.suspended,
		GrantsAsOf: timePtr(m.asOf), AccessSession: "unknown"}
	var a pairing.Access
	if m.conn != nil {
		a = m.conn.Access()
		in.LastContact = timePtr(m.conn.LastContact())
	}
	switch {
	case activeAt(a, now):
		in.AccessSession = "active"
		in.AccessSessionUntil = timePtr(a.ExpiresAt)
	case a.State == pairing.AccessActive, a.State == pairing.AccessNone:
		in.AccessSession = "none"
	}
	in.GrantsConfirmed = m.listed && in.AccessSession == "active"
	var gs []*Grant
	for _, g := range m.grants {
		if !m.dead[g.ID] {
			gs = append(gs, g)
		}
	}
	stmts := m.statements
	if m.suspended || !in.GrantsConfirmed {
		stmts = nil
	}
	in.Grants = infos(gs, stmts, now)
	return in
}
