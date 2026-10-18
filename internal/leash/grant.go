package leash

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/leashwire"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Limits of VAULT-MESSAGING §10.11.
const (
	// MaxGrants an agent holds.
	MaxGrants = 32
	maxScope  = 64
)

// opRE is a grant's scope (an owner type or items.read), as leashwire
// checks a delegation's scope.op; tagRE a normalised tag (§10.8).
var (
	opRE  = regexp.MustCompile(`^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*)+$`)
	tagRE = regexp.MustCompile(`^[a-z0-9][a-z0-9 _-]{0,31}$`)
)

var errGrant = errors.New("invalid grant")

// Grant is one of this agent's grants as its vault sent it
// (VAULT-MESSAGING §10.11), checked: its members are well formed and,
// when it carries a delegation, the delegation is signed under its own
// `iss` and says what the members say.
type Grant struct {
	ID          string
	AgentID     string
	Version     uint64
	Scope       string
	Approval    string
	Connections []string
	// The share rule of an items.read grant.
	Tags   []string
	Match  string
	Access string
	Uses   uint64
	// PerHour and PerDay are 0 when the grant has no rate limits.
	PerHour   uint64
	PerDay    uint64
	ExpiresAt time.Time // zero: no expiry
	IssuedAt  time.Time
	StatusTTL time.Duration
	// Delegation and Sig are nil for a grant whose delegation the vault
	// does not serve (§10.11: a delegation of the 0.6.0 format); such a
	// grant is never presented.
	Delegation []byte
	Sig        []byte

	del *leashwire.Delegation
}

// expired reports whether the grant has expired at now (§10.11: an
// expired grant matches nothing).
func (g *Grant) expired(now time.Time) bool {
	return !g.ExpiresAt.IsZero() && !now.Before(g.ExpiresAt)
}

// wireGrant is a grant's wire form (§10.11) and, without the status
// members, its saved form. []byte members are standard base64 with
// padding, as encoding/json writes and reads them.
type wireGrant struct {
	GrantID     string            `json:"grant_id"`
	AgentID     string            `json:"agent_id"`
	Version     uint64            `json:"version"`
	Scope       string            `json:"scope"`
	Approval    string            `json:"approval"`
	Connections []string          `json:"connections,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
	Match       string            `json:"match,omitempty"`
	Access      string            `json:"access,omitempty"`
	Uses        uint64            `json:"uses,omitempty"`
	PerHour     uint64            `json:"per_hour,omitempty"`
	PerDay      uint64            `json:"per_day,omitempty"`
	ExpiresAt   string            `json:"expires_at,omitempty"`
	StatusTTL   uint64            `json:"status_ttl"`
	IssuedAt    string            `json:"issued_at"`
	Delegation  []byte            `json:"delegation,omitempty"`
	Sig         []byte            `json:"sig,omitempty"`
	Status      []byte            `json:"status,omitempty"`
	StatusSig   []byte            `json:"status_sig,omitempty"`
	Rotations   []json.RawMessage `json:"rotations,omitempty"`
}

func parseTime(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, errGrant
	}
	return t.UTC(), nil
}

// parseGrant checks a grant's members and its delegation. agentID is
// this agent's device id and must be the grant's agent_id (an empty one
// refuses every grant).
func parseGrant(w *wireGrant, agentID string) (*Grant, error) {
	g := &Grant{ID: w.GrantID, AgentID: w.AgentID, Version: w.Version, Scope: w.Scope, Approval: w.Approval,
		Connections: w.Connections, Tags: w.Tags, Match: w.Match, Access: w.Access, Uses: w.Uses,
		PerHour: w.PerHour, PerDay: w.PerDay, StatusTTL: time.Duration(w.StatusTTL) * time.Second}
	if !envelope.ValidULID(g.ID) || agentID == "" || g.AgentID != agentID || g.Version < 1 {
		return nil, errGrant
	}
	if len(g.Scope) > maxScope || !opRE.MatchString(g.Scope) || g.Approval != "ask" && g.Approval != "auto" {
		return nil, errGrant
	}
	if w.Connections != nil {
		if g.Scope == leashwire.ScopeItems || len(g.Connections) == 0 || len(g.Connections) > leashwire.MaxList {
			return nil, errGrant
		}
		for _, c := range g.Connections {
			if !envelope.ValidULID(c) {
				return nil, errGrant
			}
		}
	}
	if g.Scope == leashwire.ScopeItems {
		if len(g.Tags) == 0 || len(g.Tags) > leashwire.MaxTags || g.Match != "any" && g.Match != "all" ||
			g.Access != "read" || g.Uses > leashwire.MaxUses {
			return nil, errGrant
		}
		for _, t := range g.Tags {
			if !tagRE.MatchString(t) {
				return nil, errGrant
			}
		}
	} else if w.Tags != nil || g.Match != "" || g.Access != "" || g.Uses != 0 {
		return nil, errGrant
	}
	// Rate limits exactly for an auto or items.read grant (§10.11).
	if (g.PerHour == 0) != (g.PerDay == 0) || g.PerHour > leashwire.MaxPerHour || g.PerDay > leashwire.MaxPerDay ||
		(g.PerHour != 0) != (g.Approval == "auto" || g.Scope == leashwire.ScopeItems) {
		return nil, errGrant
	}
	if g.StatusTTL < leashwire.MinStatusTTL || g.StatusTTL > leashwire.MaxStatusTTL {
		return nil, errGrant
	}
	var err error
	if g.IssuedAt, err = parseTime(w.IssuedAt); err != nil {
		return nil, err
	}
	if w.ExpiresAt != "" {
		if g.ExpiresAt, err = parseTime(w.ExpiresAt); err != nil {
			return nil, err
		}
	}
	if w.Delegation == nil && w.Sig == nil {
		return g, nil
	}
	if len(w.Sig) != ed25519.SignatureSize {
		return nil, errGrant
	}
	d, err := leashwire.ParseCanonical(w.Delegation)
	if err != nil {
		return nil, errGrant
	}
	// The signature under the delegation's own iss (whether iss is the
	// member's key is for a relying party to decide, §10.11 step 1); its
	// iat as the time, so that only the signature is checked here.
	if _, err := leashwire.Verify(d.Iss, w.Delegation, w.Sig, d.IssuedAt); err != nil {
		return nil, errGrant
	}
	if !sameAsDelegation(g, d) {
		return nil, errGrant
	}
	g.Delegation, g.Sig, g.del = bytes.Clone(w.Delegation), bytes.Clone(w.Sig), d
	return g, nil
}

// sameAsDelegation reports whether the grant's members say what its
// signed delegation says (§10.11 "Members"), so that what the connector
// shows of a grant is what it would present.
func sameAsDelegation(g *Grant, d *leashwire.Delegation) bool {
	if d.GrantID != g.ID || d.Version != g.Version || d.Scope.Op != g.Scope || d.Approval != g.Approval ||
		d.StatusTTL != g.StatusTTL || !slices.Equal(d.Scope.Connections, g.Connections) ||
		!slices.Equal(d.Scope.Tags, g.Tags) || d.Scope.Match != g.Match || d.Scope.Access != g.Access || d.Scope.Uses != g.Uses {
		return false
	}
	if d.Limits == nil {
		if g.PerHour != 0 {
			return false
		}
	} else if d.Limits.PerHour != g.PerHour || d.Limits.PerDay != g.PerDay {
		return false
	}
	if d.Expires.IsZero() != g.ExpiresAt.IsZero() {
		return false
	}
	return d.Expires.IsZero() || d.Expires.Unix() == g.ExpiresAt.Unix()
}

// wire returns the grant's saved form (no status members).
func (g *Grant) wire() *wireGrant {
	w := &wireGrant{GrantID: g.ID, AgentID: g.AgentID, Version: g.Version, Scope: g.Scope, Approval: g.Approval,
		Connections: g.Connections, Tags: g.Tags, Match: g.Match, Access: g.Access, Uses: g.Uses,
		PerHour: g.PerHour, PerDay: g.PerDay, StatusTTL: uint64(g.StatusTTL / time.Second),
		IssuedAt: g.IssuedAt.Format(time.RFC3339Nano), Delegation: g.Delegation, Sig: g.Sig}
	if !g.ExpiresAt.IsZero() {
		w.ExpiresAt = g.ExpiresAt.Format(time.RFC3339Nano)
	}
	return w
}

// statement is a status statement checked for its grant's delegation.
type statement struct {
	status, sig []byte
	rotations   []*handshake.Rotation
	issuedAt    time.Time
	notAfter    time.Time
}

// ttl is the statement's lifetime.
func (s *statement) ttl() time.Duration { return s.notAfter.Sub(s.issuedAt) }

// refreshAt is when the statement is refreshed: when less than a
// quarter of its lifetime, and at least a minute, remains
// (VAULT-MESSAGING §10.11 "Delivery"; AGENT-PLAN §4.5), as the reference
// client's LeashPresent does.
func (s *statement) refreshAt() time.Time {
	margin := max(s.ttl()/4, time.Minute)
	return s.notAfter.Add(-margin)
}

// checkStatement checks a status statement for g at now with the
// reference verifier, leashwire.VerifyPresentedTrust (VAULT-MESSAGING
// §10.11 "Verification", steps 1 to 5), trusting only g's own iss: the
// statement must be signed by the delegation's status issuer (through
// the rotation chain), name this delegation, be current at now, and live
// no longer than the delegation's status_ttl.
func checkStatement(g *Grant, status, sig []byte, rots []json.RawMessage, now time.Time) (*statement, error) {
	if g.del == nil || len(sig) != ed25519.SignatureSize || len(rots) > leashwire.MaxRotations {
		return nil, errGrant
	}
	st := &statement{status: bytes.Clone(status), sig: bytes.Clone(sig)}
	for _, r := range rots {
		rot, err := handshake.ParseRotation(r)
		if err != nil {
			return nil, errGrant
		}
		st.rotations = append(st.rotations, rot)
	}
	iss := g.del.Iss
	p := &leashwire.Presented{Delegation: g.Delegation, Sig: g.Sig, Status: st.status, StatusSig: st.sig, Rotations: st.rotations}
	if _, err := leashwire.VerifyPresentedTrust(func(k ed25519.PublicKey) bool { return suite.EqualPublic(k, iss) }, p, now); err != nil {
		return nil, errGrant
	}
	ps, err := leashwire.ParseStatus(st.status)
	if err != nil {
		return nil, errGrant
	}
	st.issuedAt, st.notAfter = ps.IssuedAt, ps.NotAfter
	return st, nil
}

// presented returns copies of what is presented for g with st.
func presented(g *Grant, st *statement) *leashwire.Presented {
	return &leashwire.Presented{
		Delegation: bytes.Clone(g.Delegation), Sig: bytes.Clone(g.Sig),
		Status: bytes.Clone(st.status), StatusSig: bytes.Clone(st.sig),
		Rotations: slices.Clone(st.rotations),
	}
}
