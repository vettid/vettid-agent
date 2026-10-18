package leash

// The vault's LEASH vectors (VAULT-MESSAGING §16, leash.json; AGENT-PLAN
// §5, A3.1): each case, sent to the connector as a grant in an agent's
// leash.grant.list answer, is presented byte for byte as the vector's
// delegation, sig, status and status_sig, and the altered forms are
// never presented. A vector that stops matching is a stop-and-report
// item: never edit testdata/vectors/ or skip a case to make this pass.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/leashwire"

	"github.com/vettid/vettid-agent/internal/pairing"
	"github.com/vettid/vettid-agent/internal/vaultconn"
)

// The sha256sum of testdata/vectors/leash.json in
// testdata/vectors/SOURCE.md.
const leashVectorSHA256 = "b1200366e5310cd5ac7bbded3bb035b6efa1408579a7c19bd4a73ca9fcba2beb"

type vectorCase struct {
	Case           string `json:"case"`
	DelegationB64  string `json:"delegation_b64"`
	SigB64         string `json:"sig_b64"`
	StatusIssuedAt int64  `json:"status_issued_at"`
	StatusB64      string `json:"status_b64"`
	StatusSigB64   string `json:"status_sig_b64"`
	AcceptFrom     int64  `json:"accept_from"`
	AcceptTo       int64  `json:"accept_to"`
}

type vectorFile struct {
	CredentialKeyPKB64 string     `json:"credential_key_pk_b64"`
	AgentIKSeedHex     string     `json:"agent_ik_seed_hex"`
	A                  vectorCase `json:"a"`
	B                  vectorCase `json:"b"`
}

func b64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// wireFromVector is the grant the vault would send for the case: its
// members as the delegation says, and the case's four parts.
func wireFromVector(t *testing.T, d *leashwire.Delegation, del, sig, st, stSig []byte) json.RawMessage {
	t.Helper()
	w := map[string]any{"grant_id": d.GrantID, "agent_id": testAgent, "version": d.Version, "scope": d.Scope.Op,
		"approval": d.Approval, "status_ttl": int(d.StatusTTL / time.Second),
		"issued_at": d.IssuedAt.Format(time.RFC3339), "delegation": del, "sig": sig, "status": st, "status_sig": stSig}
	if d.Scope.Connections != nil {
		w["connections"] = d.Scope.Connections
	}
	if d.Scope.Op == leashwire.ScopeItems {
		w["tags"], w["match"], w["access"] = d.Scope.Tags, d.Scope.Match, d.Scope.Access
		if d.Scope.Uses > 0 {
			w["uses"] = d.Scope.Uses
		}
	}
	if d.Limits != nil {
		w["per_hour"], w["per_day"] = d.Limits.PerHour, d.Limits.PerDay
	}
	if !d.Expires.IsZero() {
		w["expires_at"] = d.Expires.Format(time.RFC3339)
	}
	b, err := json.Marshal(w)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestLeashVectorsPresented(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors", "leash.json"))
	if err != nil {
		t.Fatal(err)
	}
	if h := sha256.Sum256(raw); hex.EncodeToString(h[:]) != leashVectorSHA256 {
		t.Fatalf("leash.json sha256 %x differs from SOURCE.md: stop and report", h)
	}
	var v vectorFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	seed, err := hex.DecodeString(v.AgentIKSeedHex)
	if err != nil {
		t.Fatal(err)
	}
	agentIK := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	member := ed25519.PublicKey(b64(t, v.CredentialKeyPKB64))

	for name, c := range map[string]vectorCase{"a": v.A, "b": v.B} {
		del, sig, st, stSig := b64(t, c.DelegationB64), b64(t, c.SigB64), b64(t, c.StatusB64), b64(t, c.StatusSigB64)
		d, err := leashwire.Parse(del)
		if err != nil {
			t.Fatal(err)
		}
		newAt := func(now time.Time, body json.RawMessage) (*Manager, *fakeConn) {
			m := New(Options{Now: func() time.Time { return now }})
			f := &fakeConn{m: m, ik: agentIK, access: pairing.Access{State: pairing.AccessActive},
				list:      func() *vaultconn.Response { return ok(body) },
				statusGet: func(string) *vaultconn.Response { return fail("internal") }}
			if err := m.Bind(f); err != nil {
				t.Fatal(err)
			}
			return m, f
		}

		t.Run(name+"/presented", func(t *testing.T) {
			// From the statement's issue until its refresh time it is
			// presented as received, with no request but the list.
			ps, err := leashwire.ParseStatus(st)
			if err != nil {
				t.Fatal(err)
			}
			margin := max(ps.NotAfter.Sub(ps.IssuedAt)/4, time.Minute)
			for _, now := range []time.Time{time.Unix(c.StatusIssuedAt, 0), ps.NotAfter.Add(-margin - time.Second)} {
				m, f := newAt(now, set(t, false, wireFromVector(t, d, del, sig, st, stSig)))
				p, err := m.Present(ctx, d.GrantID)
				if err != nil {
					t.Fatalf("%s (%s) at %v: %v", name, c.Case, now, err)
				}
				if !bytes.Equal(p.Delegation, del) || !bytes.Equal(p.Sig, sig) || !bytes.Equal(p.Status, st) ||
					!bytes.Equal(p.StatusSig, stSig) || len(p.Rotations) != 0 {
					t.Fatalf("%s: presentation differs from the vector's members", name)
				}
				if _, err := leashwire.VerifyPresented(member, p, now); err != nil {
					t.Fatalf("%s: presentation refused by the reference verifier: %v", name, err)
				}
				if f.count("leash.status.get") != 0 {
					t.Fatalf("%s: refreshed a statement before its refresh time", name)
				}
				if in := m.ConnectionInfo(); len(in.Grants) != 1 || in.Grants[0].GrantID != d.GrantID {
					t.Fatalf("%s: info %+v", name, in)
				}
			}
		})

		t.Run(name+"/altered", func(t *testing.T) {
			at := time.Unix(c.StatusIssuedAt, 0)
			for _, part := range []string{"delegation", "sig", "status", "status_sig"} {
				for _, pos := range []string{"first", "middle", "last"} {
					parts := map[string][]byte{"delegation": bytes.Clone(del), "sig": bytes.Clone(sig),
						"status": bytes.Clone(st), "status_sig": bytes.Clone(stSig)}
					b := parts[part]
					b[map[string]int{"first": 0, "middle": len(b) / 2, "last": len(b) - 1}[pos]] ^= 0x01
					m, _ := newAt(at, set(t, false, wireFromVector(t, d, parts["delegation"], parts["sig"], parts["status"], parts["status_sig"])))
					if p, err := m.Present(ctx, d.GrantID); p != nil || err == nil {
						t.Errorf("%s: presented with %s altered at its %s byte", name, part, pos)
					}
				}
			}
			// Outside the statement's window, and for another agent key.
			for _, now := range []time.Time{time.Unix(c.AcceptTo+1, 0), time.Unix(c.StatusIssuedAt, 0).Add(-leashwire.StatusSkew - time.Second)} {
				m, _ := newAt(now, set(t, false, wireFromVector(t, d, del, sig, st, stSig)))
				if p, err := m.Present(ctx, d.GrantID); p != nil || err == nil {
					t.Errorf("%s: presented at %v", name, now)
				}
			}
			m := New(Options{Now: func() time.Time { return at }})
			f := &fakeConn{m: m, ik: pub(otherKey), access: pairing.Access{State: pairing.AccessActive},
				list: func() *vaultconn.Response { return ok(set(t, false, wireFromVector(t, d, del, sig, st, stSig))) }}
			_ = m.Bind(f)
			if p, err := m.Present(ctx, d.GrantID); p != nil || err == nil {
				t.Errorf("%s: presented for another agent key", name)
			}
		})
	}
}
