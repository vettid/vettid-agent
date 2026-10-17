package vettidagent_test

// The vault's LEASH vectors (VAULT-MESSAGING §16, leash.json; AGENT-PLAN
// §5), copied from vettid-vault at the commit recorded in
// testdata/vectors/SOURCE.md, checked against the vault packages this
// module is built with. A vector that stops matching is a stop-and-report
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
)

// leashVectorSHA256 is the sha256sum of testdata/vectors/leash.json,
// as recorded in testdata/vectors/SOURCE.md.
const leashVectorSHA256 = "b1200366e5310cd5ac7bbded3bb035b6efa1408579a7c19bd4a73ca9fcba2beb"

type leashCase struct {
	Case                string `json:"case"`
	NonceHex            string `json:"nonce_hex"`
	IAt                 int64  `json:"iat"`
	DelegationJSON      string `json:"delegation_json"`
	DelegationB64       string `json:"delegation_b64"`
	DelegationLen       int    `json:"delegation_len"`
	DelegationSHA256Hex string `json:"delegation_sha256_hex"`
	SigB64              string `json:"sig_b64"`
	StatusIssuedAt      int64  `json:"status_issued_at"`
	StatusJSON          string `json:"status_json"`
	StatusB64           string `json:"status_b64"`
	StatusSigB64        string `json:"status_sig_b64"`
	AcceptFrom          int64  `json:"accept_from"`
	AcceptTo            int64  `json:"accept_to"`
}

type leashVectors struct {
	ContextDelegation    string    `json:"context_delegation"`
	ContextStatus        string    `json:"context_status"`
	CredentialKeySeedHex string    `json:"credential_key_seed_hex"`
	CredentialKeyPKB64   string    `json:"credential_key_pk_b64"`
	AgentIKSeedHex       string    `json:"agent_ik_seed_hex"`
	AgentIKPKB64         string    `json:"agent_ik_pk_b64"`
	VaultIKSeedHex       string    `json:"vault_ik_seed_hex"`
	VaultIKPKB64         string    `json:"vault_ik_pk_b64"`
	SkewSeconds          int64     `json:"skew_seconds"`
	A                    leashCase `json:"a"`
	B                    leashCase `json:"b"`
}

func mustB64(t *testing.T, what, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
	return b
}

func mustHex(t *testing.T, what, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
	return b
}

func loadLeashVectors(t *testing.T) *leashVectors {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "vectors", "leash.json"))
	if err != nil {
		t.Fatal(err)
	}
	if h := sha256.Sum256(raw); hex.EncodeToString(h[:]) != leashVectorSHA256 {
		t.Fatalf("testdata/vectors/leash.json sha256 %x differs from SOURCE.md %s: stop and report", h, leashVectorSHA256)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var v leashVectors
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("leash.json: %v", err)
	}
	return &v
}

// presentation is one vector case decoded into what an agent presents.
type presentation struct {
	name      string
	c         leashCase
	del, sig  []byte
	st, stSig []byte
}

func (p presentation) presented() *leashwire.Presented {
	return &leashwire.Presented{
		Delegation: bytes.Clone(p.del), Sig: bytes.Clone(p.sig),
		Status: bytes.Clone(p.st), StatusSig: bytes.Clone(p.stSig),
	}
}

func TestLeashVectors(t *testing.T) {
	v := loadLeashVectors(t)

	if v.ContextDelegation != leashwire.Label || v.ContextStatus != leashwire.LabelStatus {
		t.Fatalf("context strings %q %q, leashwire %q %q", v.ContextDelegation, v.ContextStatus, leashwire.Label, leashwire.LabelStatus)
	}
	if time.Duration(v.SkewSeconds)*time.Second != leashwire.StatusSkew {
		t.Fatalf("skew %d s, leashwire %v", v.SkewSeconds, leashwire.StatusSkew)
	}
	keys := map[string]ed25519.PublicKey{}
	for name, k := range map[string][2]string{
		"credential key": {v.CredentialKeySeedHex, v.CredentialKeyPKB64},
		"agent ik":       {v.AgentIKSeedHex, v.AgentIKPKB64},
		"vault ik":       {v.VaultIKSeedHex, v.VaultIKPKB64},
	} {
		pk := ed25519.NewKeyFromSeed(mustHex(t, name, k[0])).Public().(ed25519.PublicKey)
		if !bytes.Equal(pk, mustB64(t, name, k[1])) {
			t.Fatalf("%s: public key does not match its seed", name)
		}
		keys[name] = pk
	}
	member := keys["credential key"]

	var cases []presentation
	for name, c := range map[string]leashCase{"a": v.A, "b": v.B} {
		p := presentation{name: name, c: c,
			del: mustB64(t, name+" delegation_b64", c.DelegationB64),
			sig: mustB64(t, name+" sig_b64", c.SigB64),
			st:  mustB64(t, name+" status_b64", c.StatusB64), stSig: mustB64(t, name+" status_sig_b64", c.StatusSigB64),
		}
		if string(p.del) != c.DelegationJSON || len(p.del) != c.DelegationLen || string(p.st) != c.StatusJSON {
			t.Fatalf("%s: base64 and JSON forms differ", name)
		}
		if h := sha256.Sum256(p.del); hex.EncodeToString(h[:]) != c.DelegationSHA256Hex {
			t.Fatalf("%s: delegation sha256 differs", name)
		}
		st, err := leashwire.ParseStatusCanonical(p.st)
		if err != nil || st.IssuedAt.Unix() != c.StatusIssuedAt {
			t.Fatalf("%s: status statement: issued_at differs or %v", name, err)
		}
		cases = append(cases, p)
	}

	for _, p := range cases {
		t.Run(p.name+"/accepted", func(t *testing.T) {
			var want struct {
				GrantID string `json:"grant_id"`
				Version uint64 `json:"version"`
			}
			nonce := mustHex(t, p.name+" nonce_hex", p.c.NonceHex)
			if err := json.Unmarshal(p.del, &want); err != nil {
				t.Fatal(err)
			}
			mid := (p.c.AcceptFrom + p.c.AcceptTo) / 2
			for _, now := range []int64{p.c.AcceptFrom, mid, p.c.AcceptTo} {
				d, err := leashwire.VerifyPresented(member, p.presented(), time.Unix(now, 0))
				if err != nil {
					t.Fatalf("%s (%s): refused at %d: %v", p.name, p.c.Case, now, err)
				}
				if d.GrantID != want.GrantID || d.Version != want.Version ||
					!bytes.Equal(d.Iss, member) || !bytes.Equal(d.Sub, keys["agent ik"]) ||
					!bytes.Equal(d.StatusIssuer, keys["vault ik"]) ||
					!bytes.Equal(d.Nonce, nonce) || d.IssuedAt.Unix() != p.c.IAt {
					t.Fatalf("%s: verified delegation does not match the vector", p.name)
				}
			}
		})

		t.Run(p.name+"/refused", func(t *testing.T) {
			at := time.Unix(p.c.AcceptFrom, 0)
			refuse := func(what string, pr *leashwire.Presented, key ed25519.PublicKey, now time.Time) {
				t.Helper()
				if _, err := leashwire.VerifyPresented(key, pr, now); err == nil {
					t.Errorf("%s: accepted %s", p.name, what)
				}
			}
			// Outside the acceptance window.
			refuse("one second before accept_from", p.presented(), member, time.Unix(p.c.AcceptFrom-1, 0))
			refuse("one second after accept_to", p.presented(), member, time.Unix(p.c.AcceptTo+1, 0))
			// Another member's key: the agent's and the vault's.
			refuse("under the agent's key", p.presented(), keys["agent ik"], at)
			refuse("under the vault's key", p.presented(), keys["vault ik"], at)
			// Without a status statement.
			pr := p.presented()
			pr.Status, pr.StatusSig = nil, nil
			refuse("without a status statement", pr, member, at)
			// Each part altered by one flipped bit at its first, middle and
			// last byte.
			for _, part := range []string{"delegation", "sig", "status", "status_sig"} {
				for _, pos := range []string{"first", "middle", "last"} {
					pr := p.presented()
					b := map[string][]byte{"delegation": pr.Delegation, "sig": pr.Sig, "status": pr.Status, "status_sig": pr.StatusSig}[part]
					i := map[string]int{"first": 0, "middle": len(b) / 2, "last": len(b) - 1}[pos]
					b[i] ^= 0x01
					refuse(part+" altered at its "+pos+" byte", pr, member, at)
				}
			}
			// Signatures swapped between the delegation and the statement.
			pr = p.presented()
			pr.Sig, pr.StatusSig = pr.StatusSig, pr.Sig
			refuse("with the two signatures swapped", pr, member, at)
		})
	}

	// The other case's status statement does not vouch for this delegation.
	t.Run("statements crossed", func(t *testing.T) {
		for i, p := range cases {
			o := cases[1-i]
			pr := p.presented()
			pr.Status, pr.StatusSig = bytes.Clone(o.st), bytes.Clone(o.stSig)
			if _, err := leashwire.VerifyPresented(member, pr, time.Unix(p.c.AcceptFrom, 0)); err == nil {
				t.Errorf("%s: accepted with %s's status statement", p.name, o.name)
			}
		}
	})
}
