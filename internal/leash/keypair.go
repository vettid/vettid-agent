// Package leash holds the agent-side cryptographic material for LEASH
// token proof-of-possession and a thin client for the public validator.
//
// Specifically:
//   - Ed25519 keypair management (lazy generate + persist + load)
//   - Canonical-JSON construction of the verifier envelope
//   - EdDSA signing of that envelope
//
// The agent's private half NEVER leaves disk + memory. The public half
// goes into LEASH tokens as `vettid:agent_pubkey` so verifiers can
// challenge the agent to prove possession on every verify call.
//
// See vettid-dev/docs/LEASH-TOKEN-FORMAT.md for the wire format.
package leash

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// KeyFileName is the on-disk name of the persisted agent keypair.
// Lives under the agent's config dir alongside other connection state.
const KeyFileName = "leash_agent_key.json"

// persistedKey is the on-disk JSON wrapper. Private + public are kept
// in the same file because (a) the public is derivable from private,
// and (b) keeping them paired makes corruption detection straightforward
// — if you read both back and ed25519 doesn't agree, the file is bad.
type persistedKey struct {
	Private []byte `json:"private"` // 64 bytes (Ed25519 expanded seed)
	Public  []byte `json:"public"`  // 32 bytes
}

// AgentKey is an in-memory Ed25519 keypair plus the base64url-encoded
// public half that LEASH tokens carry.
type AgentKey struct {
	Private   ed25519.PrivateKey
	Public    ed25519.PublicKey
	PublicB64 string // base64url, no padding — the LEASH vettid:agent_pubkey shape
}

// LoadOrCreate returns the persisted keypair for this agent, generating
// a fresh one on first call. The file lives at {configDir}/{KeyFileName}
// with 0600 permissions.
//
// Idempotent: subsequent calls on the same configDir return the same key.
// First call writes a new file; subsequent calls read it.
func LoadOrCreate(configDir string) (*AgentKey, error) {
	path := filepath.Join(configDir, KeyFileName)
	if data, err := os.ReadFile(path); err == nil {
		return parsePersisted(data)
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	// Fresh keypair.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 keypair: %w", err)
	}
	wrapped := persistedKey{Private: []byte(priv), Public: []byte(pub)}
	out, err := json.Marshal(wrapped)
	if err != nil {
		return nil, fmt.Errorf("marshal keypair: %w", err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		return nil, fmt.Errorf("write %s: %w", path, err)
	}
	return &AgentKey{
		Private:   priv,
		Public:    pub,
		PublicB64: base64.RawURLEncoding.EncodeToString(pub),
	}, nil
}

// parsePersisted decodes a previously-written keypair file and
// sanity-checks the byte lengths. Returns a clear error rather than
// letting downstream Ed25519 ops panic on a malformed key.
func parsePersisted(data []byte) (*AgentKey, error) {
	var p persistedKey
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parse keypair file: %w", err)
	}
	if len(p.Private) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("private key must be %d bytes, got %d",
			ed25519.PrivateKeySize, len(p.Private))
	}
	if len(p.Public) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key must be %d bytes, got %d",
			ed25519.PublicKeySize, len(p.Public))
	}
	// Cross-check: re-derive the public from the private and require
	// equality. Detects corruption / tampering of the on-disk file.
	derived := ed25519.PrivateKey(p.Private).Public().(ed25519.PublicKey)
	if string(derived) != string(p.Public) {
		return nil, fmt.Errorf("keypair file corrupt: pubkey doesn't match privkey")
	}
	return &AgentKey{
		Private:   ed25519.PrivateKey(p.Private),
		Public:    ed25519.PublicKey(p.Public),
		PublicB64: base64.RawURLEncoding.EncodeToString(p.Public),
	}, nil
}

// SignEnvelope returns the base64url-encoded EdDSA signature over the
// canonical JSON of `{leash, request, nonce, timestamp}`. The verifier
// reconstructs the exact same canonical form and re-verifies.
//
// MUST match the validator's canonicalization byte-for-byte:
//   - object keys sorted lexicographically
//   - no whitespace anywhere
//   - JSON-standard string escaping (\", \\, \n, etc.)
func SignEnvelope(key *AgentKey, leash string, request any, nonce string, timestamp int64) (string, error) {
	canon, err := canonicalJSON(map[string]any{
		"leash":     leash,
		"request":   request,
		"nonce":     nonce,
		"timestamp": timestamp,
	})
	if err != nil {
		return "", fmt.Errorf("canonicalize envelope: %w", err)
	}
	sig := ed25519.Sign(key.Private, []byte(canon))
	return base64.RawURLEncoding.EncodeToString(sig), nil
}

// canonicalJSON produces a deterministic byte representation matching
// the verifier's canonicalization rules: sorted keys, no whitespace,
// JSON.stringify-style escaping. Pure, no allocations beyond the result.
func canonicalJSON(value any) (string, error) {
	switch v := value.(type) {
	case nil:
		return "null", nil
	case bool, float64, int, int64, string:
		out, err := json.Marshal(v)
		if err != nil {
			return "", err
		}
		return string(out), nil
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		// Sort lexicographically — same as Object.keys().sort() in JS.
		for i := 1; i < len(keys); i++ {
			for j := i; j > 0 && keys[j-1] > keys[j]; j-- {
				keys[j-1], keys[j] = keys[j], keys[j-1]
			}
		}
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			kJSON, err := json.Marshal(k)
			if err != nil {
				return "", err
			}
			child, err := canonicalJSON(v[k])
			if err != nil {
				return "", err
			}
			parts = append(parts, string(kJSON)+":"+child)
		}
		return "{" + join(parts, ",") + "}", nil
	case []any:
		parts := make([]string, 0, len(v))
		for _, item := range v {
			child, err := canonicalJSON(item)
			if err != nil {
				return "", err
			}
			parts = append(parts, child)
		}
		return "[" + join(parts, ",") + "]", nil
	default:
		// Fall through to json.Marshal for unrecognized shapes —
		// callers should keep envelopes to primitives + maps + arrays
		// but be permissive about request payload shape.
		out, err := json.Marshal(v)
		if err != nil {
			return "", err
		}
		return string(out), nil
	}
}

// join is strings.Join inlined to avoid the import for this one call.
func join(parts []string, sep string) string {
	if len(parts) == 0 {
		return ""
	}
	out := parts[0]
	for i := 1; i < len(parts); i++ {
		out += sep + parts[i]
	}
	return out
}
