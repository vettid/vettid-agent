package leash

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLoadOrCreate_PersistsAndReloads — first call generates a fresh
// key + writes the file; second call loads the same bytes. Catches
// any drift in serialization shape that would break existing installs.
func TestLoadOrCreate_PersistsAndReloads(t *testing.T) {
	dir := t.TempDir()

	k1, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("first LoadOrCreate: %v", err)
	}
	if len(k1.Private) != ed25519.PrivateKeySize {
		t.Errorf("private key size: got %d want %d", len(k1.Private), ed25519.PrivateKeySize)
	}
	if len(k1.Public) != ed25519.PublicKeySize {
		t.Errorf("public key size: got %d want %d", len(k1.Public), ed25519.PublicKeySize)
	}
	if k1.PublicB64 == "" {
		t.Error("PublicB64 should be set")
	}

	// File should exist with 0600 perms.
	path := filepath.Join(dir, KeyFileName)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("key file not written: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("file perms: got %o want 0600", info.Mode().Perm())
	}

	// Second call should load the same key, not regenerate.
	k2, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("second LoadOrCreate: %v", err)
	}
	if string(k1.Private) != string(k2.Private) {
		t.Error("private key changed across calls — should have loaded from disk")
	}
	if string(k1.Public) != string(k2.Public) {
		t.Error("public key changed across calls")
	}
	if k1.PublicB64 != k2.PublicB64 {
		t.Error("PublicB64 changed across calls")
	}
}

// TestLoadOrCreate_RejectsCorruptedFile — if someone tampers with the
// stored pubkey (without updating the priv), Load must refuse rather
// than return a key whose sigs won't verify.
func TestLoadOrCreate_RejectsCorruptedFile(t *testing.T) {
	dir := t.TempDir()

	// Generate one valid key.
	k1, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}

	// Write back a file where the public is bogus (zeros).
	bogus := persistedKey{
		Private: []byte(k1.Private),
		Public:  make([]byte, ed25519.PublicKeySize), // all zeros, won't match
	}
	path := filepath.Join(dir, KeyFileName)
	mustWriteJSON(t, path, bogus)

	if _, err := LoadOrCreate(dir); err == nil {
		t.Error("expected error on corrupted keypair file")
	} else if !strings.Contains(err.Error(), "corrupt") {
		t.Errorf("expected 'corrupt' in error, got: %v", err)
	}
}

// TestSignEnvelope_RoundTripsUnderPublicKey — the signature we produce
// must verify against the AgentKey.Public half. Equivalent of the
// verifier's PoP check, run locally as a sanity test.
func TestSignEnvelope_RoundTripsUnderPublicKey(t *testing.T) {
	dir := t.TempDir()
	k, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}

	leash := "header.claims.sig"
	request := map[string]any{"action": "profile.email:read"}
	nonce := "n0nceY2FudG91Y2h0aGlz"
	timestamp := int64(1716000000)

	sigB64, err := SignEnvelope(k, leash, request, nonce, timestamp)
	if err != nil {
		t.Fatalf("SignEnvelope: %v", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}

	// Reconstruct the canonical bytes the verifier would build.
	canon, err := canonicalJSON(map[string]any{
		"leash":     leash,
		"request":   request,
		"nonce":     nonce,
		"timestamp": timestamp,
	})
	if err != nil {
		t.Fatalf("canonicalJSON: %v", err)
	}
	if !ed25519.Verify(k.Public, []byte(canon), sig) {
		t.Error("signature did not verify under agent's pubkey")
	}
}

// TestCanonicalJSON_SortsKeysDeterministically — the canonicalization
// must produce the same bytes regardless of map iteration order.
// Catches any future refactor that breaks sort stability.
func TestCanonicalJSON_SortsKeysDeterministically(t *testing.T) {
	// Both maps have identical content; canonical output must match.
	a := map[string]any{
		"zebra": 1,
		"apple": 2,
		"mango": map[string]any{"y": 1, "x": 2},
	}
	b := map[string]any{
		"apple": 2,
		"mango": map[string]any{"x": 2, "y": 1},
		"zebra": 1,
	}
	ca, err := canonicalJSON(a)
	if err != nil {
		t.Fatalf("canonicalJSON(a): %v", err)
	}
	cb, err := canonicalJSON(b)
	if err != nil {
		t.Fatalf("canonicalJSON(b): %v", err)
	}
	if ca != cb {
		t.Errorf("canonicalization not stable:\n  a: %s\n  b: %s", ca, cb)
	}
	// Expected exact bytes — locks the canonicalization rules so a future
	// change has to acknowledge it touched the wire contract.
	want := `{"apple":2,"mango":{"x":2,"y":1},"zebra":1}`
	if ca != want {
		t.Errorf("canonicalization changed:\n  got:  %s\n  want: %s", ca, want)
	}
}

// TestCanonicalJSON_HandlesNull — null appears in our envelope as
// vettid:audience and must canonicalize to the literal "null".
func TestCanonicalJSON_HandlesNull(t *testing.T) {
	got, err := canonicalJSON(map[string]any{"k": nil})
	if err != nil {
		t.Fatalf("canonicalJSON: %v", err)
	}
	if got != `{"k":null}` {
		t.Errorf("null handling: got %s", got)
	}
}

func mustWriteJSON(t *testing.T, path string, v any) {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
