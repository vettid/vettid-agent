package registration

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"golang.org/x/crypto/hkdf"

	"github.com/vettid/vettid-agent/internal/crypto"
)

// keyPair is a small helper for tests that need a real X25519 keypair
// without dragging the full GenerateX25519KeyPair signature into every
// test body.
func keyPair() (*crypto.X25519KeyPair, error) {
	return crypto.GenerateX25519KeyPair()
}

// TestDeriveAgentSessionKey_MatchesVaultWiring verifies the agent's HKDF
// inputs (salt + info) match what vault-manager/agent_pairing.go's
// deriveSessionKey produces. The vault uses:
//
//	salt = connection_id
//	info = "vettid-agent-session-v1|<session_id>"
//	ikm  = X25519(...)
//
// Re-derive that combination here directly with the stdlib HKDF and
// compare. If this test breaks, EVERY encrypted op a paired agent sends
// will fail to decrypt at the vault — silently, from the agent's side
// (the vault will return an error envelope the agent treats as a normal
// rejection). Domain-separation regressions here are uniquely
// catastrophic.
func TestDeriveAgentSessionKey_MatchesVaultWiring(t *testing.T) {
	shared := []byte("0123456789abcdef0123456789abcdef") // 32 bytes
	connID := "conn-deadbeef-0000-0000-0000-000000000000"
	sessID := "sess-cafebabe-1111-1111-1111-111111111111"

	got, err := deriveAgentSessionKey(shared, connID, sessID)
	if err != nil {
		t.Fatalf("deriveAgentSessionKey: %v", err)
	}
	if len(got) != crypto.KeySize {
		t.Fatalf("session key length = %d, want %d", len(got), crypto.KeySize)
	}

	// Independently compute what the vault would derive.
	info := DomainAgentSession + "|" + sessID
	r := hkdf.New(sha256.New, shared, []byte(connID), []byte(info))
	want := make([]byte, crypto.KeySize)
	if _, err := io.ReadFull(r, want); err != nil {
		t.Fatalf("reference HKDF: %v", err)
	}

	if !bytes.Equal(got, want) {
		t.Fatalf("session key mismatch:\n  got:  %x\n  want: %x", got, want)
	}
}

// TestDeriveAgentSessionKey_DomainConstant pins the actual string value
// of DomainAgentSession. The vault hardcodes "vettid-agent-session-v1";
// if anyone renames the agent's constant the runtime fails silently.
func TestDeriveAgentSessionKey_DomainConstant(t *testing.T) {
	if DomainAgentSession != "vettid-agent-session-v1" {
		t.Fatalf("DomainAgentSession = %q, must be %q (vault constant)",
			DomainAgentSession, "vettid-agent-session-v1")
	}
}

// TestDeriveAgentSessionKey_SessionIDIsLoadBearing — different session_ids
// must produce different keys (info-separation is per-session). Pins the
// behavior that an extend with a new session_id rotates the key.
func TestDeriveAgentSessionKey_SessionIDIsLoadBearing(t *testing.T) {
	shared := []byte("0123456789abcdef0123456789abcdef")
	connID := "conn-test"

	a, err := deriveAgentSessionKey(shared, connID, "sess-A")
	if err != nil {
		t.Fatalf("derive A: %v", err)
	}
	b, err := deriveAgentSessionKey(shared, connID, "sess-B")
	if err != nil {
		t.Fatalf("derive B: %v", err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("different session_ids produced the same key — info separation broken")
	}
}

// TestDeriveAgentSessionKey_RejectsEmptyInputs guards the input contract
// — empty shared / connection_id / session_id should error rather than
// silently produce a (technically valid but useless) zero-bound key.
func TestDeriveAgentSessionKey_RejectsEmptyInputs(t *testing.T) {
	cases := []struct {
		name   string
		shared []byte
		conn   string
		sess   string
	}{
		{"empty shared", nil, "c", "s"},
		{"empty connID", []byte("x"), "", "s"},
		{"empty sessID", []byte("x"), "c", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := deriveAgentSessionKey(tc.shared, tc.conn, tc.sess); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

// TestRequestSessionEnvelope_VaultParseable serializes the envelope our
// CompletePairing publishes and re-parses it through the structures the
// vault uses (replicated below, since they live in a different package).
// If this test breaks, the vault's HandleAgentRequestSession will reject
// the publish — but the agent has no visibility into that, since the
// vault's only response is the activation event that never comes.
func TestRequestSessionEnvelope_VaultParseable(t *testing.T) {
	meta := &AgentMetadata{
		AgentType:          "claude-code",
		BinaryFingerprint:  strings.Repeat("ab", 32),
		MachineFingerprint: strings.Repeat("cd", 32),
		Hostname:           "test-host",
		Platform:           "linux/amd64",
		OSName:             "Fedora Linux",
		OSVersion:          "43",
		AppVersion:         "0.1.0",
	}
	env := agentRequestSessionEnvelope{
		ID:        "abc123",
		Type:      "agent.request-session",
		Timestamp: "2026-05-23T12:00:00Z",
		Payload: agentRequestSessionInner{
			ConnectionID:          "conn-test",
			ApprovalToken:         strings.Repeat("ef", 32),
			AgentPubKey:           strings.Repeat("01", 32),
			AgentMetadata:         meta,
			RequestedScope:        []string{"secrets.catalog.read", "secrets.get"},
			RequestedApprovalMode: "always_ask",
			RequestedDurationSecs: 3600,
		},
	}
	envBytes, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}

	// Mirror the vault's two-stage unwrap: outer envelope unwrap, then
	// inner AgentRequestSessionRequest unmarshal.
	var outer struct {
		Type    string          `json:"type"`
		Payload json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal(envBytes, &outer); err != nil {
		t.Fatalf("outer unmarshal: %v", err)
	}
	if outer.Type != "agent.request-session" {
		t.Errorf("outer type = %q", outer.Type)
	}

	// Re-declare the vault's request shape (vault-manager/agent_pairing.go).
	// Done this way so a drift on either side breaks this test.
	var inner struct {
		ConnectionID          string `json:"connection_id"`
		ApprovalToken         string `json:"approval_token"`
		AgentPubKey           string `json:"agent_pubkey"`
		AgentMetadata         *struct {
			AgentType          string `json:"agent_type"`
			BinaryFingerprint  string `json:"binary_fingerprint"`
			MachineFingerprint string `json:"machine_fingerprint"`
			Hostname           string `json:"hostname,omitempty"`
			Platform           string `json:"platform,omitempty"`
			OSName             string `json:"os_name,omitempty"`
			OSVersion          string `json:"os_version,omitempty"`
			AppVersion         string `json:"app_version,omitempty"`
		} `json:"agent_metadata"`
		RequestedScope        []string `json:"requested_scope,omitempty"`
		RequestedApprovalMode string   `json:"requested_approval_mode,omitempty"`
		RequestedDurationSecs int64    `json:"requested_duration_s,omitempty"`
	}
	if err := json.Unmarshal(outer.Payload, &inner); err != nil {
		t.Fatalf("inner unmarshal: %v", err)
	}

	if inner.ConnectionID != "conn-test" {
		t.Errorf("connection_id = %q", inner.ConnectionID)
	}
	if inner.AgentPubKey != strings.Repeat("01", 32) {
		t.Errorf("agent_pubkey roundtrip failed")
	}
	if inner.AgentMetadata == nil {
		t.Fatal("agent_metadata missing")
	}
	if inner.AgentMetadata.AgentType != "claude-code" {
		t.Errorf("agent_type = %q", inner.AgentMetadata.AgentType)
	}
	if inner.AgentMetadata.BinaryFingerprint != strings.Repeat("ab", 32) {
		t.Errorf("binary_fingerprint roundtrip failed")
	}
	if inner.RequestedDurationSecs != 3600 {
		t.Errorf("requested_duration_s = %d", inner.RequestedDurationSecs)
	}
	if len(inner.RequestedScope) != 2 || inner.RequestedScope[0] != "secrets.catalog.read" {
		t.Errorf("requested_scope = %v", inner.RequestedScope)
	}
}

// TestSessionActivatedPayload_VaultShape verifies our activation parser
// is keyed on the same field names the vault's
// HandleAgentAuthorizeSession publishes (vault-manager/agent_pairing.go
// lines 322-334). Drift in either direction means CompletePairing
// times out instead of activating.
func TestSessionActivatedPayload_VaultShape(t *testing.T) {
	// Replicate the JSON the vault produces.
	vaultJSON := `{
		"type": "agent.session.activated",
		"connection_id": "conn-aaa",
		"session_id": "sess-bbb",
		"session_key_id": "sess-bbb",
		"vault_pubkey": "` + hex.EncodeToString(bytes.Repeat([]byte{0xa5}, 32)) + `",
		"expires_at": 1716480000,
		"duration_s": 3600,
		"granted_scope": ["secrets.get"],
		"approval_mode": "always_ask",
		"rate_limit": {"max": 60, "per": "hour"}
	}`
	var p sessionActivatedPayload
	if err := json.Unmarshal([]byte(vaultJSON), &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if p.Type != "agent.session.activated" {
		t.Errorf("type = %q", p.Type)
	}
	if p.ConnectionID != "conn-aaa" {
		t.Errorf("connection_id = %q", p.ConnectionID)
	}
	if p.SessionID != "sess-bbb" {
		t.Errorf("session_id = %q", p.SessionID)
	}
	if p.ExpiresAt != 1716480000 {
		t.Errorf("expires_at = %d", p.ExpiresAt)
	}
	if p.DurationSecs != 3600 {
		t.Errorf("duration_s = %d", p.DurationSecs)
	}
	if len(p.GrantedScope) != 1 || p.GrantedScope[0] != "secrets.get" {
		t.Errorf("granted_scope = %v", p.GrantedScope)
	}
	if p.ApprovalMode != "always_ask" {
		t.Errorf("approval_mode = %q", p.ApprovalMode)
	}
	if vp, err := hex.DecodeString(p.VaultPubKey); err != nil || len(vp) != 32 {
		t.Errorf("vault_pubkey not 32 hex bytes (len=%d, err=%v)", len(vp), err)
	}
}

// TestCollectAgentMetadata_RejectsEmptyAgentType — phone shows agent_type
// as the most prominent line on the approval card; refusing to ship
// without one is a deliberate UX choice.
func TestCollectAgentMetadata_RejectsEmptyAgentType(t *testing.T) {
	if _, err := CollectAgentMetadata("", "0.1.0"); err == nil {
		t.Fatal("expected error for empty agent_type")
	}
}

// TestExtendOutcome_ZeroIsIdempotent — the outcome holds the rotated
// session key. Zero MUST wipe it (and survive a second call + a nil
// receiver, matching PairingRuntime.Zero's contract).
func TestExtendOutcome_ZeroIsIdempotent(t *testing.T) {
	kp, err := keyPair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	o := &ExtendOutcome{
		SessionKey:   bytes.Repeat([]byte{0xCA}, 32),
		AgentKeyPair: kp,
	}
	o.Zero()
	o.Zero() // idempotent

	for _, b := range o.SessionKey {
		if b != 0 {
			t.Fatalf("session key byte not zeroed: %x", o.SessionKey)
		}
	}
	// nil receiver safe
	var nilOutcome *ExtendOutcome
	nilOutcome.Zero()
}

// TestCollectAgentMetadata_PopulatesRequiredFields — both fingerprints
// must be non-empty for the metadata to be usable.
func TestCollectAgentMetadata_PopulatesRequiredFields(t *testing.T) {
	m, err := CollectAgentMetadata("claude-code", "test-version")
	if err != nil {
		t.Fatalf("CollectAgentMetadata: %v", err)
	}
	if m.AgentType != "claude-code" {
		t.Errorf("agent_type = %q", m.AgentType)
	}
	if m.BinaryFingerprint == "" {
		t.Error("binary_fingerprint empty")
	}
	if m.MachineFingerprint == "" {
		t.Error("machine_fingerprint empty")
	}
	if m.AppVersion != "test-version" {
		t.Errorf("app_version = %q", m.AppVersion)
	}
	if m.Platform == "" {
		t.Error("platform empty — fingerprint.Platform() regression?")
	}
}
