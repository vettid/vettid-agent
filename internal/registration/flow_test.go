package registration

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/vettid/vettid-agent/internal/crypto"
	vettidnats "github.com/vettid/vettid-agent/internal/nats"
)

// TestApprovalDecrypt_MatchesVaultEncrypt verifies that the agent can decrypt
// an approval envelope created the same way the vault does:
//
//	vault: sharedSecret = X25519(vaultPriv, agentPub)
//	vault: connKey = HKDF(sharedSecret, "vettid-connection-v1")
//	vault: encrypted = XChaCha20(connKey, approvalJSON)
//
//	agent: sharedSecret = X25519(agentPriv, vaultPub)  (same value)
//	agent: connKey = HKDF(sharedSecret, "vettid-connection-v1")  (same value)
//	agent: approvalJSON = XChaCha20-Decrypt(connKey, encrypted)
func TestApprovalDecrypt_MatchesVaultEncrypt(t *testing.T) {
	// Generate keypairs for both sides
	vaultKP, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("generate vault keypair: %v", err)
	}
	agentKP, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("generate agent keypair: %v", err)
	}

	// Both sides compute the same shared secret
	vaultShared, err := crypto.ComputeSharedSecret(vaultKP.PrivateKey[:], agentKP.PublicKey[:])
	if err != nil {
		t.Fatalf("vault compute shared secret: %v", err)
	}
	defer crypto.ZeroBytes(vaultShared)

	agentShared, err := crypto.ComputeSharedSecret(agentKP.PrivateKey[:], vaultKP.PublicKey[:])
	if err != nil {
		t.Fatalf("agent compute shared secret: %v", err)
	}
	defer crypto.ZeroBytes(agentShared)

	if !bytes.Equal(vaultShared, agentShared) {
		t.Fatal("shared secrets do not match — X25519 ECDH broken")
	}

	// Both sides derive the same connection key
	vaultConnKey, err := crypto.DeriveConnectionKey(vaultShared, "conn-test")
	if err != nil {
		t.Fatalf("vault derive connection key: %v", err)
	}
	defer crypto.ZeroBytes(vaultConnKey)

	agentConnKey, err := crypto.DeriveConnectionKey(agentShared, "conn-test")
	if err != nil {
		t.Fatalf("agent derive connection key: %v", err)
	}
	defer crypto.ZeroBytes(agentConnKey)

	if !bytes.Equal(vaultConnKey, agentConnKey) {
		t.Fatal("connection keys do not match — HKDF derivation broken")
	}

	// Vault encrypts approval (simulating vault-manager/connections.go)
	originalApproval := vettidnats.ConnectionApproval{
		ConnectionID: "conn-abc-123",
		KeyID:        "conn-abc-123",
		Contract: vettidnats.Contract{
			Scope:        []string{"api_keys", "ssh_keys"},
			ApprovalMode: "auto_within_contract",
			RateLimit:    vettidnats.RateLimit{Max: 60, Per: "hour"},
		},
	}

	approvalJSON, err := json.Marshal(originalApproval)
	if err != nil {
		t.Fatalf("marshal approval: %v", err)
	}

	// Vault encrypts with XChaCha20-Poly1305 (no AAD, matching vault code)
	encrypted, err := crypto.Encrypt(vaultConnKey, approvalJSON, nil)
	if err != nil {
		t.Fatalf("vault encrypt approval: %v", err)
	}

	// Agent decrypts with its independently-derived connection key
	decrypted, err := crypto.Decrypt(agentConnKey, encrypted, nil)
	if err != nil {
		t.Fatalf("agent decrypt approval: %v", err)
	}
	defer crypto.ZeroBytes(decrypted)

	var recoveredApproval vettidnats.ConnectionApproval
	if err := json.Unmarshal(decrypted, &recoveredApproval); err != nil {
		t.Fatalf("unmarshal decrypted approval: %v", err)
	}

	// Verify all fields match
	if recoveredApproval.ConnectionID != originalApproval.ConnectionID {
		t.Errorf("ConnectionID = %q, want %q", recoveredApproval.ConnectionID, originalApproval.ConnectionID)
	}
	if recoveredApproval.KeyID != originalApproval.KeyID {
		t.Errorf("KeyID = %q, want %q", recoveredApproval.KeyID, originalApproval.KeyID)
	}
	if recoveredApproval.Contract.ApprovalMode != originalApproval.Contract.ApprovalMode {
		t.Errorf("ApprovalMode = %q, want %q", recoveredApproval.Contract.ApprovalMode, originalApproval.Contract.ApprovalMode)
	}
	if len(recoveredApproval.Contract.Scope) != len(originalApproval.Contract.Scope) {
		t.Fatalf("Scope length = %d, want %d", len(recoveredApproval.Contract.Scope), len(originalApproval.Contract.Scope))
	}
	for i, s := range recoveredApproval.Contract.Scope {
		if s != originalApproval.Contract.Scope[i] {
			t.Errorf("Scope[%d] = %q, want %q", i, s, originalApproval.Contract.Scope[i])
		}
	}
	if recoveredApproval.Contract.RateLimit.Max != originalApproval.Contract.RateLimit.Max {
		t.Errorf("RateLimit.Max = %d, want %d", recoveredApproval.Contract.RateLimit.Max, originalApproval.Contract.RateLimit.Max)
	}
	if recoveredApproval.Contract.RateLimit.Per != originalApproval.Contract.RateLimit.Per {
		t.Errorf("RateLimit.Per = %q, want %q", recoveredApproval.Contract.RateLimit.Per, originalApproval.Contract.RateLimit.Per)
	}
}

// TestApprovalDecrypt_WrongKey verifies decryption fails with a different key.
func TestApprovalDecrypt_WrongKey(t *testing.T) {
	// Generate two unrelated keypairs (no shared secret relationship)
	vaultKP, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("generate vault keypair: %v", err)
	}
	agentKP, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("generate agent keypair: %v", err)
	}
	wrongKP, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("generate wrong keypair: %v", err)
	}

	// Vault encrypts with vault<->agent shared secret
	vaultShared, err := crypto.ComputeSharedSecret(vaultKP.PrivateKey[:], agentKP.PublicKey[:])
	if err != nil {
		t.Fatalf("compute shared secret: %v", err)
	}
	defer crypto.ZeroBytes(vaultShared)

	vaultConnKey, err := crypto.DeriveConnectionKey(vaultShared, "conn-test")
	if err != nil {
		t.Fatalf("derive connection key: %v", err)
	}
	defer crypto.ZeroBytes(vaultConnKey)

	approval := vettidnats.ConnectionApproval{
		ConnectionID: "conn-xyz-789",
		KeyID:        "conn-xyz-789",
	}
	approvalJSON, _ := json.Marshal(approval)

	encrypted, err := crypto.Encrypt(vaultConnKey, approvalJSON, nil)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Wrong agent tries to decrypt with vault<->wrong shared secret
	wrongShared, err := crypto.ComputeSharedSecret(wrongKP.PrivateKey[:], vaultKP.PublicKey[:])
	if err != nil {
		t.Fatalf("compute wrong shared secret: %v", err)
	}
	defer crypto.ZeroBytes(wrongShared)

	wrongConnKey, err := crypto.DeriveConnectionKey(wrongShared, "conn-test")
	if err != nil {
		t.Fatalf("derive wrong connection key: %v", err)
	}
	defer crypto.ZeroBytes(wrongConnKey)

	_, err = crypto.Decrypt(wrongConnKey, encrypted, nil)
	if err == nil {
		t.Error("expected decryption to fail with wrong agent's key")
	}
}
