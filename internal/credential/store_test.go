package credential

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/vettid/vettid-agent/internal/crypto"
)

func testCreds() *ConnectionCredentials {
	return &ConnectionCredentials{
		ConnectionID:    "conn-abc123",
		ConnectionKey:   bytes.Repeat([]byte{0x42}, 32),
		KeyID:           "key-001",
		AgentPrivateKey: bytes.Repeat([]byte{0x11}, 32),
		AgentPublicKey:  bytes.Repeat([]byte{0x22}, 32),
		VaultPublicKey:  bytes.Repeat([]byte{0x33}, 32),
		JWT:             "eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5In0",
		Seed:            "SUAB1234567890",
		MessageSpaceURL: "nats://ms.vettid.dev:4222",
		OwnerGUID:       "owner-guid-123",
		OwnerName:       "Jane D.",
		Scope:           []string{"api_keys", "ssh_keys"},
		ApprovalMode:    "auto_within_contract",
	}
}

func TestSaveLoad_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	passphrase := []byte("Test-Pass-1234!")
	platformKey := bytes.Repeat([]byte{0xAA}, 32)
	creds := testCreds()

	if err := Save(dir, creds, passphrase, platformKey); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// File should exist
	if !Exists(dir) {
		t.Fatal("Exists should return true after Save")
	}

	// File should have restrictive permissions
	info, err := os.Stat(filepath.Join(dir, credentialFile))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("file permissions = %o, want 0600", info.Mode().Perm())
	}

	// Load should return identical credentials
	loaded, err := Load(dir, passphrase, platformKey)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if loaded.ConnectionID != creds.ConnectionID {
		t.Errorf("ConnectionID = %q, want %q", loaded.ConnectionID, creds.ConnectionID)
	}
	if !bytes.Equal(loaded.ConnectionKey, creds.ConnectionKey) {
		t.Error("ConnectionKey mismatch")
	}
	if loaded.KeyID != creds.KeyID {
		t.Errorf("KeyID = %q, want %q", loaded.KeyID, creds.KeyID)
	}
	if !bytes.Equal(loaded.AgentPrivateKey, creds.AgentPrivateKey) {
		t.Error("AgentPrivateKey mismatch")
	}
	if !bytes.Equal(loaded.AgentPublicKey, creds.AgentPublicKey) {
		t.Error("AgentPublicKey mismatch")
	}
	if !bytes.Equal(loaded.VaultPublicKey, creds.VaultPublicKey) {
		t.Error("VaultPublicKey mismatch")
	}
	if loaded.JWT != creds.JWT {
		t.Errorf("JWT = %q, want %q", loaded.JWT, creds.JWT)
	}
	if loaded.Seed != creds.Seed {
		t.Errorf("Seed = %q, want %q", loaded.Seed, creds.Seed)
	}
	if loaded.MessageSpaceURL != creds.MessageSpaceURL {
		t.Errorf("MessageSpaceURL = %q, want %q", loaded.MessageSpaceURL, creds.MessageSpaceURL)
	}
	if loaded.OwnerGUID != creds.OwnerGUID {
		t.Errorf("OwnerGUID = %q, want %q", loaded.OwnerGUID, creds.OwnerGUID)
	}
	if loaded.OwnerName != creds.OwnerName {
		t.Errorf("OwnerName = %q, want %q", loaded.OwnerName, creds.OwnerName)
	}
	if len(loaded.Scope) != len(creds.Scope) {
		t.Errorf("Scope length = %d, want %d", len(loaded.Scope), len(creds.Scope))
	}
	if loaded.ApprovalMode != creds.ApprovalMode {
		t.Errorf("ApprovalMode = %q, want %q", loaded.ApprovalMode, creds.ApprovalMode)
	}
}

func TestLoad_WrongPassphrase(t *testing.T) {
	dir := t.TempDir()
	platformKey := bytes.Repeat([]byte{0xAA}, 32)

	if err := Save(dir, testCreds(), []byte("Correct-Pass-1234!"), platformKey); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Load with a wrong passphrase — Load does not enforce strength so
	// short attempts are still rejected via AEAD failure, not a strength
	// gate. This documents the asymmetry: Save is strict, Load is
	// permissive so legacy installs still decrypt.
	_, err := Load(dir, []byte("Wrong-Pass-9999@"), platformKey)
	if err == nil {
		t.Error("expected error with wrong passphrase")
	}
}

func TestLoad_WrongPlatformKey(t *testing.T) {
	dir := t.TempDir()
	passphrase := []byte("Test-Pass-1234!")

	if err := Save(dir, testCreds(), passphrase, bytes.Repeat([]byte{0xAA}, 32)); err != nil {
		t.Fatalf("Save: %v", err)
	}

	_, err := Load(dir, passphrase, bytes.Repeat([]byte{0xBB}, 32))
	if err == nil {
		t.Error("expected error with wrong platform key (different machine)")
	}
}

func TestLoad_NoFile(t *testing.T) {
	dir := t.TempDir()

	_, err := Load(dir, []byte("Test-Pass-1234!"), []byte("key"))
	if err == nil {
		t.Error("expected error when no credential file exists")
	}
}

func TestExists(t *testing.T) {
	dir := t.TempDir()

	if Exists(dir) {
		t.Error("Exists should return false for empty directory")
	}

	// Create the file
	Save(dir, testCreds(), []byte("Test-Pass-1234!"), bytes.Repeat([]byte{0xAA}, 32))

	if !Exists(dir) {
		t.Error("Exists should return true after Save")
	}
}

func TestDelete(t *testing.T) {
	dir := t.TempDir()

	Save(dir, testCreds(), []byte("Test-Pass-1234!"), bytes.Repeat([]byte{0xAA}, 32))

	if !Exists(dir) {
		t.Fatal("file should exist after Save")
	}

	if err := Delete(dir); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	if Exists(dir) {
		t.Error("file should not exist after Delete")
	}

	// Delete on non-existent file should not error
	if err := Delete(dir); err != nil {
		t.Errorf("Delete non-existent: %v", err)
	}
}

func TestLoadWithTolerance_FullMatch(t *testing.T) {
	dir := t.TempDir()
	passphrase := "Test-Pass-1234!"

	// Create a platform key file for deterministic testing
	keyFile := filepath.Join(dir, "platform.key")
	keyData := bytes.Repeat([]byte{0xAA}, 32)
	os.WriteFile(keyFile, keyData, 0600)

	// Save using the platform key file
	key, _ := readPlatformKey(keyFile)
	if err := Save(dir, testCreds(), []byte(passphrase), key); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Load with tolerance — should succeed with full match
	loaded, reEncrypted, err := LoadWithTolerance(dir, passphrase, keyFile)
	if err != nil {
		t.Fatalf("LoadWithTolerance: %v", err)
	}
	if reEncrypted {
		t.Error("should not re-encrypt when full match succeeds")
	}
	if loaded.ConnectionID != testCreds().ConnectionID {
		t.Error("loaded credentials don't match")
	}
}

func TestLoadWithTolerance_WrongPassphrase(t *testing.T) {
	dir := t.TempDir()

	keyFile := filepath.Join(dir, "platform.key")
	os.WriteFile(keyFile, bytes.Repeat([]byte{0xAA}, 32), 0600)

	key, _ := readPlatformKey(keyFile)
	Save(dir, testCreds(), []byte("correct"), key)

	_, _, err := LoadWithTolerance(dir, "wrong", keyFile)
	if err == nil {
		t.Error("expected error with wrong passphrase")
	}
}

func TestZero(t *testing.T) {
	creds := testCreds()
	creds.Zero()

	allZero := func(b []byte) bool {
		for _, v := range b {
			if v != 0 {
				return false
			}
		}
		return true
	}

	if !allZero(creds.ConnectionKey) {
		t.Error("ConnectionKey not zeroed")
	}
	if !allZero(creds.AgentPrivateKey) {
		t.Error("AgentPrivateKey not zeroed")
	}
	if !allZero(creds.AgentPublicKey) {
		t.Error("AgentPublicKey not zeroed")
	}
	if !allZero(creds.VaultPublicKey) {
		t.Error("VaultPublicKey not zeroed")
	}
}

func TestStoreVersion(t *testing.T) {
	dir := t.TempDir()
	platformKey := bytes.Repeat([]byte{0xAA}, 32)

	Save(dir, testCreds(), []byte("Test-Pass-1234!"), platformKey)

	// Read the raw store to check version
	store, err := readStore(dir)
	if err != nil {
		t.Fatalf("readStore: %v", err)
	}

	if store.Version != storeVersion {
		t.Errorf("store version = %d, want %d", store.Version, storeVersion)
	}

	// Argon2 params should be stored
	params := crypto.DefaultArgon2Params()
	if store.Argon2Params.Time != params.Time {
		t.Errorf("Argon2 Time = %d, want %d", store.Argon2Params.Time, params.Time)
	}
	if store.Argon2Params.Memory != params.Memory {
		t.Errorf("Argon2 Memory = %d, want %d", store.Argon2Params.Memory, params.Memory)
	}
	if store.Argon2Params.Threads != params.Threads {
		t.Errorf("Argon2 Threads = %d, want %d", store.Argon2Params.Threads, params.Threads)
	}
}

func TestSave_EncryptedOnDisk(t *testing.T) {
	dir := t.TempDir()
	platformKey := bytes.Repeat([]byte{0xAA}, 32)
	creds := testCreds()

	Save(dir, creds, []byte("Test-Pass-1234!"), platformKey)

	// Raw file should not contain plaintext credential values
	data, _ := os.ReadFile(filepath.Join(dir, credentialFile))

	if bytes.Contains(data, []byte(creds.ConnectionID)) {
		t.Error("raw file contains plaintext ConnectionID")
	}
	if bytes.Contains(data, []byte(creds.JWT)) {
		t.Error("raw file contains plaintext JWT")
	}
	if bytes.Contains(data, []byte(creds.OwnerName)) {
		t.Error("raw file contains plaintext OwnerName")
	}
}

// Helper to read a platform key file
func readPlatformKey(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return data[:32], nil
}
