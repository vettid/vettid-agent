package crypto

import (
	"bytes"
	"testing"
)

func TestDeriveKeyHKDF(t *testing.T) {
	secret, _ := GenerateRandomBytes(32)

	key, err := DeriveKeyHKDF(secret, DomainConnection)
	if err != nil {
		t.Fatalf("DeriveKeyHKDF: %v", err)
	}

	if len(key) != KeySize {
		t.Errorf("derived key length = %d, want %d", len(key), KeySize)
	}
}

func TestDeriveKeyHKDF_Deterministic(t *testing.T) {
	secret := []byte("fixed-shared-secret-for-testing!")

	key1, err := DeriveKeyHKDF(secret, DomainConnection)
	if err != nil {
		t.Fatalf("first DeriveKeyHKDF: %v", err)
	}

	key2, err := DeriveKeyHKDF(secret, DomainConnection)
	if err != nil {
		t.Fatalf("second DeriveKeyHKDF: %v", err)
	}

	if !bytes.Equal(key1, key2) {
		t.Error("same input should produce same output")
	}
}

func TestDeriveKeyHKDF_DomainSeparation(t *testing.T) {
	secret := []byte("fixed-shared-secret-for-testing!")

	key1, err := DeriveKeyHKDF(secret, DomainConnection)
	if err != nil {
		t.Fatalf("DeriveKeyHKDF connection: %v", err)
	}

	key2, err := DeriveKeyHKDF(secret, DomainAgent)
	if err != nil {
		t.Fatalf("DeriveKeyHKDF agent: %v", err)
	}

	if bytes.Equal(key1, key2) {
		t.Error("different domains should produce different keys")
	}
}

func TestDeriveKeyHKDF_DifferentSecrets(t *testing.T) {
	key1, _ := DeriveKeyHKDF([]byte("secret-A-padded-to-32-bytes!!!!"), DomainConnection)
	key2, _ := DeriveKeyHKDF([]byte("secret-B-padded-to-32-bytes!!!!"), DomainConnection)

	if bytes.Equal(key1, key2) {
		t.Error("different secrets should produce different keys")
	}
}

func TestDeriveKeyHKDF_EmptyInputs(t *testing.T) {
	_, err := DeriveKeyHKDF(nil, DomainConnection)
	if err == nil {
		t.Error("expected error for nil secret")
	}

	_, err = DeriveKeyHKDF([]byte("secret"), "")
	if err == nil {
		t.Error("expected error for empty domain")
	}
}

func TestDeriveConnectionKey(t *testing.T) {
	// Simulate a full key exchange
	alice, _ := GenerateX25519KeyPair()
	bob, _ := GenerateX25519KeyPair()

	aliceShared, _ := ComputeSharedSecret(alice.PrivateKey[:], bob.PublicKey[:])
	bobShared, _ := ComputeSharedSecret(bob.PrivateKey[:], alice.PublicKey[:])

	aliceKey, err := DeriveConnectionKey(aliceShared)
	if err != nil {
		t.Fatalf("Alice DeriveConnectionKey: %v", err)
	}

	bobKey, err := DeriveConnectionKey(bobShared)
	if err != nil {
		t.Fatalf("Bob DeriveConnectionKey: %v", err)
	}

	// Both sides should derive the same connection key
	if !bytes.Equal(aliceKey, bobKey) {
		t.Error("Alice and Bob derived different connection keys")
	}
}
