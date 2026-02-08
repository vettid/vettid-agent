package crypto

import (
	"testing"
)

func TestGenerateX25519KeyPair(t *testing.T) {
	kp, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}

	// Public and private keys should be 32 bytes
	if len(kp.PublicKey) != KeySize {
		t.Errorf("public key length = %d, want %d", len(kp.PublicKey), KeySize)
	}
	if len(kp.PrivateKey) != KeySize {
		t.Errorf("private key length = %d, want %d", len(kp.PrivateKey), KeySize)
	}

	// Keys should not be all zeros
	allZero := true
	for _, b := range kp.PublicKey {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("public key is all zeros")
	}

	// Public and private keys should be different
	if kp.PublicKey == kp.PrivateKey {
		t.Error("public and private keys are identical")
	}
}

func TestGenerateX25519KeyPair_Uniqueness(t *testing.T) {
	kp1, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("first GenerateX25519KeyPair: %v", err)
	}

	kp2, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("second GenerateX25519KeyPair: %v", err)
	}

	if kp1.PublicKey == kp2.PublicKey {
		t.Error("two generated keypairs have identical public keys")
	}
	if kp1.PrivateKey == kp2.PrivateKey {
		t.Error("two generated keypairs have identical private keys")
	}
}

func TestComputeSharedSecret(t *testing.T) {
	// Generate two keypairs
	alice, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("generate Alice keypair: %v", err)
	}

	bob, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("generate Bob keypair: %v", err)
	}

	// Both sides should derive the same shared secret
	aliceShared, err := ComputeSharedSecret(alice.PrivateKey[:], bob.PublicKey[:])
	if err != nil {
		t.Fatalf("Alice compute shared secret: %v", err)
	}

	bobShared, err := ComputeSharedSecret(bob.PrivateKey[:], alice.PublicKey[:])
	if err != nil {
		t.Fatalf("Bob compute shared secret: %v", err)
	}

	if !TimingSafeEqual(aliceShared, bobShared) {
		t.Error("shared secrets do not match")
	}

	// Shared secret should be 32 bytes
	if len(aliceShared) != KeySize {
		t.Errorf("shared secret length = %d, want %d", len(aliceShared), KeySize)
	}
}

func TestComputeSharedSecret_InvalidKeyLength(t *testing.T) {
	_, err := ComputeSharedSecret(make([]byte, 16), make([]byte, 32))
	if err == nil {
		t.Error("expected error for short private key")
	}

	_, err = ComputeSharedSecret(make([]byte, 32), make([]byte, 16))
	if err == nil {
		t.Error("expected error for short public key")
	}
}

func TestZero(t *testing.T) {
	kp, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}

	kp.Zero()

	for i, b := range kp.PrivateKey {
		if b != 0 {
			t.Errorf("private key byte %d = %d after Zero, want 0", i, b)
		}
	}
}

func TestGenerateRandomBytes(t *testing.T) {
	b, err := GenerateRandomBytes(32)
	if err != nil {
		t.Fatalf("GenerateRandomBytes: %v", err)
	}
	if len(b) != 32 {
		t.Errorf("length = %d, want 32", len(b))
	}

	// Should not be all zeros (probabilistically impossible)
	allZero := true
	for _, v := range b {
		if v != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("random bytes are all zeros")
	}
}

func TestZeroBytes(t *testing.T) {
	b := []byte{1, 2, 3, 4, 5}
	ZeroBytes(b)
	for i, v := range b {
		if v != 0 {
			t.Errorf("byte %d = %d after ZeroBytes, want 0", i, v)
		}
	}
}

func TestTimingSafeEqual(t *testing.T) {
	a := []byte{1, 2, 3, 4}
	b := []byte{1, 2, 3, 4}
	c := []byte{1, 2, 3, 5}
	d := []byte{1, 2, 3}

	if !TimingSafeEqual(a, b) {
		t.Error("equal slices should return true")
	}
	if TimingSafeEqual(a, c) {
		t.Error("different slices should return false")
	}
	if TimingSafeEqual(a, d) {
		t.Error("different length slices should return false")
	}
	if !TimingSafeEqual(nil, nil) {
		t.Error("two nil slices should return true")
	}
	if !TimingSafeEqual([]byte{}, []byte{}) {
		t.Error("two empty slices should return true")
	}
}
