package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// TestECIES_AAD_RoundTrip confirms encrypt/decrypt round-trips
// under eciesAADv1.
func TestECIES_AAD_RoundTrip(t *testing.T) {
	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		t.Fatalf("rand: %v", err)
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("derive pub: %v", err)
	}
	msg := []byte("hello agent — testing #72 AAD binding")
	ct, err := ECIESEncrypt(pub, msg, "test-domain")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	pt, err := ECIESDecrypt(priv, ct, "test-domain")
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(pt, msg) {
		t.Errorf("round-trip mismatch")
	}
}

// TestECIES_AAD_LegacyFallback confirms that a ciphertext sealed with
// nil AAD (pre-#72) still decrypts via the fallback path.
func TestECIES_AAD_LegacyFallback(t *testing.T) {
	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		t.Fatalf("rand: %v", err)
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("derive pub: %v", err)
	}

	// Hand-build a legacy (nil-AAD) ciphertext using the same HKDF /
	// XChaCha20-Poly1305 wire format ECIESEncrypt produces.
	ephPriv, err := GenerateRandomBytes(KeySize)
	if err != nil {
		t.Fatalf("rand eph: %v", err)
	}
	ephPub, err := curve25519.X25519(ephPriv, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("derive eph pub: %v", err)
	}
	shared, err := curve25519.X25519(ephPriv, pub)
	if err != nil {
		t.Fatalf("ecdh: %v", err)
	}
	encKey, err := DeriveKeyHKDF(shared, nil, "legacy-domain")
	if err != nil {
		t.Fatalf("hkdf: %v", err)
	}
	aead, err := chacha20poly1305.NewX(encKey)
	if err != nil {
		t.Fatalf("aead: %v", err)
	}
	nonce, err := GenerateRandomBytes(aead.NonceSize())
	if err != nil {
		t.Fatalf("rand nonce: %v", err)
	}
	msg := []byte("pre-#72 agent ciphertext")
	ct := aead.Seal(nil, nonce, msg, nil) // legacy: nil AAD
	legacyBlob := append([]byte{}, ephPub...)
	legacyBlob = append(legacyBlob, nonce...)
	legacyBlob = append(legacyBlob, ct...)

	pt, err := ECIESDecrypt(priv, legacyBlob, "legacy-domain")
	if err != nil {
		t.Fatalf("legacy decrypt: %v", err)
	}
	if !bytes.Equal(pt, msg) {
		t.Errorf("legacy round-trip mismatch")
	}
}
