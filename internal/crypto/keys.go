// Package crypto provides cryptographic operations for the VettID Agent Connector.
//
// Implements X25519 key exchange, ChaCha20-Poly1305 encryption, HKDF key
// derivation, and Argon2id password hashing — matching the crypto stack used
// by the VettID enclave.
//
// Crypto stack:
//   - X25519 key exchange (Curve25519 ECDH)
//   - XChaCha20-Poly1305 AEAD (24-byte nonce)
//   - HKDF-SHA256 for key derivation with domain separation
//   - Argon2id for password-based key derivation
//   - ECIES: ephemeral X25519 + HKDF + XChaCha20-Poly1305
package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

const (
	KeySize   = 32
	NonceSize = 24 // XChaCha20-Poly1305

	// Domain separation labels for HKDF — must match enclave
	DomainConnection = "vettid-connection-v1"
	DomainAgent      = "vettid-agent-v1"
)

// X25519KeyPair holds an X25519 keypair for ECDH key exchange.
type X25519KeyPair struct {
	PublicKey  [KeySize]byte
	PrivateKey [KeySize]byte
}

// GenerateX25519KeyPair generates a new random X25519 keypair.
func GenerateX25519KeyPair() (*X25519KeyPair, error) {
	var priv [KeySize]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return nil, fmt.Errorf("generate random key: %w", err)
	}

	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("derive public key: %w", err)
	}

	kp := &X25519KeyPair{}
	copy(kp.PrivateKey[:], priv[:])
	copy(kp.PublicKey[:], pub)
	return kp, nil
}

// Zero securely wipes the private key material from memory.
func (kp *X25519KeyPair) Zero() {
	ZeroBytes(kp.PrivateKey[:])
}

// ComputeSharedSecret performs X25519 ECDH to derive a shared secret.
// The caller must zero the returned secret after use.
func ComputeSharedSecret(privateKey, peerPublicKey []byte) ([]byte, error) {
	if len(privateKey) != KeySize || len(peerPublicKey) != KeySize {
		return nil, fmt.Errorf("keys must be %d bytes", KeySize)
	}
	shared, err := curve25519.X25519(privateKey, peerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("compute shared secret: %w", err)
	}
	return shared, nil
}

// GenerateRandomBytes returns n cryptographically random bytes.
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("generate random bytes: %w", err)
	}
	return b, nil
}

// ZeroBytes overwrites a byte slice with zeros.
// SECURITY: Use this to wipe keys, secrets, and other sensitive data from memory.
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// TimingSafeEqual performs a constant-time comparison of two byte slices.
// Returns true if and only if the slices have equal length and equal content.
func TimingSafeEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
