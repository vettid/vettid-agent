// Package crypto provides cryptographic operations for the VettID Agent Connector.
//
// Implements X25519 key exchange, ChaCha20-Poly1305 encryption, and Argon2id
// key derivation — matching the crypto stack used by the VettID enclave.
package crypto

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

const (
	KeySize    = 32
	NonceSize  = 24 // XChaCha20-Poly1305
)

type X25519KeyPair struct {
	PublicKey  [KeySize]byte
	PrivateKey [KeySize]byte
}

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

func ComputeSharedSecret(privateKey, peerPublicKey []byte) ([]byte, error) {
	shared, err := curve25519.X25519(privateKey, peerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("compute shared secret: %w", err)
	}
	return shared, nil
}
