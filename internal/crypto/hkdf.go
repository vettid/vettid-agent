package crypto

import (
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// DeriveKeyHKDF derives a symmetric key from a shared secret using HKDF-SHA256.
// The domain parameter provides cryptographic domain separation — different domains
// produce different keys from the same shared secret.
//
// This matches the enclave's HKDF pattern for deriving connection-specific encryption keys.
func DeriveKeyHKDF(sharedSecret []byte, domain string) ([]byte, error) {
	if len(sharedSecret) == 0 {
		return nil, fmt.Errorf("shared secret must not be empty")
	}
	if domain == "" {
		return nil, fmt.Errorf("domain must not be empty")
	}

	// HKDF-SHA256: salt=domain (as bytes), info=nil
	// Matches enclave pattern: hkdf.New(sha256.New, sharedSecret, []byte(domain), nil)
	r := hkdf.New(sha256.New, sharedSecret, []byte(domain), nil)

	key := make([]byte, KeySize)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("HKDF expand: %w", err)
	}

	return key, nil
}

// DeriveConnectionKey derives a symmetric encryption key for a connection
// from an X25519 shared secret using the connection domain.
func DeriveConnectionKey(sharedSecret []byte) ([]byte, error) {
	return DeriveKeyHKDF(sharedSecret, DomainConnection)
}
