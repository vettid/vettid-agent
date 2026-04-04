package crypto

import (
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// DeriveKeyHKDF derives a symmetric key from a shared secret using HKDF-SHA256.
// The salt provides binding to a specific context (e.g., connection_id).
// The domain parameter provides cryptographic domain separation.
//
// This matches the enclave's HKDF pattern for deriving connection-specific encryption keys.
func DeriveKeyHKDF(sharedSecret []byte, salt []byte, domain string) ([]byte, error) {
	if len(sharedSecret) == 0 {
		return nil, fmt.Errorf("shared secret must not be empty")
	}
	if domain == "" {
		return nil, fmt.Errorf("domain must not be empty")
	}

	// HKDF-SHA256: salt=connection_id (for binding), info=domain (for separation)
	r := hkdf.New(sha256.New, sharedSecret, salt, []byte(domain))

	key := make([]byte, KeySize)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("HKDF expand: %w", err)
	}

	return key, nil
}

// DeriveConnectionKey derives a symmetric encryption key for a connection
// from an X25519 shared secret using the connection_id as salt and the
// connection domain for separation.
func DeriveConnectionKey(sharedSecret []byte, connectionID string) ([]byte, error) {
	return DeriveKeyHKDF(sharedSecret, []byte(connectionID), DomainConnection)
}
