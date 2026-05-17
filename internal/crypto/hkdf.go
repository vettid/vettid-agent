package crypto

import (
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// DeriveKeyHKDF derives a symmetric key from a shared secret using HKDF-SHA256.
//
// SECURITY (#105): HKDF parameters are wired deliberately:
//   • IKM    = shared secret (the X25519 output or other secret input)
//   • salt   = caller-supplied per-context value (typically a stable
//              connection_id, request_id, or other identifier)
//   • info   = domain string (cross-purpose separation tag)
//
// The original audit flagged "HKDF uses domain as salt, not info" —
// that observation was stale; the wiring below puts the salt where
// salt belongs (per-context binding via the Extract step) and the
// domain where info belongs (per-purpose separation via the Expand
// step). RFC 5869 §3.1 + §3.2 covers exactly this split. Keep both
// non-empty: an empty salt collapses Extract to a fixed mapping, and
// an empty info weakens domain separation across call sites.
//
// This matches the enclave's HKDF pattern for deriving connection-
// specific encryption keys.
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
