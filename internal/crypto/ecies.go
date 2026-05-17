package crypto

import (
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// ECIES format: ephemeral_pubkey (32 bytes) || nonce (24 bytes) || ciphertext+tag
const eciesOverhead = KeySize + chacha20poly1305.NonceSizeX // 32 + 24 = 56

// SECURITY (#72): AEAD additional-authenticated-data binding.
// Encrypt always seals with eciesAADv1. Decrypt tries v1 first then
// falls back to nil for ciphertexts produced before this change, so
// existing agent credentials sealed under nil AAD still decrypt.
var eciesAADv1 = []byte("vettid-ecies-aad-v1")

// ECIESEncrypt encrypts plaintext for a recipient identified by their X25519 public key.
//
// Uses ECIES (Elliptic Curve Integrated Encryption Scheme):
//  1. Generate ephemeral X25519 keypair
//  2. ECDH: ephemeral_private * recipient_public → shared secret
//  3. HKDF-SHA256: shared secret + domain → encryption key
//  4. XChaCha20-Poly1305: encrypt plaintext with derived key
//  5. Output: ephemeral_public || nonce || ciphertext+tag
//
// The domain parameter provides cryptographic domain separation.
// This matches the enclave's encryptWithDomain pattern.
func ECIESEncrypt(recipientPublicKey []byte, plaintext []byte, domain string) ([]byte, error) {
	if len(recipientPublicKey) != KeySize {
		return nil, fmt.Errorf("recipient public key must be %d bytes", KeySize)
	}

	// 1. Generate ephemeral keypair
	ephPriv, err := GenerateRandomBytes(KeySize)
	if err != nil {
		return nil, fmt.Errorf("generate ephemeral key: %w", err)
	}
	defer ZeroBytes(ephPriv)

	ephPub, err := curve25519.X25519(ephPriv, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("derive ephemeral public key: %w", err)
	}

	// 2. ECDH
	sharedSecret, err := curve25519.X25519(ephPriv, recipientPublicKey)
	if err != nil {
		return nil, fmt.Errorf("ECDH key exchange: %w", err)
	}
	defer ZeroBytes(sharedSecret)

	// 3. HKDF
	encKey, err := DeriveKeyHKDF(sharedSecret, nil, domain)
	if err != nil {
		return nil, fmt.Errorf("derive encryption key: %w", err)
	}
	defer ZeroBytes(encKey)

	// 4. XChaCha20-Poly1305
	aead, err := chacha20poly1305.NewX(encKey)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	nonce, err := GenerateRandomBytes(aead.NonceSize())
	if err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	// SECURITY (#72): bind to eciesAADv1 — the vault-side decrypt
	// path accepts this and falls back to nil for legacy blobs.
	ciphertext := aead.Seal(nil, nonce, plaintext, eciesAADv1)

	// 5. Assemble: ephemeral_public (32) || nonce (24) || ciphertext+tag
	result := make([]byte, 0, len(ephPub)+len(nonce)+len(ciphertext))
	result = append(result, ephPub...)
	result = append(result, nonce...)
	result = append(result, ciphertext...)

	return result, nil
}

// ECIESDecrypt decrypts ECIES-encrypted data using the recipient's private key.
//
// Expects format: ephemeral_public (32) || nonce (24) || ciphertext+tag
// The domain must match what was used for encryption.
func ECIESDecrypt(recipientPrivateKey []byte, data []byte, domain string) ([]byte, error) {
	if len(recipientPrivateKey) != KeySize {
		return nil, fmt.Errorf("private key must be %d bytes", KeySize)
	}

	minSize := eciesOverhead + chacha20poly1305.Overhead // 56 + 16 = 72 minimum (empty plaintext)
	if len(data) < minSize {
		return nil, fmt.Errorf("ciphertext too short: need at least %d bytes, got %d", minSize, len(data))
	}

	// Parse components
	ephPub := data[:KeySize]
	nonce := data[KeySize : KeySize+chacha20poly1305.NonceSizeX]
	ciphertext := data[KeySize+chacha20poly1305.NonceSizeX:]

	// ECDH.
	// SECURITY (#83): ephPub is wire-supplied — reject small-order
	// points before the ECDH so a malicious sender can't probe the
	// recipient's long-lived private key via contributory behavior.
	sharedSecret, err := safeX25519(recipientPrivateKey, ephPub)
	if err != nil {
		return nil, fmt.Errorf("ECDH key exchange: %w", err)
	}
	defer ZeroBytes(sharedSecret)

	// HKDF
	encKey, err := DeriveKeyHKDF(sharedSecret, nil, domain)
	if err != nil {
		return nil, fmt.Errorf("derive encryption key: %w", err)
	}
	defer ZeroBytes(encKey)

	// Decrypt
	aead, err := chacha20poly1305.NewX(encKey)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	// SECURITY (#72): try eciesAADv1 first, fall back to nil AAD for
	// blobs produced before this change.
	plaintext, err := aead.Open(nil, nonce, ciphertext, eciesAADv1)
	if err != nil {
		fbPlaintext, fbErr := aead.Open(nil, nonce, ciphertext, nil)
		if fbErr != nil {
			return nil, fmt.Errorf("ECIES decrypt: %w", err)
		}
		plaintext = fbPlaintext
	}

	return plaintext, nil
}
