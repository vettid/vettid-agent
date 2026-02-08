package crypto

import (
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// Encrypt encrypts plaintext using XChaCha20-Poly1305 with the given symmetric key.
// The nonce is prepended to the ciphertext. additionalData is authenticated but not encrypted.
//
// Output format: nonce (24 bytes) || ciphertext+tag
func Encrypt(key, plaintext, additionalData []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("key must be %d bytes, got %d", KeySize, len(key))
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	nonce, err := GenerateRandomBytes(aead.NonceSize())
	if err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	// Prepend nonce to ciphertext
	ciphertext := aead.Seal(nonce, nonce, plaintext, additionalData)
	return ciphertext, nil
}

// Decrypt decrypts XChaCha20-Poly1305 encrypted data with the given symmetric key.
// Expects format: nonce (24 bytes) || ciphertext+tag
func Decrypt(key, ciphertextWithNonce, additionalData []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("key must be %d bytes, got %d", KeySize, len(key))
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	nonceSize := aead.NonceSize()
	minSize := nonceSize + aead.Overhead()
	if len(ciphertextWithNonce) < minSize {
		return nil, fmt.Errorf("ciphertext too short: need at least %d bytes, got %d", minSize, len(ciphertextWithNonce))
	}

	nonce := ciphertextWithNonce[:nonceSize]
	ciphertext := ciphertextWithNonce[nonceSize:]

	plaintext, err := aead.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, fmt.Errorf("decrypt: authentication failed")
	}

	return plaintext, nil
}
