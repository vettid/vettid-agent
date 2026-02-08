package crypto

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

func Encrypt(key, plaintext, additionalData []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	// Prepend nonce to ciphertext
	ciphertext := aead.Seal(nonce, nonce, plaintext, additionalData)
	return ciphertext, nil
}

func Decrypt(key, ciphertextWithNonce, additionalData []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	nonceSize := aead.NonceSize()
	if len(ciphertextWithNonce) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce := ciphertextWithNonce[:nonceSize]
	ciphertext := ciphertextWithNonce[nonceSize:]

	plaintext, err := aead.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return plaintext, nil
}
