package crypto

import (
	"bytes"
	"testing"
)

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	key, err := GenerateRandomBytes(KeySize)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	plaintext := []byte("hello, VettID agent connector!")
	ciphertext, err := Encrypt(key, plaintext, nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Ciphertext should be longer than plaintext (nonce + tag overhead)
	if len(ciphertext) <= len(plaintext) {
		t.Error("ciphertext should be longer than plaintext")
	}

	// Ciphertext should not contain plaintext
	if bytes.Contains(ciphertext, plaintext) {
		t.Error("ciphertext contains plaintext")
	}

	decrypted, err := Decrypt(key, ciphertext, nil)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptDecrypt_WithAAD(t *testing.T) {
	key, err := GenerateRandomBytes(KeySize)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	plaintext := []byte("secret data")
	aad := []byte("connection-id:abc123")

	ciphertext, err := Encrypt(key, plaintext, aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Decrypt with correct AAD should succeed
	decrypted, err := Decrypt(key, ciphertext, aad)
	if err != nil {
		t.Fatalf("Decrypt with correct AAD: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Error("decrypted data does not match plaintext")
	}

	// Decrypt with wrong AAD should fail
	_, err = Decrypt(key, ciphertext, []byte("wrong-aad"))
	if err == nil {
		t.Error("expected error when decrypting with wrong AAD")
	}

	// Decrypt with no AAD should fail
	_, err = Decrypt(key, ciphertext, nil)
	if err == nil {
		t.Error("expected error when decrypting without AAD")
	}
}

func TestEncryptDecrypt_EmptyPlaintext(t *testing.T) {
	key, err := GenerateRandomBytes(KeySize)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	ciphertext, err := Encrypt(key, []byte{}, nil)
	if err != nil {
		t.Fatalf("Encrypt empty: %v", err)
	}

	decrypted, err := Decrypt(key, ciphertext, nil)
	if err != nil {
		t.Fatalf("Decrypt empty: %v", err)
	}

	if len(decrypted) != 0 {
		t.Errorf("expected empty plaintext, got %d bytes", len(decrypted))
	}
}

func TestEncrypt_DifferentCiphertextEachTime(t *testing.T) {
	key, err := GenerateRandomBytes(KeySize)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	plaintext := []byte("same plaintext")

	ct1, err := Encrypt(key, plaintext, nil)
	if err != nil {
		t.Fatalf("first Encrypt: %v", err)
	}

	ct2, err := Encrypt(key, plaintext, nil)
	if err != nil {
		t.Fatalf("second Encrypt: %v", err)
	}

	if bytes.Equal(ct1, ct2) {
		t.Error("two encryptions of the same plaintext produced identical ciphertext (nonce reuse)")
	}
}

func TestDecrypt_WrongKey(t *testing.T) {
	key1, _ := GenerateRandomBytes(KeySize)
	key2, _ := GenerateRandomBytes(KeySize)

	ciphertext, err := Encrypt(key1, []byte("secret"), nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	_, err = Decrypt(key2, ciphertext, nil)
	if err == nil {
		t.Error("expected error when decrypting with wrong key")
	}
}

func TestDecrypt_TamperedCiphertext(t *testing.T) {
	key, _ := GenerateRandomBytes(KeySize)

	ciphertext, err := Encrypt(key, []byte("secret"), nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Tamper with the last byte of ciphertext
	tampered := make([]byte, len(ciphertext))
	copy(tampered, ciphertext)
	tampered[len(tampered)-1] ^= 0xff

	_, err = Decrypt(key, tampered, nil)
	if err == nil {
		t.Error("expected error when decrypting tampered ciphertext")
	}
}

func TestDecrypt_TruncatedCiphertext(t *testing.T) {
	key, _ := GenerateRandomBytes(KeySize)

	_, err := Decrypt(key, []byte("short"), nil)
	if err == nil {
		t.Error("expected error for truncated ciphertext")
	}
}

func TestEncrypt_InvalidKeyLength(t *testing.T) {
	_, err := Encrypt(make([]byte, 16), []byte("data"), nil)
	if err == nil {
		t.Error("expected error for 16-byte key")
	}

	_, err = Encrypt(make([]byte, 64), []byte("data"), nil)
	if err == nil {
		t.Error("expected error for 64-byte key")
	}
}
