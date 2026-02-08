package crypto

import (
	"bytes"
	"testing"
)

func TestECIES_RoundTrip(t *testing.T) {
	recipient, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}

	plaintext := []byte("secret message for the vault owner")
	domain := DomainAgent

	ciphertext, err := ECIESEncrypt(recipient.PublicKey[:], plaintext, domain)
	if err != nil {
		t.Fatalf("ECIESEncrypt: %v", err)
	}

	// Ciphertext should include ephemeral pubkey (32) + nonce (24) + ciphertext + tag (16)
	expectedMinLen := 32 + 24 + len(plaintext) + 16
	if len(ciphertext) != expectedMinLen {
		t.Errorf("ciphertext length = %d, want %d", len(ciphertext), expectedMinLen)
	}

	decrypted, err := ECIESDecrypt(recipient.PrivateKey[:], ciphertext, domain)
	if err != nil {
		t.Fatalf("ECIESDecrypt: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

func TestECIES_DifferentCiphertextEachTime(t *testing.T) {
	recipient, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}

	plaintext := []byte("same plaintext")
	domain := DomainAgent

	ct1, err := ECIESEncrypt(recipient.PublicKey[:], plaintext, domain)
	if err != nil {
		t.Fatalf("first ECIESEncrypt: %v", err)
	}

	ct2, err := ECIESEncrypt(recipient.PublicKey[:], plaintext, domain)
	if err != nil {
		t.Fatalf("second ECIESEncrypt: %v", err)
	}

	if bytes.Equal(ct1, ct2) {
		t.Error("two ECIES encryptions produced identical ciphertext")
	}

	// Both should decrypt to the same plaintext
	d1, _ := ECIESDecrypt(recipient.PrivateKey[:], ct1, domain)
	d2, _ := ECIESDecrypt(recipient.PrivateKey[:], ct2, domain)
	if !bytes.Equal(d1, d2) {
		t.Error("different ciphertexts decrypted to different plaintexts")
	}
}

func TestECIES_WrongPrivateKey(t *testing.T) {
	recipient, _ := GenerateX25519KeyPair()
	other, _ := GenerateX25519KeyPair()

	plaintext := []byte("secret")
	ciphertext, err := ECIESEncrypt(recipient.PublicKey[:], plaintext, DomainAgent)
	if err != nil {
		t.Fatalf("ECIESEncrypt: %v", err)
	}

	_, err = ECIESDecrypt(other.PrivateKey[:], ciphertext, DomainAgent)
	if err == nil {
		t.Error("expected error when decrypting with wrong private key")
	}
}

func TestECIES_WrongDomain(t *testing.T) {
	recipient, _ := GenerateX25519KeyPair()

	plaintext := []byte("secret")
	ciphertext, err := ECIESEncrypt(recipient.PublicKey[:], plaintext, DomainAgent)
	if err != nil {
		t.Fatalf("ECIESEncrypt: %v", err)
	}

	_, err = ECIESDecrypt(recipient.PrivateKey[:], ciphertext, DomainConnection)
	if err == nil {
		t.Error("expected error when decrypting with wrong domain")
	}
}

func TestECIES_EmptyPlaintext(t *testing.T) {
	recipient, _ := GenerateX25519KeyPair()

	ciphertext, err := ECIESEncrypt(recipient.PublicKey[:], []byte{}, DomainAgent)
	if err != nil {
		t.Fatalf("ECIESEncrypt empty: %v", err)
	}

	decrypted, err := ECIESDecrypt(recipient.PrivateKey[:], ciphertext, DomainAgent)
	if err != nil {
		t.Fatalf("ECIESDecrypt empty: %v", err)
	}

	if len(decrypted) != 0 {
		t.Errorf("expected empty plaintext, got %d bytes", len(decrypted))
	}
}

func TestECIES_LargePlaintext(t *testing.T) {
	recipient, _ := GenerateX25519KeyPair()

	// 1 MB plaintext
	plaintext := make([]byte, 1024*1024)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	ciphertext, err := ECIESEncrypt(recipient.PublicKey[:], plaintext, DomainAgent)
	if err != nil {
		t.Fatalf("ECIESEncrypt large: %v", err)
	}

	decrypted, err := ECIESDecrypt(recipient.PrivateKey[:], ciphertext, DomainAgent)
	if err != nil {
		t.Fatalf("ECIESDecrypt large: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Error("large plaintext round-trip failed")
	}
}

func TestECIES_TamperedCiphertext(t *testing.T) {
	recipient, _ := GenerateX25519KeyPair()

	ciphertext, err := ECIESEncrypt(recipient.PublicKey[:], []byte("secret"), DomainAgent)
	if err != nil {
		t.Fatalf("ECIESEncrypt: %v", err)
	}

	// Tamper with ciphertext portion (after ephemeral pubkey + nonce)
	tampered := make([]byte, len(ciphertext))
	copy(tampered, ciphertext)
	tampered[len(tampered)-1] ^= 0xff

	_, err = ECIESDecrypt(recipient.PrivateKey[:], tampered, DomainAgent)
	if err == nil {
		t.Error("expected error for tampered ciphertext")
	}
}

func TestECIES_TruncatedCiphertext(t *testing.T) {
	recipient, _ := GenerateX25519KeyPair()

	_, err := ECIESDecrypt(recipient.PrivateKey[:], []byte("too short"), DomainAgent)
	if err == nil {
		t.Error("expected error for truncated ciphertext")
	}
}

func TestECIES_InvalidKeyLength(t *testing.T) {
	_, err := ECIESEncrypt(make([]byte, 16), []byte("data"), DomainAgent)
	if err == nil {
		t.Error("expected error for short public key")
	}

	_, err = ECIESDecrypt(make([]byte, 16), make([]byte, 100), DomainAgent)
	if err == nil {
		t.Error("expected error for short private key")
	}
}
