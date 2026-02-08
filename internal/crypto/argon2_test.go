package crypto

import (
	"bytes"
	"testing"
)

func TestDeriveKey_Deterministic(t *testing.T) {
	passphrase := []byte("my-passphrase")
	platformKey := []byte("platform-key-32-bytes-long!!!!!")
	salt := []byte("sixteen-byte-sa!")
	params := DefaultArgon2Params()

	key1 := DeriveKey(passphrase, platformKey, salt, params)
	key2 := DeriveKey(passphrase, platformKey, salt, params)

	if !bytes.Equal(key1, key2) {
		t.Error("same inputs should produce same key")
	}

	if len(key1) != Argon2KeySize {
		t.Errorf("key length = %d, want %d", len(key1), Argon2KeySize)
	}
}

func TestDeriveKey_DifferentPassphrase(t *testing.T) {
	platformKey := []byte("platform-key-32-bytes-long!!!!!")
	salt := []byte("sixteen-byte-sa!")
	params := DefaultArgon2Params()

	key1 := DeriveKey([]byte("passphrase-A"), platformKey, salt, params)
	key2 := DeriveKey([]byte("passphrase-B"), platformKey, salt, params)

	if bytes.Equal(key1, key2) {
		t.Error("different passphrases should produce different keys")
	}
}

func TestDeriveKey_DifferentPlatformKey(t *testing.T) {
	passphrase := []byte("my-passphrase")
	salt := []byte("sixteen-byte-sa!")
	params := DefaultArgon2Params()

	key1 := DeriveKey(passphrase, []byte("platform-key-machine-A-32-bytes"), salt, params)
	key2 := DeriveKey(passphrase, []byte("platform-key-machine-B-32-bytes"), salt, params)

	if bytes.Equal(key1, key2) {
		t.Error("different platform keys should produce different keys")
	}
}

func TestDeriveKey_DifferentSalt(t *testing.T) {
	passphrase := []byte("my-passphrase")
	platformKey := []byte("platform-key-32-bytes-long!!!!!")
	params := DefaultArgon2Params()

	key1 := DeriveKey(passphrase, platformKey, []byte("salt-aaaaaaaaaa!"), params)
	key2 := DeriveKey(passphrase, platformKey, []byte("salt-bbbbbbbbbb!"), params)

	if bytes.Equal(key1, key2) {
		t.Error("different salts should produce different keys")
	}
}

func TestDeriveKey_NilParams(t *testing.T) {
	// Should use defaults when params is nil
	key := DeriveKey([]byte("pass"), []byte("platform"), []byte("salt-16-bytes!!"), nil)
	if len(key) != Argon2KeySize {
		t.Errorf("key length = %d, want %d", len(key), Argon2KeySize)
	}
}

func TestGenerateSalt(t *testing.T) {
	salt1, err := GenerateSalt()
	if err != nil {
		t.Fatalf("first GenerateSalt: %v", err)
	}

	salt2, err := GenerateSalt()
	if err != nil {
		t.Fatalf("second GenerateSalt: %v", err)
	}

	if len(salt1) != Argon2SaltSize {
		t.Errorf("salt length = %d, want %d", len(salt1), Argon2SaltSize)
	}

	if bytes.Equal(salt1, salt2) {
		t.Error("two generated salts are identical")
	}
}

func TestDefaultArgon2Params(t *testing.T) {
	params := DefaultArgon2Params()

	if params.Time != 3 {
		t.Errorf("Time = %d, want 3", params.Time)
	}
	if params.Memory != 65536 {
		t.Errorf("Memory = %d, want 65536", params.Memory)
	}
	if params.Threads != 4 {
		t.Errorf("Threads = %d, want 4", params.Threads)
	}
}
