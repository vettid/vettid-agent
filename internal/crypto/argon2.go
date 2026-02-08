package crypto

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/argon2"
)

const (
	Argon2SaltSize = 16
	Argon2KeySize  = 32
)

type Argon2Params struct {
	Time    uint32
	Memory  uint32 // in KB
	Threads uint8
}

func DefaultArgon2Params() *Argon2Params {
	return &Argon2Params{
		Time:    3,
		Memory:  65536, // 64 MB
		Threads: 4,
	}
}

func DeriveKey(passphrase, platformKey, salt []byte, params *Argon2Params) []byte {
	// Combine passphrase and platform key as input
	input := make([]byte, 0, len(passphrase)+len(platformKey))
	input = append(input, passphrase...)
	input = append(input, platformKey...)

	return argon2.IDKey(input, salt, params.Time, params.Memory, params.Threads, Argon2KeySize)
}

func GenerateSalt() ([]byte, error) {
	salt := make([]byte, Argon2SaltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}
	return salt, nil
}
