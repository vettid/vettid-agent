package crypto

import (
	"fmt"

	"golang.org/x/crypto/argon2"
)

const (
	Argon2SaltSize = 16
	Argon2KeySize  = 32
)

// Argon2Params holds the Argon2id parameters for key derivation.
type Argon2Params struct {
	Time    uint32 `json:"time"`
	Memory  uint32 `json:"memory"`  // in KB
	Threads uint8  `json:"threads"`
}

// DefaultArgon2Params returns the default Argon2id parameters.
// Time=3, Memory=64MB, Threads=4 — matching the design doc defaults.
func DefaultArgon2Params() *Argon2Params {
	return &Argon2Params{
		Time:    3,
		Memory:  65536, // 64 MB
		Threads: 4,
	}
}

// SECURITY (#55): minimum Argon2id parameters accepted by
// ValidateArgon2Params. An attacker who tampers with the cleartext
// argon2_params field in the EncryptedStore can't change the
// ciphertext (AEAD-tag protects it) but they CAN lower the params
// to make offline brute-force against the passphrase faster. These
// bounds prevent downgrade — they match the defaults above, so any
// store that was written by an honest agent will pass.
const (
	MinArgon2Time    uint32 = 3
	MinArgon2Memory  uint32 = 65536 // 64 MiB
	MinArgon2Threads uint8  = 1
)

// ValidateArgon2Params rejects parameter sets below the minimum
// security bound. Callers should run this on params loaded from
// untrusted sources before passing them to DeriveKey.
func ValidateArgon2Params(p Argon2Params) error {
	if p.Time < MinArgon2Time {
		return fmt.Errorf("argon2 time=%d below minimum %d (downgrade refused)", p.Time, MinArgon2Time)
	}
	if p.Memory < MinArgon2Memory {
		return fmt.Errorf("argon2 memory=%dKB below minimum %dKB (downgrade refused)", p.Memory, MinArgon2Memory)
	}
	if p.Threads < MinArgon2Threads {
		return fmt.Errorf("argon2 threads=%d below minimum %d", p.Threads, MinArgon2Threads)
	}
	return nil
}

// DeriveKey derives an encryption key from a passphrase and platform key using Argon2id.
//
// The passphrase and platform key are concatenated as input to Argon2id.
// This binds the derived key to both the user's passphrase and the specific machine,
// so credentials are undecryptable if either factor is missing.
//
// SECURITY: The caller should zero the returned key after use.
func DeriveKey(passphrase, platformKey, salt []byte, params *Argon2Params) []byte {
	if params == nil {
		params = DefaultArgon2Params()
	}

	// Combine passphrase and platform key as input
	input := make([]byte, 0, len(passphrase)+len(platformKey))
	input = append(input, passphrase...)
	input = append(input, platformKey...)
	defer ZeroBytes(input)

	return argon2.IDKey(input, salt, params.Time, params.Memory, params.Threads, Argon2KeySize)
}

// GenerateSalt generates a random salt for Argon2id.
func GenerateSalt() ([]byte, error) {
	salt, err := GenerateRandomBytes(Argon2SaltSize)
	if err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}
	return salt, nil
}
