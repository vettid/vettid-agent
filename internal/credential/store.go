// Package credential manages encrypted credential storage (connection.enc)
// for the VettID Agent Connector.
//
// Credentials are encrypted at rest using:
//
//	passphrase + platform_key -> Argon2id -> 256-bit key -> XChaCha20-Poly1305
//
// The platform key is derived from machine attributes, binding credentials
// to the specific machine where they were created. 4-of-5 attribute tolerance
// allows decryption after minor hardware changes (e.g. NIC replacement).
package credential

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/rs/zerolog/log"

	"github.com/vettid/vettid-agent/internal/crypto"
	"github.com/vettid/vettid-agent/internal/fingerprint"
)

const (
	credentialFile = "connection.enc"
	storeVersion   = 1
)

// ConnectionCredentials holds all sensitive material for a vault connection.
type ConnectionCredentials struct {
	ConnectionID    string   `json:"connection_id"`
	ConnectionKey   []byte   `json:"connection_key"`
	KeyID           string   `json:"key_id"`
	AgentPrivateKey []byte   `json:"agent_private_key"`
	AgentPublicKey  []byte   `json:"agent_public_key"`
	VaultPublicKey  []byte   `json:"vault_public_key"`
	JWT             string   `json:"jwt"`              // NATS JWT for authentication
	Seed            string   `json:"seed"`             // NATS seed for signing
	MessageSpaceURL string   `json:"messagespace_url"` // NATS server URI
	OwnerGUID       string   `json:"owner_guid"`
	OwnerName       string   `json:"owner_name"`
	Scope           []string `json:"scope"`
	ApprovalMode    string   `json:"approval_mode"`
}

// Zero wipes all sensitive byte fields in the credentials.
func (c *ConnectionCredentials) Zero() {
	crypto.ZeroBytes(c.ConnectionKey)
	crypto.ZeroBytes(c.AgentPrivateKey)
	crypto.ZeroBytes(c.AgentPublicKey)
	crypto.ZeroBytes(c.VaultPublicKey)
}

// EncryptedStore is the on-disk format for connection.enc.
type EncryptedStore struct {
	Version      int              `json:"version"`
	Salt         []byte           `json:"salt"`
	Ciphertext   []byte           `json:"ciphertext"`
	Argon2Params crypto.Argon2Params `json:"argon2_params"`
}

// Save encrypts credentials and writes them to connection.enc in configDir.
// The encryption key is derived from passphrase + platformKey via Argon2id.
//
// SECURITY (#60): refuses to seal credentials under a weak passphrase.
// See ValidatePassphraseStrength for the rules. Existing weak-pass
// installs can keep loading via Load (this gate only applies to
// Save) — the next rotation will require a stronger one.
func Save(configDir string, creds *ConnectionCredentials, passphrase, platformKey []byte) error {
	if err := ValidatePassphraseStrength(passphrase); err != nil {
		return err
	}
	plaintext, err := json.Marshal(creds)
	if err != nil {
		return fmt.Errorf("marshal credentials: %w", err)
	}
	defer crypto.ZeroBytes(plaintext)

	salt, err := crypto.GenerateSalt()
	if err != nil {
		return err
	}

	params := crypto.DefaultArgon2Params()
	key := crypto.DeriveKey(passphrase, platformKey, salt, params)
	defer crypto.ZeroBytes(key)

	ciphertext, err := crypto.Encrypt(key, plaintext, nil)
	if err != nil {
		return fmt.Errorf("encrypt credentials: %w", err)
	}

	store := EncryptedStore{
		Version:      storeVersion,
		Salt:         salt,
		Ciphertext:   ciphertext,
		Argon2Params: *params,
	}

	data, err := json.Marshal(store)
	if err != nil {
		return fmt.Errorf("marshal store: %w", err)
	}

	path := filepath.Join(configDir, credentialFile)
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}

	return nil
}

// Load reads and decrypts credentials from connection.enc in configDir.
// Uses a single platform key (no tolerance — caller should use LoadWithTolerance
// for machine-fingerprint-based keys).
func Load(configDir string, passphrase, platformKey []byte) (*ConnectionCredentials, error) {
	store, err := readStore(configDir)
	if err != nil {
		return nil, err
	}

	return decryptStore(store, passphrase, platformKey)
}

// LoadWithTolerance attempts to decrypt credentials with the full machine fingerprint first,
// then tries all 4-of-5 attribute combinations if the full fingerprint fails.
//
// If a 4-of-5 combo succeeds, the credentials are re-encrypted with the current full
// fingerprint to "heal" the store after a minor hardware change.
//
// Returns the credentials and whether re-encryption occurred.
func LoadWithTolerance(configDir string, passphrase string, platformKeyFile string) (*ConnectionCredentials, bool, error) {
	store, err := readStore(configDir)
	if err != nil {
		return nil, false, err
	}

	// If using a platform key file, no tolerance needed
	if platformKeyFile != "" {
		pk, err := fingerprint.DerivePlatformKey(platformKeyFile)
		if err != nil {
			return nil, false, err
		}
		creds, err := decryptStore(store, []byte(passphrase), pk)
		if err != nil {
			return nil, false, err
		}
		return creds, false, nil
	}

	// Collect current machine attributes
	attrs, err := fingerprint.CollectMachineAttributes()
	if err != nil {
		return nil, false, fmt.Errorf("collect machine attributes: %w", err)
	}

	// Try full fingerprint first
	fullKey := fingerprint.ComputeMachineFingerprint(attrs)
	creds, err := decryptStore(store, []byte(passphrase), fullKey)
	if err == nil {
		return creds, false, nil
	}

	// Full fingerprint failed — try 4-of-5 combinations
	log.Warn().Msg("Full fingerprint failed, trying 4-of-5 attribute combinations...")

	combos := fingerprint.FourOfFiveCombinations(attrs)
	for i, combo := range combos {
		comboKey := fingerprint.ComputeMachineFingerprint(combo)
		creds, err = decryptStore(store, []byte(passphrase), comboKey)
		if err == nil {
			log.Warn().
				Int("combo", i).
				Msg("4-of-5 fingerprint match — re-encrypting with current full fingerprint")

			// Re-encrypt with the current full fingerprint
			if reErr := Save(configDir, creds, []byte(passphrase), fullKey); reErr != nil {
				log.Error().Err(reErr).Msg("Failed to re-encrypt credentials with updated fingerprint")
				// Return creds anyway — we decrypted successfully
			}
			return creds, true, nil
		}
	}

	return nil, false, fmt.Errorf("decrypt credentials: wrong passphrase or different machine (all fingerprint combinations failed)")
}

// Exists returns true if a credential file exists in configDir.
func Exists(configDir string) bool {
	path := filepath.Join(configDir, credentialFile)
	_, err := os.Stat(path)
	return err == nil
}

// Delete removes the credential file from configDir.
func Delete(configDir string) error {
	path := filepath.Join(configDir, credentialFile)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove %s: %w", path, err)
	}
	return nil
}

func readStore(configDir string) (*EncryptedStore, error) {
	path := filepath.Join(configDir, credentialFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	var store EncryptedStore
	if err := json.Unmarshal(data, &store); err != nil {
		return nil, fmt.Errorf("parse store: %w", err)
	}

	return &store, nil
}

func decryptStore(store *EncryptedStore, passphrase, platformKey []byte) (*ConnectionCredentials, error) {
	// SECURITY (#55): refuse to derive a key under tampered-down
	// Argon2 parameters. The stored argon2_params field rides in
	// the cleartext envelope so an attacker with file access can
	// flip Time to 1 to make offline brute-force feasible — even
	// though they can't decrypt the ciphertext directly, a
	// weakened param-set lets them precompute against the
	// captured salt + ciphertext. Bound-check before deriving.
	if err := crypto.ValidateArgon2Params(store.Argon2Params); err != nil {
		return nil, fmt.Errorf("untrusted argon2 params on disk: %w", err)
	}
	params := &store.Argon2Params
	key := crypto.DeriveKey(passphrase, platformKey, store.Salt, params)
	defer crypto.ZeroBytes(key)

	plaintext, err := crypto.Decrypt(key, store.Ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	defer crypto.ZeroBytes(plaintext)

	var creds ConnectionCredentials
	if err := json.Unmarshal(plaintext, &creds); err != nil {
		return nil, fmt.Errorf("parse credentials: %w", err)
	}

	return &creds, nil
}
