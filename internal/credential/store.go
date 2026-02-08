// Package credential manages encrypted credential storage (connection.enc)
// for the VettID Agent Connector.
//
// Credentials are encrypted at rest using:
//   passphrase + platform_key -> Argon2id -> 256-bit key -> ChaCha20-Poly1305
package credential

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/vettid/vettid-agent/internal/crypto"
)

const credentialFile = "connection.enc"

type ConnectionCredentials struct {
	ConnectionID      string `json:"connection_id"`
	ConnectionKey     []byte `json:"connection_key"`
	KeyID             string `json:"key_id"`
	AgentPrivateKey   []byte `json:"agent_private_key"`
	AgentPublicKey    []byte `json:"agent_public_key"`
	VaultPublicKey    []byte `json:"vault_public_key"`
	MessageSpaceToken string `json:"messagespace_token"`
	MessageSpaceURL   string `json:"messagespace_url"`
	OwnerName         string `json:"owner_name"`
	Scope             []string `json:"scope"`
	ApprovalMode      string `json:"approval_mode"`
}

type EncryptedStore struct {
	Salt       []byte `json:"salt"`
	Ciphertext []byte `json:"ciphertext"`
	Argon2Params struct {
		Time    uint32 `json:"time"`
		Memory  uint32 `json:"memory"`
		Threads uint8  `json:"threads"`
	} `json:"argon2_params"`
}

func Save(configDir string, creds *ConnectionCredentials, passphrase, platformKey []byte) error {
	plaintext, err := json.Marshal(creds)
	if err != nil {
		return fmt.Errorf("marshal credentials: %w", err)
	}

	salt, err := crypto.GenerateSalt()
	if err != nil {
		return err
	}

	params := crypto.DefaultArgon2Params()
	key := crypto.DeriveKey(passphrase, platformKey, salt, params)

	ciphertext, err := crypto.Encrypt(key, plaintext, nil)
	if err != nil {
		return fmt.Errorf("encrypt credentials: %w", err)
	}

	store := EncryptedStore{
		Salt:       salt,
		Ciphertext: ciphertext,
	}
	store.Argon2Params.Time = params.Time
	store.Argon2Params.Memory = params.Memory
	store.Argon2Params.Threads = params.Threads

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

func Load(configDir string, passphrase, platformKey []byte) (*ConnectionCredentials, error) {
	path := filepath.Join(configDir, credentialFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	var store EncryptedStore
	if err := json.Unmarshal(data, &store); err != nil {
		return nil, fmt.Errorf("parse store: %w", err)
	}

	params := &crypto.Argon2Params{
		Time:    store.Argon2Params.Time,
		Memory:  store.Argon2Params.Memory,
		Threads: store.Argon2Params.Threads,
	}
	key := crypto.DeriveKey(passphrase, platformKey, store.Salt, params)

	plaintext, err := crypto.Decrypt(key, store.Ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt credentials (wrong passphrase or different machine?): %w", err)
	}

	var creds ConnectionCredentials
	if err := json.Unmarshal(plaintext, &creds); err != nil {
		return nil, fmt.Errorf("parse credentials: %w", err)
	}

	return &creds, nil
}
