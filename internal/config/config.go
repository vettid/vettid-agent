// Package config handles TOML configuration loading for the VettID Agent Connector.
package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

type Config struct {
	API       APIConfig       `toml:"api"`
	WebSocket WebSocketConfig `toml:"websocket"`
	NATS      NATSConfig      `toml:"nats"`
	Security  SecurityConfig  `toml:"security"`
	Logging   LoggingConfig   `toml:"logging"`
}

type APIConfig struct {
	Listen      string `toml:"listen"`
	MTLSEnabled bool   `toml:"mtls_enabled"`
	MTLSCert    string `toml:"mtls_cert"`
	MTLSKey     string `toml:"mtls_key"`
}

type WebSocketConfig struct {
	Enabled        bool   `toml:"enabled"`
	Listen         string `toml:"listen"`
	AllowedOrigins string `toml:"allowed_origins"`
}

type NATSConfig struct {
	MessageSpaceURL       string `toml:"messagespace_url"`
	TLSEnabled            bool   `toml:"tls_enabled"`
	MaxReconnectAttempts  int    `toml:"max_reconnect_attempts"`
	ReconnectWaitSeconds  int    `toml:"reconnect_wait_seconds"`
	MaxReconnectWaitSecs  int    `toml:"max_reconnect_wait_seconds"`
}

type SecurityConfig struct {
	Argon2Time             int `toml:"argon2_time"`
	Argon2MemoryKB         int `toml:"argon2_memory_kb"`
	Argon2Threads          int `toml:"argon2_threads"`
	RequestTimeoutSeconds  int `toml:"request_timeout_seconds"`
	ApprovalTimeoutSeconds int `toml:"approval_timeout_seconds"`
}

type LoggingConfig struct {
	Level         string `toml:"level"`
	EncryptLogs   bool   `toml:"encrypt_logs"`
	MaxLogSizeMB  int    `toml:"max_log_size_mb"`
	MaxLogFiles   int    `toml:"max_log_files"`
}

func DefaultConfig() *Config {
	home, _ := os.UserHomeDir()
	socketPath := filepath.Join(home, ".vettid-agent", "agent.sock")

	return &Config{
		API: APIConfig{
			Listen: "unix://" + socketPath,
		},
		WebSocket: WebSocketConfig{
			Enabled:        true,
			Listen:         "127.0.0.1:7443",
			AllowedOrigins: "localhost,127.0.0.1",
		},
		NATS: NATSConfig{
			TLSEnabled:           true,
			MaxReconnectAttempts: -1,
			ReconnectWaitSeconds: 2,
			MaxReconnectWaitSecs: 60,
		},
		Security: SecurityConfig{
			Argon2Time:             3,
			Argon2MemoryKB:         65536,
			Argon2Threads:          4,
			RequestTimeoutSeconds:  30,
			ApprovalTimeoutSeconds: 300,
		},
		Logging: LoggingConfig{
			Level:        "info",
			EncryptLogs:  true,
			MaxLogSizeMB: 50,
			MaxLogFiles:  5,
		},
	}
}

func Load(configDir string) (*Config, error) {
	cfg := DefaultConfig()

	configPath := filepath.Join(configDir, "config.toml")
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return cfg, nil
	}

	if _, err := toml.DecodeFile(configPath, cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", configPath, err)
	}

	return cfg, nil
}
