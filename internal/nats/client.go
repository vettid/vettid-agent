// Package nats provides the NATS MessageSpace client for the VettID Agent Connector.
package nats

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/nats-io/nats.go"
	"github.com/rs/zerolog/log"

	"github.com/vettid/vettid-agent/internal/crypto"
)

type Client struct {
	conn         *nats.Conn
	connectionID string
	ownerGUID    string
	credsFile    string // Temp file for NATS credentials (cleaned up on close)
}

type ClientConfig struct {
	URL          string
	JWT          string // NATS JWT for authentication
	Seed         string // NATS seed for signing
	ConnectionID string
	OwnerGUID    string
	TLS          bool
}

func NewClient(cfg *ClientConfig) (*Client, error) {
	// Write JWT+seed to a temporary credentials file for nats.UserCredentials()
	credsContent := fmt.Sprintf(
		"-----BEGIN NATS USER JWT-----\n%s\n------END NATS USER JWT------\n\n-----BEGIN USER NKEY SEED-----\n%s\n------END USER NKEY SEED------",
		cfg.JWT, cfg.Seed,
	)

	tmpDir := os.TempDir()
	credsFile := filepath.Join(tmpDir, fmt.Sprintf("vettid-agent-%d.creds", os.Getpid()))
	if err := os.WriteFile(credsFile, []byte(credsContent), 0600); err != nil {
		return nil, fmt.Errorf("write temp credentials: %w", err)
	}

	opts := []nats.Option{
		nats.UserCredentials(credsFile),
		nats.Name("vettid-agent-connector"),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(2 * 1e9), // 2 seconds
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			if err != nil {
				log.Warn().Err(err).Msg("NATS disconnected")
			}
		}),
		nats.ReconnectHandler(func(_ *nats.Conn) {
			log.Info().Msg("NATS reconnected")
		}),
	}

	// SECURITY: Enable TLS for NATS connection when configured
	if cfg.TLS {
		opts = append(opts, nats.Secure())
		log.Info().Msg("NATS TLS enabled")
	}

	conn, err := nats.Connect(cfg.URL, opts...)
	if err != nil {
		os.Remove(credsFile)
		return nil, fmt.Errorf("connect to NATS: %w", err)
	}

	return &Client{
		conn:         conn,
		connectionID: cfg.ConnectionID,
		ownerGUID:    cfg.OwnerGUID,
		credsFile:    credsFile,
	}, nil
}

// PublishToOwner publishes data to the agent's MessageSpace topic.
func (c *Client) PublishToOwner(data []byte) error {
	subject := fmt.Sprintf("MessageSpace.%s.forOwner.agent", c.ownerGUID)
	if err := c.conn.Publish(subject, data); err != nil {
		return fmt.Errorf("publish to owner: %w", err)
	}
	return nil
}

// PublishTo publishes data to a specific NATS subject.
func (c *Client) PublishTo(subject string, data []byte) error {
	if err := c.conn.Publish(subject, data); err != nil {
		return fmt.Errorf("publish to %s: %w", subject, err)
	}
	return nil
}

// SubscribeTo subscribes to a specific NATS subject.
func (c *Client) SubscribeTo(subject string, handler func(*nats.Msg)) (*nats.Subscription, error) {
	sub, err := c.conn.Subscribe(subject, handler)
	if err != nil {
		return nil, fmt.Errorf("subscribe to %s: %w", subject, err)
	}
	return sub, nil
}

func (c *Client) SubscribeResponses(handler func([]byte)) error {
	subject := fmt.Sprintf("MessageSpace.%s.forOwner.agent.%s", c.ownerGUID, c.connectionID)
	_, err := c.conn.Subscribe(subject, func(msg *nats.Msg) {
		handler(msg.Data)
	})
	if err != nil {
		return fmt.Errorf("subscribe to responses: %w", err)
	}
	return nil
}

// PublishSecretRequest encrypts a SecretRequest with the connection key and publishes it.
func (c *Client) PublishSecretRequest(secretReq *SecretRequest, connKey []byte, keyID string, seq uint64) error {
	plaintext, err := json.Marshal(secretReq)
	if err != nil {
		return fmt.Errorf("marshal secret request: %w", err)
	}
	defer crypto.ZeroBytes(plaintext)

	encrypted, err := crypto.Encrypt(connKey, plaintext, nil)
	if err != nil {
		return fmt.Errorf("encrypt secret request: %w", err)
	}

	envelope, err := EncodeEnvelope(MsgSecretRequest, keyID, encrypted, seq)
	if err != nil {
		return fmt.Errorf("encode envelope: %w", err)
	}

	return c.PublishToOwner(envelope)
}

// PublishActionRequest encrypts an ActionRequest with the connection key and publishes it.
func (c *Client) PublishActionRequest(actionReq *ActionRequest, connKey []byte, keyID string, seq uint64) error {
	plaintext, err := json.Marshal(actionReq)
	if err != nil {
		return fmt.Errorf("marshal action request: %w", err)
	}
	defer crypto.ZeroBytes(plaintext)

	encrypted, err := crypto.Encrypt(connKey, plaintext, nil)
	if err != nil {
		return fmt.Errorf("encrypt action request: %w", err)
	}

	envelope, err := EncodeEnvelope(MsgAgentActionRequest, keyID, encrypted, seq)
	if err != nil {
		return fmt.Errorf("encode envelope: %w", err)
	}

	return c.PublishToOwner(envelope)
}

// PublishCatalogRequest encrypts a CatalogRefreshRequest with the connection key and publishes it.
func (c *Client) PublishCatalogRequest(req *CatalogRefreshRequest, connKey []byte, keyID string, seq uint64) error {
	plaintext, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal catalog request: %w", err)
	}
	defer crypto.ZeroBytes(plaintext)

	encrypted, err := crypto.Encrypt(connKey, plaintext, nil)
	if err != nil {
		return fmt.Errorf("encrypt catalog request: %w", err)
	}

	envelope, err := EncodeEnvelope(MsgAgentCatalogRequest, keyID, encrypted, seq)
	if err != nil {
		return fmt.Errorf("encode envelope: %w", err)
	}

	return c.PublishToOwner(envelope)
}

// Conn returns the underlying NATS connection for drain/close operations.
func (c *Client) Conn() *nats.Conn {
	return c.conn
}

// OwnerGUID returns the owner's GUID.
func (c *Client) OwnerGUID() string {
	return c.ownerGUID
}

func (c *Client) Close() {
	if c.conn != nil {
		c.conn.Close()
	}
	// SECURITY: Clean up temporary credentials file
	if c.credsFile != "" {
		// Overwrite before removing
		if data, err := os.ReadFile(c.credsFile); err == nil {
			crypto.ZeroBytes(data)
			os.WriteFile(c.credsFile, data, 0600)
		}
		os.Remove(c.credsFile)
	}
}
