// Package nats provides the NATS MessageSpace client for the VettID Agent Connector.
package nats

import (
	"encoding/json"
	"fmt"

	"github.com/nats-io/nats.go"
	"github.com/rs/zerolog/log"

	"github.com/vettid/vettid-agent/internal/crypto"
)

type Client struct {
	conn         *nats.Conn
	connectionID string
	ownerGUID    string
}

type ClientConfig struct {
	URL          string
	Token        string
	ConnectionID string
	OwnerGUID    string
	TLS          bool
}

func NewClient(cfg *ClientConfig) (*Client, error) {
	opts := []nats.Option{
		nats.Token(cfg.Token),
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

	conn, err := nats.Connect(cfg.URL, opts...)
	if err != nil {
		return nil, fmt.Errorf("connect to NATS: %w", err)
	}

	return &Client{
		conn:         conn,
		connectionID: cfg.ConnectionID,
		ownerGUID:    cfg.OwnerGUID,
	}, nil
}

func (c *Client) PublishToOwner(data []byte) error {
	subject := fmt.Sprintf("MessageSpace.%s.forOwner.agent", c.ownerGUID)
	if err := c.conn.Publish(subject, data); err != nil {
		return fmt.Errorf("publish to owner: %w", err)
	}
	return nil
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

// PublishRegistration ECIES-encrypts a ConnectionRequest with the vault's public key
// and publishes it to the owner's forOwner topic.
func (c *Client) PublishRegistration(connReq *ConnectionRequest, vaultPubKey []byte) error {
	plaintext, err := json.Marshal(connReq)
	if err != nil {
		return fmt.Errorf("marshal connection request: %w", err)
	}
	defer crypto.ZeroBytes(plaintext)

	// SECURITY: ECIES-encrypt with vault's public key so only the enclave can read it
	encrypted, err := crypto.ECIESEncrypt(vaultPubKey, plaintext, crypto.DomainAgent)
	if err != nil {
		return fmt.Errorf("ECIES encrypt registration: %w", err)
	}

	envelope, err := EncodeEnvelope(MsgAgentConnectionRequest, "", encrypted, 0)
	if err != nil {
		return fmt.Errorf("encode envelope: %w", err)
	}

	return c.PublishToOwner(envelope)
}

// SubscribeRegistration subscribes to the invitation-specific response topic
// and calls handler for each received envelope.
func (c *Client) SubscribeRegistration(invitationID string, handler func(*Envelope)) (*nats.Subscription, error) {
	subject := fmt.Sprintf("MessageSpace.%s.forOwner.agent.invitation.%s", c.ownerGUID, invitationID)
	sub, err := c.conn.Subscribe(subject, func(msg *nats.Msg) {
		env, err := DecodeEnvelope(msg.Data)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to decode registration response envelope")
			return
		}
		handler(env)
	})
	if err != nil {
		return nil, fmt.Errorf("subscribe to invitation %s: %w", invitationID, err)
	}
	return sub, nil
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

func (c *Client) Close() {
	if c.conn != nil {
		c.conn.Close()
	}
}
