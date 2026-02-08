// Package nats provides the NATS MessageSpace client for the VettID Agent Connector.
package nats

import (
	"fmt"

	"github.com/nats-io/nats.go"
	"github.com/rs/zerolog/log"
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
	subject := fmt.Sprintf("MessageSpace.%s.forOwner", c.ownerGUID)
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

func (c *Client) Close() {
	if c.conn != nil {
		c.conn.Close()
	}
}
