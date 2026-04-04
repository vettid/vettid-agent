// Package registration implements the agent registration flow
// using the same P2P connection pattern as mobile apps and desktop.
package registration

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// InvitationPayload matches the mobile peer connection invitation format.
// Returned by resolving an invite code via the standard broker endpoint.
type InvitationPayload struct {
	NATSEndpoint string `json:"nats_endpoint"` // NATS server URI
	JWT          string `json:"jwt"`           // NATS JWT for authentication
	Seed         string `json:"seed"`          // NATS seed for signing
	ConnectionID string `json:"connection_id"` // Assigned by vault
	OwnerSpace   string `json:"owner_space"`   // Vault owner identifier
	MessageSpace string `json:"message_space"` // MessageSpace topic
	ExpiresAt    string `json:"expires_at"`    // Invitation expiry (ISO 8601)
	Label        string `json:"label"`         // Inviter display name
}

const defaultBrokerBase = "https://vett.id/"

// ResolveInviteCode resolves an invite code via the standard VettID broker.
// Uses the same endpoint as mobile apps and the desktop client.
func ResolveInviteCode(code string) (*InvitationPayload, error) {
	url := code
	if !strings.HasPrefix(url, "https://") && !strings.HasPrefix(url, "http://") {
		url = defaultBrokerBase + strings.TrimPrefix(code, "/")
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("resolve invite code: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
		// Success
	case http.StatusNotFound:
		return nil, fmt.Errorf("invite code expired or already used")
	case http.StatusTooManyRequests:
		return nil, fmt.Errorf("rate limited — try again shortly")
	default:
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	var payload InvitationPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("parse invitation payload: %w", err)
	}

	if err := validateInvitation(&payload); err != nil {
		return nil, err
	}

	// Check expiry
	if payload.ExpiresAt != "" {
		if expires, err := time.Parse(time.RFC3339, payload.ExpiresAt); err == nil {
			if time.Now().After(expires) {
				return nil, fmt.Errorf("invitation has expired")
			}
		}
	}

	return &payload, nil
}

func validateInvitation(p *InvitationPayload) error {
	checks := map[string]string{
		"nats_endpoint": p.NATSEndpoint,
		"jwt":           p.JWT,
		"seed":          p.Seed,
		"connection_id": p.ConnectionID,
		"owner_space":   p.OwnerSpace,
		"message_space": p.MessageSpace,
	}
	for name, value := range checks {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("invitation field '%s' is empty", name)
		}
	}
	return nil
}
