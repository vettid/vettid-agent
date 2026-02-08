// Package registration implements the agent registration flow
// including shortlink resolution and the registration state machine.
package registration

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type ShortlinkPayload struct {
	MessageSpaceURI string `json:"messagespace_uri"`
	InviteToken     string `json:"invite_token"`
	InvitationID    string `json:"invitation_id"`
}

func ResolveShortlink(shortlink string) (*ShortlinkPayload, error) {
	// Normalize shortlink: add https:// if not present
	url := shortlink
	if !strings.HasPrefix(url, "https://") && !strings.HasPrefix(url, "http://") {
		url = "https://" + url
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("resolve shortlink: %w", err)
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
		return nil, fmt.Errorf("shortlink expired or already used")
	case http.StatusTooManyRequests:
		return nil, fmt.Errorf("rate limited — try again later")
	default:
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	var payload ShortlinkPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("parse shortlink payload: %w", err)
	}

	if payload.MessageSpaceURI == "" || payload.InviteToken == "" {
		return nil, fmt.Errorf("shortlink payload missing required fields")
	}

	return &payload, nil
}
