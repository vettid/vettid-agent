package leash

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// MintResponse mirrors the demo mint Lambda's response body. See
// vettid-dev/cdk/lambda/handlers/public/demoMintLeash.ts.
type MintResponse struct {
	Leash     string `json:"leash"`
	JTI       string `json:"jti"`
	Kid       string `json:"kid"`
	IssuedAt  int64  `json:"issued_at"`
	ExpiresAt int64  `json:"expires_at"`
}

// MintError is the shape the demo mint Lambda returns on 4xx — surfaced
// here so the CLI can render the scope-allowlist mismatches readably
// rather than treating them as generic HTTP errors.
type MintError struct {
	Error string `json:"error"`
}

// PostMint requests a Demo Alice LEASH from the public demo endpoint
// (`/v1/public/leash/demo/mint`). Scope tokens must come from the demo
// allowlist (profile.email:read, profile.phone:read, …); the endpoint
// rejects anything else with 400.
//
// The agent's `key` provides the pubkey that's embedded in the LEASH's
// `vettid:agent_pubkey` claim — the verifier later checks PoP against
// the same key when `demo validate` posts the verify envelope.
//
// This is the parallel to PostVerify: both target the public demo
// surface, no user-vault round-trip required. To mint a *real-user*
// LEASH, the flow goes app → forVault.leash.attest in the user's
// vault (see vettid-dev/enclave/vault-manager/leash_handler.go), which
// is owner-driven and outside the agent's privilege scope.
func PostMint(apiURL string, key *AgentKey, scope []string, durationSecs int, timeout time.Duration) (*MintResponse, error) {
	if len(scope) == 0 {
		return nil, fmt.Errorf("at least one scope token is required")
	}
	body, err := json.Marshal(map[string]any{
		"scope":         scope,
		"agent_pubkey":  key.PublicB64,
		"duration_secs": durationSecs,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal mint request: %w", err)
	}

	endpoint := apiURL + "/v1/public/leash/demo/mint"
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("POST %s: %w", endpoint, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode >= 500 {
		return nil, fmt.Errorf("mint endpoint returned %d: %s", resp.StatusCode, string(respBody))
	}
	if resp.StatusCode >= 400 {
		var me MintError
		if json.Unmarshal(respBody, &me) == nil && me.Error != "" {
			return nil, fmt.Errorf("mint rejected: %s", me.Error)
		}
		return nil, fmt.Errorf("mint endpoint returned %d: %s", resp.StatusCode, string(respBody))
	}

	var parsed MintResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return nil, fmt.Errorf("parse mint response: %w (body: %s)", err, string(respBody))
	}
	return &parsed, nil
}
