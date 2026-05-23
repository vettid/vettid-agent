package leash

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// VerifyResponse mirrors the verifier Lambda's response body. Fields
// optional / nullable on rejection paths. See
// vettid-dev/cdk/lambda/handlers/public/verifyLeash.ts.
type VerifyResponse struct {
	Verified              bool          `json:"verified"`
	RejectionReason       *string       `json:"rejection_reason"`
	Checks                []VerifyCheck `json:"checks"`
	Issuer                *string       `json:"issuer"`
	Subject               *string       `json:"subject"`
	ScopesGranted         []string      `json:"scopes_granted"`
	ScopeMatched          *string       `json:"scope_matched"`
	TimeRemainingSecs     *int64        `json:"time_remaining_secs"`
	GrantVersion          *int          `json:"grant_version"`
	ProfileVersionAtGrant *int          `json:"profile_version_at_grant"`
	Evidence              struct {
		JwtPubkeyKid    *string `json:"jwt_pubkey_kid"`
		AgentPubkeyUsed *string `json:"agent_pubkey_used"`
	} `json:"evidence"`
	CheckedAt int64 `json:"checked_at"`
}

// VerifyCheck is one step of the verification chain — name (e.g. "jwt-sig"),
// pass/fail, and a one-line explanation. The validator returns these in
// the order they were performed.
type VerifyCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"` // "pass" | "fail"
	Detail string `json:"detail"`
}

// PostVerify builds the verifier envelope, signs it with `key`, posts
// to `{validatorURL}/v1/public/leash/verify`, and returns the parsed
// response. Network or 5xx errors propagate as Go errors; legitimate
// verification rejections come back with Verified=false (still a
// successful HTTP exchange — the demo wants to render the failure
// chain, not throw).
func PostVerify(validatorURL string, key *AgentKey, leash string, action string, timeout time.Duration) (*VerifyResponse, error) {
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	timestamp := time.Now().Unix()
	request := map[string]any{"action": action}

	agentSig, err := SignEnvelope(key, leash, request, nonce, timestamp)
	if err != nil {
		return nil, fmt.Errorf("sign envelope: %w", err)
	}

	body, err := json.Marshal(map[string]any{
		"leash":     leash,
		"request":   request,
		"nonce":     nonce,
		"timestamp": timestamp,
		"agent_sig": agentSig,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal envelope: %w", err)
	}

	endpoint := validatorURL + "/v1/public/leash/verify"
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
		return nil, fmt.Errorf("validator returned %d: %s", resp.StatusCode, string(respBody))
	}
	if resp.StatusCode == 400 {
		return nil, fmt.Errorf("validator rejected envelope as malformed (400): %s", string(respBody))
	}

	var parsed VerifyResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return nil, fmt.Errorf("parse verifier response: %w (body: %s)", err, string(respBody))
	}
	return &parsed, nil
}
