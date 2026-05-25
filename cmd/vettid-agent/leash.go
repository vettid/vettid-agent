package main

// leash.go — subcommands for using REAL-USER LEASHes (issued by a
// vettid user from their app, as opposed to the public Demo Alice
// LEASH the `demo` subcommand mints).
//
//   vettid-agent leash pubkey                 — print this agent's
//       Ed25519 pubkey for use when minting a LEASH on the owner's
//       app. The owner needs to paste / scan this pubkey into the
//       mint dialog so the LEASH's vettid:agent_pubkey claim is
//       bound to this agent's signing key. Without that binding,
//       the verification envelope's PoP signature won't validate
//       against what the LEASH carries.
//
//   vettid-agent leash verify --leash <jwt> --action <scope-token>
//       — verifies a real-user LEASH against the public validator at
//       api.vettid.dev/v1/public/leash/verify (override with
//       --validator). Same envelope shape as `demo validate`; renamed
//       so the operator can tell which flow they're running.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/vettid/vettid-agent/internal/leash"
)

func newLeashCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "leash",
		Short: "Real-user LEASH helpers (pubkey, verify)",
		Long: `Subcommands for working with LEASHes issued by a real VettID user.

End-to-end flow:
  1. vettid-agent leash pubkey
       → prints this agent's Ed25519 pubkey (base64url).
  2. Owner mints a LEASH in their VettID app (Agent Details → Mint
     LEASH), pasting the pubkey from step 1.
  3. vettid-agent leash verify --leash <jwt> --action <scope-token>
       → posts a signed verification envelope to the validator and
       renders the result.

For Demo Alice mint+verify against the public demo endpoints, use
vettid-agent demo {attest,validate}.`,
	}
	cmd.AddCommand(newLeashPubkeyCmd())
	cmd.AddCommand(newLeashVerifyCmd())
	cmd.AddCommand(newLeashMintCmd())
	return cmd
}

// daemonClient hits the local daemon API over its Unix socket. The
// socket lives at {configDir}/agent.sock by default (matches the
// daemon's APIConfig.Listen default in internal/config/config.go).
type daemonClient struct {
	http   *http.Client
	socket string
}

func newDaemonClient(configDir string) *daemonClient {
	socket := filepath.Join(configDir, "agent.sock")
	return &daemonClient{
		socket: socket,
		http: &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "unix", socket)
				},
			},
		},
	}
}

func (c *daemonClient) postJSON(ctx context.Context, path string, body any, timeout time.Duration) ([]byte, int, error) {
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, 0, fmt.Errorf("marshal body: %w", err)
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, "http://unix"+path, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, 0, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("daemon call: %w (is `vettid-agent start` running? socket: %s)", err, c.socket)
	}
	defer resp.Body.Close()
	respBytes, _ := io.ReadAll(resp.Body)
	return respBytes, resp.StatusCode, nil
}

func newLeashMintCmd() *cobra.Command {
	var (
		scopes       []string
		durationSecs int
		reason       string
		timeoutSecs  int
		jsonOut      bool
	)
	cmd := &cobra.Command{
		Use:   "mint",
		Short: "Ask the owner to mint a LEASH bound to this agent's pubkey",
		Long: `Drives the agent-initiated LEASH mint flow. Publishes a leash_mint_request
to the vault via the running daemon's NATS session, blocks until the
owner approves on their phone (or the timeout fires), and prints the
JWT.

Requires the daemon (vettid-agent start) to be running — the CLI is a
thin wrapper around POST /v1/leash/mint on the daemon's local socket
({configDir}/agent.sock).

--scope is repeatable; each token must conform to the LEASH grammar
(resource:action[:qualifier], see vettid-dev/docs/LEASH-TOKEN-FORMAT.md).

End-to-end example:

  vettid-agent leash mint \
      --scope profile.email:read \
      --duration 1800 \
      --reason "fetch user email for triage"
  ▸ mint request sent; waiting for owner approval on phone
  ✓ MINTED
    leash:     eyJhbGciOi...
    jti:       leash-...
    expires:   2026-05-25T18:30:00Z`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(scopes) == 0 {
				return fmt.Errorf("--scope is required (repeat for multiple)")
			}
			for i, s := range scopes {
				scopes[i] = strings.TrimSpace(s)
				if scopes[i] == "" {
					return fmt.Errorf("--scope token cannot be empty")
				}
			}

			configDir, err := getConfigDir(cmd)
			if err != nil {
				return err
			}

			client := newDaemonClient(configDir)
			body := map[string]any{
				"scope":         scopes,
				"duration_secs": durationSecs,
				"reason":        reason,
				"timeout_secs":  timeoutSecs,
			}

			// HTTP timeout = phone-approval timeout + 30s grace so the
			// daemon's own timeout fires before the HTTP client gives up.
			httpTimeout := time.Duration(timeoutSecs+30) * time.Second

			fmt.Println("▸ mint request sent; waiting for owner approval on phone")

			respBytes, status, err := client.postJSON(cmd.Context(), "/v1/leash/mint", body, httpTimeout)
			if err != nil {
				return err
			}

			if jsonOut {
				fmt.Println(string(respBytes))
				if status != http.StatusOK {
					return fmt.Errorf("daemon returned HTTP %d", status)
				}
				return nil
			}

			if status != http.StatusOK {
				// Daemon returned an error envelope {"error":"..."}.
				var e struct {
					Error     string `json:"error"`
					RequestID string `json:"request_id,omitempty"`
				}
				_ = json.Unmarshal(respBytes, &e)
				if e.Error == "" {
					e.Error = strings.TrimSpace(string(respBytes))
				}
				if status == http.StatusForbidden {
					fmt.Printf("✗ DENIED — %s\n", e.Error)
				} else {
					fmt.Printf("✗ FAILED (HTTP %d) — %s\n", status, e.Error)
				}
				return fmt.Errorf("mint did not complete")
			}

			var granted struct {
				RequestID string `json:"request_id"`
				Leash     string `json:"leash"`
				JTI       string `json:"jti"`
				Kid       string `json:"kid"`
				IssuedAt  int64  `json:"issued_at"`
				ExpiresAt int64  `json:"expires_at"`
			}
			if err := json.Unmarshal(respBytes, &granted); err != nil {
				return fmt.Errorf("parse daemon response: %w", err)
			}

			bar := strings.Repeat("─", 60)
			fmt.Println(bar)
			fmt.Println("  ✓ MINTED")
			fmt.Println(bar)
			fmt.Printf("  scope:        %s\n", strings.Join(scopes, ", "))
			fmt.Println()
			fmt.Println("  Issued LEASH (compact JWT):")
			fmt.Println()
			fmt.Println("    " + granted.Leash)
			fmt.Println()
			fmt.Println("  Detail:")
			printKV("jti", granted.JTI)
			printKV("kid", granted.Kid)
			if granted.IssuedAt > 0 {
				printKV("issued at", time.Unix(granted.IssuedAt, 0).UTC().Format(time.RFC3339))
			}
			if granted.ExpiresAt > 0 {
				printKV("expires at", time.Unix(granted.ExpiresAt, 0).UTC().Format(time.RFC3339))
				printKV("valid for", fmt.Sprintf("%ds", granted.ExpiresAt-granted.IssuedAt))
			}
			fmt.Println(bar)
			fmt.Println()
			fmt.Println("  Next: vettid-agent leash verify \\")
			fmt.Printf("          --leash %q \\\n", granted.Leash)
			if len(scopes) > 0 {
				fmt.Printf("          --action %s\n", scopes[0])
			}
			return nil
		},
	}
	cmd.Flags().StringSliceVar(&scopes, "scope", nil, "LEASH scope token (repeatable; e.g. profile.email:read)")
	cmd.Flags().IntVar(&durationSecs, "duration", 1800, "Requested LEASH duration in seconds (owner may shorten)")
	cmd.Flags().StringVar(&reason, "reason", "", "Optional human-readable reason shown to the owner on the approval screen")
	cmd.Flags().IntVar(&timeoutSecs, "timeout", 300, "How long to wait for the owner to approve, in seconds")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Print the granted/denied JSON envelope verbatim")
	return cmd
}

func newLeashPubkeyCmd() *cobra.Command {
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "pubkey",
		Short: "Print this agent's Ed25519 pubkey (for real-user LEASH minting)",
		Long: `The owner's vault binds a LEASH to a specific Ed25519 pubkey via the
vettid:agent_pubkey claim. The agent then proves possession by signing
each verification envelope with the matching private key.

This command emits the pubkey in the same base64url form the mint
endpoint expects, so it can be pasted directly into the app's mint
dialog or piped into another tool.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			configDir, err := getConfigDir(cmd)
			if err != nil {
				return err
			}
			key, err := leash.LoadOrCreate(configDir)
			if err != nil {
				return fmt.Errorf("load agent key: %w", err)
			}
			if jsonOut {
				out, _ := json.MarshalIndent(map[string]string{
					"pubkey_b64url": key.PublicB64,
				}, "", "  ")
				fmt.Println(string(out))
				return nil
			}
			fmt.Println(key.PublicB64)
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit JSON instead of the raw base64url pubkey")
	return cmd
}

func newLeashVerifyCmd() *cobra.Command {
	var (
		leashJWT     string
		validatorURL string
		action       string
		jsonOut      bool
		timeoutSecs  int
		session      string
	)
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify a real-user LEASH JWT against the public validator",
		Long: `Builds a verification envelope (LEASH + request + nonce + timestamp),
signs it with this agent's Ed25519 key (proof-of-possession), POSTs to
{validator}/v1/public/leash/verify, and renders the response. The
LEASH itself can be a real-user LEASH or a demo LEASH — the validator
doesn't care, but operationally this command is the one to use for
real-user LEASHes (the 'demo validate' command is reserved for the
Demo Alice flow).

--action MUST be a scope token like "profile.email:read" — the
validator checks that this exact string appears in the LEASH's
vettid:scope.

Exit code is 0 on a successful HTTP round-trip (regardless of whether
the LEASH verified); a non-zero exit means a network or 5xx error.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if leashJWT == "" {
				return fmt.Errorf("--leash is required (paste the compact JWT)")
			}
			if action == "" {
				return fmt.Errorf("--action is required (scope token like 'profile.email:read')")
			}
			leashJWT = strings.TrimSpace(leashJWT)

			configDir, err := getConfigDir(cmd)
			if err != nil {
				return err
			}
			key, err := leash.LoadOrCreate(configDir)
			if err != nil {
				return fmt.Errorf("load agent key: %w", err)
			}

			resp, err := leash.PostVerify(
				strings.TrimRight(validatorURL, "/"),
				key,
				leashJWT,
				action,
				session,
				time.Duration(timeoutSecs)*time.Second,
			)
			if err != nil {
				return err
			}

			if jsonOut {
				out, _ := json.MarshalIndent(resp, "", "  ")
				fmt.Println(string(out))
				return nil
			}
			renderHuman(resp, key.PublicB64, validatorURL, action)
			return nil
		},
	}
	cmd.Flags().StringVar(&leashJWT, "leash", "", "compact JWT to verify (required)")
	cmd.Flags().StringVar(&validatorURL, "validator", "https://api.vettid.dev", "validator base URL")
	cmd.Flags().StringVar(&action, "action", "", "scope token to verify against (required; e.g. profile.email:read)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit raw JSON response instead of human-readable chain")
	cmd.Flags().IntVar(&timeoutSecs, "timeout", 15, "HTTP timeout in seconds")
	cmd.Flags().StringVar(&session, "session", "", "optional demo session token (ses_…) — emits the result to vettid.dev's live tester page")
	return cmd
}
