package main

// demo.go — subcommands that exercise the LEASH validator from the
// agent's perspective. Currently:
//
//   vettid-agent demo validate --leash <jwt> --action <scope-token>
//
// posts a signed verification envelope to the public LEASH validator
// (https://api.vettid.dev/v1/public/leash/verify by default) and
// pretty-prints the verification chain so a demo viewer can see each
// algorithm step pass or fail.
//
// The agent's Ed25519 keypair lives at {configDir}/leash_agent_key.json,
// generated lazily on first run. The pubkey is what the LEASH carries
// in its `vettid:agent_pubkey` claim; the privkey signs each per-call
// envelope to prove the agent holds it (PoP).
//
// Two more subcommands ('attest' to request a LEASH from the user's
// vault, 'revoke' to revoke one) wait on the enclave deploy that
// ships the vault-side leash.attest / leash.revoke ops. Until then,
// LEASHes for testing must be minted out-of-band (e.g. from a desktop
// app once it integrates the vault op, or via test fixtures).

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/vettid/vettid-agent/internal/leash"
)

func newDemoCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "demo",
		Short: "LEASH token demo helpers (validate, attest, revoke)",
		Long: `Exercises the public LEASH validator from the agent's perspective.

The full demo flow:
  1. Owner mints a LEASH for this agent via desktop/mobile (see Sprint 4.5/5)
  2. Agent runs: vettid-agent demo validate --leash <jwt> --action <scope>
  3. Validator returns a verification chain; agent prints pass/fail per step

For the validate path, the agent only needs the LEASH (bearer credential),
not the owner's vault — it proves possession with its own Ed25519 key.`,
	}
	cmd.AddCommand(newDemoValidateCmd())
	return cmd
}

func newDemoValidateCmd() *cobra.Command {
	var (
		leashJWT     string
		validatorURL string
		action       string
		jsonOut      bool
		timeoutSecs  int
	)
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Verify a LEASH JWT against the public validator",
		Long: `Builds a verification envelope (LEASH + request + nonce + timestamp),
signs it with this agent's Ed25519 key (proof-of-possession), POSTs to
the validator's /v1/public/leash/verify, and renders the response.

--action MUST be a scope token like "profile.email:read" — the validator
checks that this exact string appears in the LEASH's vettid:scope.

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
	return cmd
}

// renderHuman prints the verification chain in a terminal-friendly
// shape. Designed for live-demo viewing: verdict at the top, then
// each check on its own line, then a small detail block.
func renderHuman(r *leash.VerifyResponse, agentPubkey, validator, action string) {
	bar := strings.Repeat("─", 60)
	fmt.Println(bar)
	if r.Verified {
		fmt.Println("  ✓ VERIFIED")
	} else {
		reason := "(no reason)"
		if r.RejectionReason != nil {
			reason = *r.RejectionReason
		}
		fmt.Printf("  ✗ REJECTED — %s\n", reason)
	}
	fmt.Println(bar)
	fmt.Printf("  validator:    %s\n", validator)
	fmt.Printf("  action:       %s\n", action)
	fmt.Printf("  agent pubkey: %s\n", trunc(agentPubkey, 32))
	fmt.Println()

	fmt.Println("  Verification chain:")
	for _, c := range r.Checks {
		mark := "✗"
		if c.Status == "pass" {
			mark = "✓"
		}
		fmt.Printf("    %s %-20s %s\n", mark, c.Name, c.Detail)
	}

	fmt.Println()
	fmt.Println("  Detail:")
	printKV("issuer", strOr(r.Issuer, "—"))
	printKV("subject", strOr(r.Subject, "—"))
	printKV("scope matched", strOr(r.ScopeMatched, "—"))
	if len(r.ScopesGranted) > 0 {
		printKV("scopes granted", strings.Join(r.ScopesGranted, ", "))
	}
	if r.TimeRemainingSecs != nil {
		printKV("time remaining", fmt.Sprintf("%ds", *r.TimeRemainingSecs))
	}
	if r.GrantVersion != nil {
		printKV("grant version", fmt.Sprintf("%d", *r.GrantVersion))
	}
	if r.ProfileVersionAtGrant != nil {
		printKV("profile version", fmt.Sprintf("%d (at grant time)", *r.ProfileVersionAtGrant))
	}
	if r.Evidence.JwtPubkeyKid != nil {
		printKV("kid", *r.Evidence.JwtPubkeyKid)
	}
	if r.CheckedAt > 0 {
		printKV("checked at", time.Unix(r.CheckedAt, 0).UTC().Format(time.RFC3339))
	}
	fmt.Println(bar)
}

func printKV(k, v string) {
	fmt.Printf("    %-17s %s\n", k+":", v)
}

func strOr(s *string, fallback string) string {
	if s == nil || *s == "" {
		return fallback
	}
	return *s
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
