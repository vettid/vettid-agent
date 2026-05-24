package main

// demo.go — subcommands that exercise the public LEASH endpoints from
// the agent's perspective.
//
//   vettid-agent demo attest   --scope <token> [--scope <token>...] [--duration <secs>]
//   vettid-agent demo validate --leash <jwt>   --action <scope-token>
//
// Both target the public Demo Alice surface on api.vettid.dev — no
// user-vault round-trip is involved. `attest` mints a fresh Demo Alice
// LEASH bound to this agent's pubkey; `validate` posts a signed
// verification envelope to /v1/public/leash/verify and renders the
// chain. Together they exercise the same paths the gamified page on
// vettid.dev/leash exercises, but from a real agent process.
//
// The agent's Ed25519 keypair lives at {configDir}/leash_agent_key.json,
// generated lazily on first run. The pubkey is what the LEASH carries
// in its `vettid:agent_pubkey` claim; the privkey signs each per-call
// envelope to prove the agent holds it (PoP).
//
// Real-user LEASHes (issued by an actual VettID user, not Demo Alice)
// are minted by the user's app calling forVault.leash.attest on their
// own vault — that path is outside the agent's privilege scope and not
// reachable from this command.

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
		Short: "LEASH demo helpers (attest, validate)",
		Long: `Exercises the public Demo Alice LEASH endpoints from the agent's perspective.

End-to-end flow you can run right now:
  1. vettid-agent demo attest   --scope profile.email:read
       → mints a Demo Alice LEASH for this agent's pubkey, prints the JWT
  2. vettid-agent demo validate --leash <jwt> --action profile.email:read
       → posts a signed verify envelope, renders pass/fail per check

Both subcommands hit api.vettid.dev (override with --api / --validator).
Neither talks to a real user's vault.`,
	}
	cmd.AddCommand(newDemoAttestCmd())
	cmd.AddCommand(newDemoValidateCmd())
	return cmd
}

func newDemoAttestCmd() *cobra.Command {
	var (
		scopes       []string
		apiURL       string
		durationSecs int
		jsonOut      bool
		timeoutSecs  int
	)
	cmd := &cobra.Command{
		Use:   "attest",
		Short: "Mint a Demo Alice LEASH bound to this agent's pubkey",
		Long: `Requests a fresh LEASH from the public Demo Alice mint endpoint at
{api}/v1/public/leash/demo/mint. The agent's Ed25519 pubkey (loaded
or lazily generated under {configDir}/leash_agent_key.json) is bound
into the vettid:agent_pubkey claim so 'demo validate' under the same
config dir produces a passing PoP signature.

--scope is repeatable; tokens must be on the demo allowlist (see
DEMO_SCOPE_OPTIONS in vettid-dev). Pipe the printed JWT directly into
'demo validate --leash …' for a full round-trip.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(scopes) == 0 {
				return fmt.Errorf("--scope is required (repeat for multiple, e.g. --scope profile.email:read --scope profile.name:read)")
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
			key, err := leash.LoadOrCreate(configDir)
			if err != nil {
				return fmt.Errorf("load agent key: %w", err)
			}

			resp, err := leash.PostMint(
				strings.TrimRight(apiURL, "/"),
				key,
				scopes,
				durationSecs,
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
			renderMint(resp, key.PublicB64, apiURL, scopes)
			return nil
		},
	}
	cmd.Flags().StringSliceVar(&scopes, "scope", nil, "scope token (repeatable; allowlisted; e.g. profile.email:read)")
	cmd.Flags().StringVar(&apiURL, "api", "https://api.vettid.dev", "demo API base URL")
	cmd.Flags().IntVar(&durationSecs, "duration", 120, "leash duration in seconds (max 600 per demo cap)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit raw JSON response instead of human-readable summary")
	cmd.Flags().IntVar(&timeoutSecs, "timeout", 15, "HTTP timeout in seconds")
	return cmd
}

func newDemoValidateCmd() *cobra.Command {
	var (
		leashJWT     string
		validatorURL string
		action       string
		jsonOut      bool
		timeoutSecs  int
		session      string
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

// renderMint prints the mint response in a terminal-friendly shape —
// the LEASH JWT printed in a copy-pasteable block, then a short
// summary of the claims you'd be looking at if you decoded it.
func renderMint(r *leash.MintResponse, agentPubkey, apiURL string, scopes []string) {
	bar := strings.Repeat("─", 60)
	fmt.Println(bar)
	fmt.Println("  ✓ MINTED")
	fmt.Println(bar)
	fmt.Printf("  api:          %s\n", apiURL)
	fmt.Printf("  scope:        %s\n", strings.Join(scopes, ", "))
	fmt.Printf("  agent pubkey: %s\n", trunc(agentPubkey, 32))
	fmt.Println()
	fmt.Println("  Issued LEASH (compact JWT):")
	fmt.Println()
	fmt.Println("    " + r.Leash)
	fmt.Println()
	fmt.Println("  Detail:")
	printKV("jti", r.JTI)
	printKV("kid", r.Kid)
	if r.IssuedAt > 0 {
		printKV("issued at", time.Unix(r.IssuedAt, 0).UTC().Format(time.RFC3339))
	}
	if r.ExpiresAt > 0 {
		printKV("expires at", time.Unix(r.ExpiresAt, 0).UTC().Format(time.RFC3339))
		printKV("valid for", fmt.Sprintf("%ds", r.ExpiresAt-r.IssuedAt))
	}
	fmt.Println(bar)
	fmt.Println()
	fmt.Println("  Next: vettid-agent demo validate \\")
	fmt.Printf("          --leash %q \\\n", r.Leash)
	if len(scopes) > 0 {
		fmt.Printf("          --action %s\n", scopes[0])
	} else {
		fmt.Println("          --action <one-of-the-scope-tokens-above>")
	}
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
