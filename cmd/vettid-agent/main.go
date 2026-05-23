package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/vettid/vettid-agent/internal/api"
	"github.com/vettid/vettid-agent/internal/config"
	"github.com/vettid/vettid-agent/internal/credential"
	"github.com/vettid/vettid-agent/internal/crypto"
	"github.com/vettid/vettid-agent/internal/fingerprint"
	vettidnats "github.com/vettid/vettid-agent/internal/nats"
	"github.com/vettid/vettid-agent/internal/registration"
)

var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

func main() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	rootCmd := &cobra.Command{
		Use:   "vettid-agent",
		Short: "VettID Agent Connector — Secure sidecar for AI agent vault access",
		Long: `The VettID Agent Connector enables AI agents to securely request
secrets and data from a VettID vault owner. It runs as a sidecar process
alongside the AI agent, handling all cryptographic operations, NATS
connectivity, and vault communication.`,
		SilenceUsage: true,
	}

	rootCmd.PersistentFlags().String("config-dir", "", "Config directory (default: ~/.vettid-agent)")

	rootCmd.AddCommand(
		newInitCmd(),
		newStartCmd(),
		newStatusCmd(),
		newRebindCmd(),
		newRevokeCmd(),
		newVersionCmd(),
	)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// getConfigDir resolves the config directory from the --config-dir flag,
// defaulting to ~/.vettid-agent, and creates it with 0700 permissions if needed.
func getConfigDir(cmd *cobra.Command) (string, error) {
	dir, _ := cmd.Flags().GetString("config-dir")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("get home directory: %w", err)
		}
		dir = filepath.Join(home, ".vettid-agent")
	}

	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("create config directory %s: %w", dir, err)
	}

	return dir, nil
}

func newInitCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init <invite-code>",
		Short: "Register with a vault using an invite code",
		Long: `Registers this agent with a vault using a one-time 12-character
invite code displayed in the vault owner's app.

Two-stage NATS pairing:
  1. Stage 1 mints scoped guest creds via the bootstrap endpoint, fetches
     the invite payload from JetStream, and tears down the guest connection.
  2. Stage 2 reconnects with the per-pair scoped creds, publishes
     agent.request-session, waits for the owner to approve on the phone,
     does X25519+HKDF, and seals connection.enc under the local passphrase.

See vettid-agent/docs/AGENT-PAIRING-FLOW.md for the full protocol.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			configDir, err := getConfigDir(cmd)
			if err != nil {
				return err
			}

			if credential.Exists(configDir) {
				return fmt.Errorf("already registered (credentials exist at %s). Use 'vettid-agent revoke' first", configDir)
			}

			agentType, _ := cmd.Flags().GetString("type")
			if agentType == "" {
				agentType = promptAgentType()
			}

			timeoutSecs, _ := cmd.Flags().GetInt("timeout")
			timeout := time.Duration(timeoutSecs) * time.Second

			scope, _ := cmd.Flags().GetStringSlice("scope")
			approvalMode, _ := cmd.Flags().GetString("approval-mode")
			durationSecs, _ := cmd.Flags().GetInt64("duration")
			platformKeyFile, _ := cmd.Flags().GetString("platform-key-file")
			passphraseFile, _ := cmd.Flags().GetString("passphrase-file")

			ctx, cancel := context.WithTimeout(cmd.Context(), timeout+30*time.Second)
			defer cancel()

			// Stage 1 — resolve invite via the guest bootstrap path.
			fmt.Fprintln(os.Stderr, "▸ resolving invite")
			session, runtimeState, err := registration.ResolveInvite(ctx, args[0])
			if err != nil {
				return fmt.Errorf("stage 1: %w", err)
			}
			defer runtimeState.Zero()

			// Build the identity card the phone shows the owner.
			metadata, err := registration.CollectAgentMetadata(agentType, version)
			if err != nil {
				return fmt.Errorf("collect agent metadata: %w", err)
			}

			// Derive the platform key the credential store will encrypt under.
			// We do this before reading the passphrase so a misconfigured
			// platform-key-file fails fast.
			platformKey, err := fingerprint.DerivePlatformKey(platformKeyFile)
			if err != nil {
				return fmt.Errorf("derive platform key: %w", err)
			}
			defer crypto.ZeroBytes(platformKey)

			passphrase, err := readPassphraseForInit(passphraseFile)
			if err != nil {
				return err
			}
			defer crypto.ZeroBytes(passphrase)

			fmt.Fprintln(os.Stderr, "▸ request-session sent; awaiting owner approval on phone")

			outcome, err := registration.CompletePairing(
				ctx,
				session,
				runtimeState,
				metadata,
				registration.CompletePairingOptions{
					Timeout:               timeout,
					RequestedScope:        scope,
					RequestedApprovalMode: approvalMode,
					RequestedDurationSecs: durationSecs,
				},
				configDir,
				passphrase,
				platformKey,
			)
			if err != nil {
				return fmt.Errorf("stage 2: %w", err)
			}

			fmt.Fprintln(os.Stderr, "▸ activated")
			fmt.Println()
			fmt.Printf("Registration complete.\n")
			fmt.Printf("  connection_id: %s\n", outcome.ConnectionID)
			fmt.Printf("  session_id:    %s\n", outcome.SessionID)
			fmt.Printf("  expires_at:    %s (%ds)\n",
				time.Unix(outcome.ExpiresAt, 0).Format(time.RFC3339),
				outcome.DurationSeconds)
			fmt.Printf("  approval_mode: %s\n", outcome.ApprovalMode)
			if len(outcome.GrantedScope) == 0 {
				fmt.Printf("  scope:         (none — phone granted no scope tokens)\n")
			} else {
				fmt.Printf("  scope:         %s\n", strings.Join(outcome.GrantedScope, ", "))
			}
			fmt.Println("\nRun 'vettid-agent start' to begin.")
			return nil
		},
	}
	cmd.Flags().String("type", "", "Agent type label shown to the owner (e.g. claude-code, cursor, self-hosted-llm)")
	cmd.Flags().Int("timeout", 300, "Approval wait timeout in seconds")
	cmd.Flags().StringSlice("scope", nil, "Requested scope tokens (repeatable; hints only — phone picks the final set). Vocabulary: secrets.catalog.read, secrets.get, secrets.put, message.send, message.recv, call.history, connection.list, connection.get, agent.action.<tool>")
	cmd.Flags().String("approval-mode", "always_ask", `Requested approval mode hint: "always_ask" or "auto_within_contract"`)
	cmd.Flags().Int64("duration", registration.DefaultRequestedDurationSecs, "Requested session duration in seconds (hint; phone caps at 24h)")
	cmd.Flags().String("passphrase-file", "", "Read passphrase from file instead of prompting (init only)")
	cmd.Flags().String("platform-key-file", "", "Platform key file for containers/VMs (skips machine-attribute collection)")
	return cmd
}

// readPassphraseForInit reads a passphrase for credential.Save during init.
// Either reads from a file (CI/automated install) or prompts twice and
// requires confirmation. The two-prompt path is *only* on init — start
// reads once because there's nothing to confirm against.
func readPassphraseForInit(file string) ([]byte, error) {
	if file != "" {
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("read passphrase file: %w", err)
		}
		// Strip a single trailing newline if present (common when shell
		// users do `echo > file` to populate it).
		if n := len(data); n > 0 && data[n-1] == '\n' {
			data = data[:n-1]
		}
		return data, nil
	}
	fmt.Print("Choose a passphrase to seal connection.enc: ")
	first, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return nil, fmt.Errorf("read passphrase: %w", err)
	}
	fmt.Print("Confirm passphrase: ")
	second, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		crypto.ZeroBytes(first)
		return nil, fmt.Errorf("read passphrase confirmation: %w", err)
	}
	if string(first) != string(second) {
		crypto.ZeroBytes(first)
		crypto.ZeroBytes(second)
		return nil, fmt.Errorf("passphrases did not match")
	}
	crypto.ZeroBytes(second)
	return first, nil
}

func newStartCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start the connector and local API",
		Long: `Starts the connector. Decrypts credentials, connects to NATS,
and begins serving the local API and WebSocket endpoint.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			configDir, err := getConfigDir(cmd)
			if err != nil {
				return err
			}

			// Check credentials exist
			if !credential.Exists(configDir) {
				return fmt.Errorf("not registered. Run 'vettid-agent init <invite-code>' first")
			}

			// Load config
			cfg, err := config.Load(configDir)
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}

			// Read passphrase
			passphraseFile, _ := cmd.Flags().GetString("passphrase-file")
			platformKeyFile, _ := cmd.Flags().GetString("platform-key-file")

			var passphrase []byte
			if passphraseFile != "" {
				passphrase, err = os.ReadFile(passphraseFile)
				if err != nil {
					return fmt.Errorf("read passphrase file: %w", err)
				}
			} else {
				fmt.Print("Enter passphrase: ")
				passphrase, err = term.ReadPassword(int(syscall.Stdin))
				fmt.Println()
				if err != nil {
					return fmt.Errorf("read passphrase: %w", err)
				}
			}
			defer crypto.ZeroBytes(passphrase)

			// Load credentials with tolerance
			creds, reencrypted, err := credential.LoadWithTolerance(configDir, string(passphrase), platformKeyFile)
			if err != nil {
				return fmt.Errorf("load credentials: %w", err)
			}
			defer creds.Zero()

			if reencrypted {
				log.Info().Msg("Credentials re-encrypted with current machine fingerprint")
			}

			log.Info().
				Str("connection_id", creds.ConnectionID).
				Str("approval_mode", creds.ApprovalMode).
				Msg("Credentials loaded")

			// Connect to NATS
			client, err := vettidnats.NewClient(&vettidnats.ClientConfig{
				URL:          creds.MessageSpaceURL,
				JWT:          creds.JWT,
				Seed:         creds.Seed,
				ConnectionID: creds.ConnectionID,
				OwnerGUID:    creds.OwnerGUID,
				TLS:          cfg.NATS.TLSEnabled,
			})
			if err != nil {
				return fmt.Errorf("connect to NATS: %w", err)
			}
			defer client.Close()

			log.Info().Msg("Connected to MessageSpace")

			// Determine request timeout from config
			requestTimeout := time.Duration(cfg.Security.RequestTimeoutSeconds) * time.Second
			if requestTimeout == 0 {
				requestTimeout = 30 * time.Second
			}

			// Parse allowed origins from config
			var allowedOrigins []string
			if cfg.WebSocket.AllowedOrigins != "" {
				for _, o := range strings.Split(cfg.WebSocket.AllowedOrigins, ",") {
					if trimmed := strings.TrimSpace(o); trimmed != "" {
						allowedOrigins = append(allowedOrigins, trimmed)
					}
				}
			}

			// Start API server with all dependencies
			server, err := api.NewServer(&api.ServerConfig{
				Listen:         cfg.API.Listen,
				AllowedOrigins: allowedOrigins,
				NATSClient:     client,
				ConnKey:        creds.ConnectionKey,
				KeyID:          creds.KeyID,
				ConnectionID:   creds.ConnectionID,
				OwnerGUID:      creds.OwnerGUID,
				Scope:          creds.Scope,
				ApprovalMode:   creds.ApprovalMode,
				RequestTimeout: requestTimeout,
			})
			if err != nil {
				return fmt.Errorf("create API server: %w", err)
			}

			if err := server.Start(cfg.API.Listen); err != nil {
				return fmt.Errorf("start API server: %w", err)
			}

			// SECURITY (#56 + #57): one shared validator for the
			// process so sequence-monotonicity is enforced across
			// every inbound envelope, and timestamp skew is checked
			// at the same point.
			validator := vettidnats.NewEnvelopeValidator()

			// Subscribe to NATS responses and dispatch to tracker/catalog
			if err := client.SubscribeResponses(func(data []byte) {
				handleNATSResponse(data, server, creds.ConnectionKey, validator)
			}); err != nil {
				return fmt.Errorf("subscribe to responses: %w", err)
			}

			fmt.Println("Agent connector running. Press Ctrl+C to stop.")

			// Wait for shutdown signal
			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
			sig := <-sigCh

			log.Info().Str("signal", sig.String()).Msg("Shutting down...")

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			if err := server.Stop(ctx); err != nil {
				log.Error().Err(err).Msg("API server shutdown error")
			}

			// Drain NATS connection
			if err := client.Conn().Drain(); err != nil {
				log.Error().Err(err).Msg("NATS drain error")
			}

			fmt.Println("Stopped.")
			return nil
		},
	}
	cmd.Flags().String("passphrase-file", "", "Read passphrase from file")
	cmd.Flags().String("platform-key-file", "", "Platform key file for containers/VMs")
	cmd.Flags().Bool("daemon", false, "Run in background")
	return cmd
}

func newStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show connection status and health",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("not yet implemented")
			return nil
		},
	}
}

func newRebindCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rebind",
		Short: "Re-bind credentials to current machine after hardware changes",
		Long: `Re-derives the platform key from the current machine's attributes and
re-encrypts credentials. Use after hardware changes (NIC replacement, hostname
change, etc.) that cause normal startup to fail.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("not yet implemented")
			return nil
		},
	}
}

func newRevokeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "revoke",
		Short: "Disconnect from vault and clean up credentials",
		Long: `Sends disconnect notification to vault, invalidates local credentials,
and removes encrypted config files.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("not yet implemented")
			return nil
		},
	}
	cmd.Flags().Bool("confirm", false, "Skip confirmation prompt")
	return cmd
}

func newVersionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Show version and binary fingerprint",
		RunE: func(cmd *cobra.Command, args []string) error {
			fingerprint, err := binaryFingerprint()
			if err != nil {
				fingerprint = "unavailable"
			}

			fmt.Printf("vettid-agent %s\n", version)
			fmt.Printf("  commit:      %s\n", commit)
			fmt.Printf("  built:       %s\n", buildDate)
			fmt.Printf("  go:          %s\n", runtime.Version())
			fmt.Printf("  platform:    %s/%s\n", runtime.GOOS, runtime.GOARCH)
			fmt.Printf("  fingerprint: %s\n", fingerprint)
			return nil
		},
	}
	cmd.Flags().Bool("json", false, "Output in JSON format")
	return cmd
}

// promptAgentType interactively prompts the user to select an agent type.
func promptAgentType() string {
	types := []string{
		"coding_assistant",
		"data_pipeline",
		"automation",
		"monitoring",
		"custom",
	}

	fmt.Println("\nSelect agent type:")
	for i, t := range types {
		fmt.Printf("  %d. %s\n", i+1, t)
	}
	fmt.Print("Choice [1]: ")

	var input string
	fmt.Scanln(&input)

	if input == "" {
		return types[0]
	}

	choice := 0
	if _, err := fmt.Sscanf(input, "%d", &choice); err != nil || choice < 1 || choice > len(types) {
		fmt.Println("Invalid choice, using 'coding_assistant'")
		return types[0]
	}

	return types[choice-1]
}

// handleNATSResponse decodes incoming NATS envelopes and dispatches them
// to the appropriate handler (tracker or catalog).
func handleNATSResponse(data []byte, server *api.Server, connKey []byte, validator *vettidnats.EnvelopeValidator) {
	env, err := vettidnats.DecodeEnvelope(data)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to decode NATS response envelope")
		return
	}

	// SECURITY (#56 + #57): refuse envelopes that fail sequence
	// monotonicity or timestamp-skew bounds. Drops the message
	// silently after logging; the vault will resend if it actually
	// needed a reply.
	if err := validator.Validate(env); err != nil {
		log.Warn().Err(err).
			Str("type", string(env.Type)).
			Uint64("sequence", env.Sequence).
			Time("timestamp", env.Timestamp).
			Msg("Envelope validation failed — dropping")
		return
	}

	switch env.Type {
	case vettidnats.MsgSecretResponse:
		plaintext, err := crypto.Decrypt(connKey, env.Payload, nil)
		if err != nil {
			log.Error().Err(err).Msg("Failed to decrypt secret response")
			return
		}
		defer crypto.ZeroBytes(plaintext)

		var resp vettidnats.SecretResponse
		if err := json.Unmarshal(plaintext, &resp); err != nil {
			log.Error().Err(err).Msg("Failed to unmarshal secret response")
			return
		}

		result := &api.TrackedResult{
			RequestID:   resp.RequestID,
			SecretValue: resp.SecretValue,
			ExpiresAt:   resp.ExpiresAt,
			Reason:      resp.Reason,
		}

		switch resp.Status {
		case "approved":
			result.Status = api.StatusApproved
		case "denied":
			result.Status = api.StatusDenied
		case "pending_approval":
			result.Status = api.StatusPendingApproval
		default:
			result.Status = api.StatusError
			if result.Reason == "" {
				result.Reason = "unknown status: " + resp.Status
			}
		}

		server.Tracker().Resolve(resp.RequestID, result)

	case vettidnats.MsgAgentActionResponse:
		plaintext, err := crypto.Decrypt(connKey, env.Payload, nil)
		if err != nil {
			log.Error().Err(err).Msg("Failed to decrypt action response")
			return
		}
		defer crypto.ZeroBytes(plaintext)

		var resp vettidnats.ActionResponse
		if err := json.Unmarshal(plaintext, &resp); err != nil {
			log.Error().Err(err).Msg("Failed to unmarshal action response")
			return
		}

		result := &api.TrackedResult{
			RequestID: resp.RequestID,
			Result:    resp.Result,
			Reason:    resp.Reason,
		}

		switch resp.Status {
		case "completed":
			result.Status = api.StatusCompleted
		case "denied":
			result.Status = api.StatusDenied
		case "error":
			result.Status = api.StatusError
		default:
			result.Status = api.StatusError
			if result.Reason == "" {
				result.Reason = "unknown status: " + resp.Status
			}
		}

		server.Tracker().Resolve(resp.RequestID, result)

	case vettidnats.MsgAgentSecretCatalog:
		plaintext, err := crypto.Decrypt(connKey, env.Payload, nil)
		if err != nil {
			log.Error().Err(err).Msg("Failed to decrypt secret catalog")
			return
		}
		defer crypto.ZeroBytes(plaintext)

		var catalog vettidnats.SecretCatalog
		if err := json.Unmarshal(plaintext, &catalog); err != nil {
			log.Error().Err(err).Msg("Failed to unmarshal secret catalog")
			return
		}

		server.Catalog().Update(&catalog)
		log.Info().
			Uint64("version", catalog.Version).
			Int("entries", len(catalog.Entries)).
			Msg("Secret catalog updated")

	default:
		log.Debug().Str("type", string(env.Type)).Msg("Ignoring unknown NATS message type")
	}
}

func binaryFingerprint() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("get executable path: %w", err)
	}

	f, err := os.Open(exe)
	if err != nil {
		return "", fmt.Errorf("open binary: %w", err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash binary: %w", err)
	}

	return fmt.Sprintf("%x", h.Sum(nil)), nil
}
