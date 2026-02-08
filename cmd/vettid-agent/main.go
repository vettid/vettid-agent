package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
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
		Use:   "init <shortlink>",
		Short: "Register with a vault using a shortlink",
		Long: `Resolves the one-time shortlink, connects to the owner's MessageSpace,
performs key exchange, sends registration details, and waits for owner approval.
On approval, prompts for an encryption passphrase and writes encrypted credentials.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			configDir, err := getConfigDir(cmd)
			if err != nil {
				return err
			}

			// Check if already registered
			if credential.Exists(configDir) {
				return fmt.Errorf("already registered (credentials exist at %s). Use 'vettid-agent revoke' first", configDir)
			}

			agentType, _ := cmd.Flags().GetString("type")
			if agentType == "" {
				agentType = promptAgentType()
			}

			timeoutSecs, _ := cmd.Flags().GetInt("timeout")
			timeout := time.Duration(timeoutSecs) * time.Second

			flow := registration.NewFlow(registration.FlowConfig{
				Shortlink: args[0],
				AgentType: agentType,
				Timeout:   timeout,
				ConfigDir: configDir,
			})

			if err := flow.Run(); err != nil {
				return err
			}

			fmt.Println("\nRegistration complete. Run 'vettid-agent start' to begin.")
			return nil
		},
	}
	cmd.Flags().String("type", "", "Agent type (coding_assistant, data_pipeline, automation, monitoring, custom)")
	cmd.Flags().Int("timeout", 300, "Approval wait timeout in seconds")
	return cmd
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
				return fmt.Errorf("not registered. Run 'vettid-agent init <shortlink>' first")
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
				Token:        creds.MessageSpaceToken,
				ConnectionID: creds.ConnectionID,
				OwnerGUID:    creds.OwnerGUID,
			})
			if err != nil {
				return fmt.Errorf("connect to NATS: %w", err)
			}
			defer client.Close()

			log.Info().Msg("Connected to MessageSpace")

			// Start API server
			server, err := api.NewServer(&api.ServerConfig{
				Listen: cfg.API.Listen,
			})
			if err != nil {
				return fmt.Errorf("create API server: %w", err)
			}

			if err := server.Start(cfg.API.Listen); err != nil {
				return fmt.Errorf("start API server: %w", err)
			}

			// Subscribe to responses (handler is a no-op for now — Step 8)
			if err := client.SubscribeResponses(func(data []byte) {
				log.Debug().Int("bytes", len(data)).Msg("Received response from vault")
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
