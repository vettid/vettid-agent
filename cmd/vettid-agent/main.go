package main

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"runtime"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
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

func newInitCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init <shortlink>",
		Short: "Register with a vault using a shortlink",
		Long: `Resolves the one-time shortlink, connects to the owner's MessageSpace,
performs key exchange, sends registration details, and waits for owner approval.
On approval, prompts for an encryption passphrase and writes encrypted credentials.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("not yet implemented")
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
			fmt.Println("not yet implemented")
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
