# CLAUDE.md

This file provides guidance to Claude Code when working with code in this repository.

## Project Overview

VettID Agent Connector — a lightweight Go binary that enables AI agents to securely request secrets and data from a VettID vault owner. It runs as a sidecar process alongside the AI agent, handling all cryptographic operations, NATS connectivity, and vault communication.

## Build Commands

```bash
make build            # Build for current platform
make test             # Run all tests
make lint             # Run linter
make clean            # Remove build artifacts
make release          # Cross-compile for all platforms
```

Or directly:
```bash
go build -o vettid-agent ./cmd/vettid-agent
go test ./...
```

## Project Structure

```
cmd/vettid-agent/main.go     # CLI entrypoint (cobra)
internal/
  config/config.go            # TOML config loading
  crypto/
    keys.go                   # X25519 keypair generation
    encrypt.go                # ChaCha20-Poly1305 encrypt/decrypt
    argon2.go                 # Argon2id key derivation
  credential/store.go         # Encrypted credential storage (connection.enc)
  fingerprint/
    machine.go                # Machine fingerprint collection
    binary.go                 # Binary SHA-256 fingerprint
    platform_key.go           # Platform key derivation
  nats/
    client.go                 # NATS MessageSpace client
    messages.go               # Message types and serialization
  api/
    server.go                 # Local REST API (Unix socket + TCP)
    handlers.go               # Route handlers
    websocket.go              # WebSocket endpoint
  registration/
    shortlink.go              # Shortlink resolver
    flow.go                   # Registration state machine
```

## Crypto Stack

Matches the VettID enclave crypto stack:
- **X25519** — Key exchange for E2E encryption
- **ChaCha20-Poly1305** — Symmetric encryption (XChaCha20 variant, 24-byte nonce)
- **Argon2id** — Password hashing and key derivation
- **HMAC-SHA256** — Machine fingerprinting and platform key derivation
- **SHA-256** — Binary fingerprinting

## Architecture

```
AI Agent → Local API/WebSocket → Agent Connector → NATS MessageSpace → Vault (Nitro Enclave) → Owner's App
```

The connector never stores secrets. All policy enforcement happens in the vault. The agent never holds encryption keys or NATS credentials.

## CLI Commands

| Command | Description |
|---------|-------------|
| `init <shortlink>` | Register with a vault using a shortlink |
| `start` | Start the connector and local API |
| `status` | Show connection status and health |
| `rebind` | Re-bind credentials after hardware changes |
| `revoke` | Disconnect from vault and clean up |
| `version` | Show version and binary fingerprint |

## Key Design Decisions

- **One connector = one vault** — Run multiple instances with `--config-dir` for multiple vaults
- **No secret caching** — Requests fail if disconnected
- **Platform binding** — Credentials are encrypted with passphrase + machine fingerprint, undecryptable on different machines
- **Local-only API** — Unix socket or localhost TCP, never exposed to network

## Related Repos

- `vettid-dev` — Backend infrastructure (CDK, Lambda, Enclave, NATS)
- `vettid-android` — Android mobile app
- `vettid-ios` — iOS mobile app

## Security Patterns

Look for `// SECURITY:` comments marking critical sections.

Never commit:
- Encryption keys or credentials
- Connection tokens or NATS credentials
- Platform key files
- Any PII or secrets
