# VettID Agent Connector

Secure sidecar for AI agent vault access. Enables AI agents to request secrets and data from a [VettID](https://vettid.dev) vault owner — without the agent ever touching encryption keys, NATS credentials, or raw vault tokens.

## How It Works

```
┌──────────────┐    localhost     ┌────────────────────┐     TLS + E2E     ┌──────────────────┐
│              │  (Unix socket    │                    │    encrypted      │                  │
│   AI Agent   │   or :7443)      │  Agent Connector   │───────────────────│  Owner's Vault   │
│  (any LLM)   │◄───────────────►│  (this binary)     │   NATS Messages   │  (Nitro Enclave) │
│              │  Simple REST     │                    │                   │                  │
└──────────────┘  or WebSocket    └────────────────────┘                   └──────────────────┘
```

The Agent Connector runs alongside your AI agent as a sidecar process. It handles:

- **Registration** — One-time setup via a shortlink from the vault owner's mobile app
- **Key exchange** — X25519 key agreement, ChaCha20-Poly1305 encryption
- **NATS messaging** — Publishes encrypted requests, subscribes to responses
- **Local API** — REST (Unix socket or TCP) and WebSocket for the agent to use
- **Credential security** — Encrypted at rest with Argon2id + machine-bound platform key

The vault owner controls everything: what secrets are accessible, whether requests auto-approve or require manual approval, and rate limits. Revocation is instant.

## Quick Start

### 1. Owner creates invitation (mobile app)

Tap **Connect Agent** → a 2-minute shortlink appears.

### 2. Operator registers

```bash
vettid-agent init vettid.dev/a/K7x9Qm --type coding_assistant
```

The connector resolves the shortlink, performs key exchange, and waits for owner approval.

### 3. Owner approves (mobile app)

Review agent details, set permissions (scope, approval mode, rate limits), tap **Approve**.

### 4. Start the connector

```bash
vettid-agent start
```

### 5. Agent makes requests

```bash
# Via Unix socket
curl --unix-socket ~/.vettid-agent/agent.sock \
  http://localhost/v1/secrets/request \
  -d '{"secret_type":"api_key","secret_name":"openai_api_key","purpose":"API call","action":"retrieve"}'

# Via WebSocket
ws://127.0.0.1:7443/v1/ws?token=<session_token>
```

## Installation

### From GitHub Releases

Download the latest binary for your platform from [Releases](https://github.com/vettid/vettid-agent/releases).

### From Source

```bash
git clone https://github.com/vettid/vettid-agent.git
cd vettid-agent
make build
```

Requires Go 1.24+.

## CLI Reference

| Command | Description |
|---------|-------------|
| `vettid-agent init <shortlink>` | Register with a vault |
| `vettid-agent start` | Start connector and local API |
| `vettid-agent status` | Show connection health |
| `vettid-agent rebind` | Re-bind credentials after hardware changes |
| `vettid-agent revoke` | Disconnect and clean up |
| `vettid-agent version` | Show version and binary fingerprint |

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/secrets/request` | POST | Request a secret from the vault |
| `/v1/status` | GET | Check connector health |
| `/v1/requests/{id}` | GET | Poll pending request status |
| `/v1/connection/disconnect` | POST | Disconnect from vault |
| `/v1/ws` | WebSocket | Full-duplex for browser agents |

## Security Model

- **Zero-trust for the agent** — Never holds keys or NATS credentials
- **Platform binding** — Credentials encrypted with passphrase + machine fingerprint
- **E2E encryption** — All vault communication encrypted with connection-specific keys
- **Owner sovereignty** — Vault owner controls all permissions via mobile app
- **No secret caching** — Secrets pass through, never stored

See [docs/vettid-agent-connector-design.md](docs/vettid-agent-connector-design.md) for the full design document.

## License

[AGPL-3.0](LICENSE)
