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

- **Registration** — One-time setup via an invite code from the vault owner's mobile app
- **Key exchange** — X25519 key agreement, ChaCha20-Poly1305 encryption
- **NATS messaging** — Publishes encrypted requests, subscribes to responses
- **Local API** — REST (Unix socket or TCP) and WebSocket for the agent to use
- **Credential security** — Encrypted at rest with Argon2id + machine-bound platform key

The vault owner controls everything: what secrets are accessible, whether requests auto-approve or require manual approval, and rate limits. Revocation is instant.

## Quick Start

The full protocol is documented in [`docs/AGENT-PAIRING-FLOW.md`](docs/AGENT-PAIRING-FLOW.md). The end-to-end pairing is a two-stage NATS round-trip; the user-facing steps are:

### 1. Owner creates an invite (mobile app)

In the VettID app, tap **Settings → Agents → Pair new agent**. The phone displays a 12-character invite code (e.g. `ABCD-EFGH-JKLM`). The code is good for 2 minutes.

### 2. Operator registers

```bash
vettid-agent init ABCDEFGHJKLM --type claude-code
```

You'll be prompted for a passphrase. This passphrase seals `connection.enc` under both your input AND the host's machine fingerprint — a copy of the file alone is useless on another machine.

The connector:
- Mints per-pair guest NATS credentials via the public bootstrap endpoint
- Reads the invite payload from JetStream
- Generates an ephemeral X25519 keypair + a 32-byte approval token
- Publishes `agent.request-session` carrying its identity card (binary + machine fingerprints, OS, app version, agent type)
- Waits for the owner to approve on their phone (`--timeout` defaults to 300 s)

Optional flags:
- `--scope secrets.catalog.read --scope secrets.get` — request specific scope tokens (phone has final say)
- `--approval-mode auto_within_contract` — request auto-approve for ops within the granted scope
- `--duration 14400` — request a 4-hour session (vault caps at 24 h)
- `--passphrase-file /etc/vettid/passphrase` — for CI / container installs

### 3. Owner approves (mobile app)

The phone surfaces an **Authorize Agent** screen with the identity card, a per-token scope picker (defaults match the agent's requested set), approval-mode radio, and a duration picker. The owner narrows scope/duration as needed and taps **Approve**.

### 4. Start the connector

```bash
vettid-agent start
```

Prompts for the same passphrase used at init.

### 5. Agent makes requests

```bash
# Via Unix socket (the default for ~/.vettid-agent)
curl --unix-socket ~/.vettid-agent/agent.sock \
  http://localhost/v1/secrets/request \
  -d '{"secret_name":"openai_api_key","purpose":"API call"}'

# Via WebSocket (TCP listener mode)
ws://127.0.0.1:7443/v1/ws?token=<session_token>
```

### 6. Status / extend / revoke

```bash
# Show the active session and seconds remaining
vettid-agent status

# Extend the session without restarting the daemon
curl --unix-socket ~/.vettid-agent/agent.sock \
  http://localhost/v1/pair/extend -X POST

# Offline extend (stops the daemon, then re-seals connection.enc)
vettid-agent extend

# Disconnect and wipe local credentials
vettid-agent revoke
```

`POST /v1/pair/extend` is the load-bearing path for long-running agents: it triggers an `agent.request-session` round-trip, blocks until the owner re-approves on their phone, then **hot-rotates the in-memory session key** and re-seals `connection.enc` — the running daemon keeps serving without a restart.

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
| `vettid-agent init <invite-code>` | Register with a vault (12-char code from the mobile app) |
| `vettid-agent start` | Start connector and local API |
| `vettid-agent status` | Show pairing + session expiry |
| `vettid-agent extend` | Renew session offline (rewrites `connection.enc`) |
| `vettid-agent rebind` | Re-bind credentials after hardware changes |
| `vettid-agent revoke` | Disconnect and wipe local credentials |
| `vettid-agent version` | Show version and binary fingerprint |

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/secrets/request` | POST | Request a secret from the vault |
| `/v1/secrets/use` | POST | Use a secret in-enclave (sign/HTTP request) without exposing the value |
| `/v1/secrets` | GET | List catalog entries (metadata only) |
| `/v1/secrets/refresh` | POST | Request a catalog refresh from the vault |
| `/v1/status` | GET | Check connector health + active session |
| `/v1/requests/{id}` | GET | Poll pending request status |
| `/v1/messages/send` | POST | Send a message or approval request to the owner |
| `/v1/pair/extend` | POST | Renew the active session via owner approval (hot-rotates the in-memory key) |
| `/v1/connection/disconnect` | POST | Disconnect from vault |
| `/v1/ws` | WebSocket | Full-duplex for browser agents |

## Security Model

- **Zero-trust for the agent** — Never holds keys or NATS credentials
- **Platform binding** — Credentials encrypted with passphrase + machine fingerprint
- **E2E encryption** — All vault communication encrypted with connection-specific keys
- **Owner sovereignty** — Vault owner controls all permissions via mobile app
- **No secret caching** — Secrets pass through, never stored

See [docs/vettid-agent-connector-design.md](docs/vettid-agent-connector-design.md) for the full design document.

## Related Repositories

- [vettid-dev](https://github.com/vettid/vettid-dev) - Backend infrastructure
- [vettid-android](https://github.com/vettid/vettid-android) - Android app
- [vettid-ios](https://github.com/vettid/vettid-ios) - iOS app
- [vettid-desktop](https://github.com/vettid/vettid-desktop) - Desktop app (Tauri/Rust/Svelte)
- [vettid-service-vault](https://github.com/vettid/vettid-service-vault) - Service integration layer

## License

[AGPL-3.0](LICENSE)
