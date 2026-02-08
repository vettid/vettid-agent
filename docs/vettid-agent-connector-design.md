# VettID Agent Connector — Design Document

**Version:** 1.0
**Date:** 2026-02-08
**Status:** Final

---

## 1. Overview

The VettID Agent Connector is a lightweight, standalone program that enables AI agents to securely request secrets and data from a VettID owner's vault. It runs as a **sidecar process** alongside the AI agent, handling all cryptographic operations, NATS connectivity, and vault communication so the agent itself never touches keys or credentials.

### Design Principles

- **Zero-trust for the agent** — The AI agent never holds encryption keys, NATS credentials, or raw vault tokens. It only sees responses to approved requests via a local-only API.
- **Reuse existing infrastructure** — Leverages the same NATS MessageSpace, key exchange, and protean credential patterns already proven in VettID's user-to-user connection model.
- **Owner sovereignty** — The vault owner (via their mobile app) controls registration, permissions, and revocation. The agent cannot escalate its own access.
- **Simple deployment** — A single Go binary with a config file. No databases, no cloud dependencies on the agent side, no Service Vault infrastructure required.
- **Cost-effective** — No additional NATS infrastructure needed. Agent connections ride on the existing MessageSpace architecture.

---

## 2. Architecture

### Communication Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│  AGENT ENVIRONMENT (developer's machine, cloud VM, container, etc.) │
│                                                                     │
│  ┌──────────────┐    localhost     ┌────────────────────┐          │
│  │              │  (Unix socket    │                    │          │
│  │   AI Agent   │   or :7443)      │  Agent Connector   │          │
│  │  (any LLM)   │◄───────────────►│  (Go binary)       │          │
│  │              │  Simple REST     │                    │          │
│  └──────────────┘  or WebSocket    └────────┬───────────┘          │
│                                              │                      │
└──────────────────────────────────────────────┼──────────────────────┘
                                               │ TLS + Connection Keys
                                               │ (NATS client)
                                               ▼
┌──────────────────────────────────────────────────────────────────────┐
│  VETTID INFRASTRUCTURE                                              │
│                                                                      │
│  ┌──────────────────────┐         ┌──────────────────────────┐      │
│  │  ms.vettid.dev       │         │  os.vettid.dev           │      │
│  │  (MessageSpace NATS) │         │  (OwnerSpace NATS)       │      │
│  │                      │         │                          │      │
│  │  MessageSpace.{guid} │         │  OwnerSpace.{guid}       │      │
│  │  ├── forOwner  ◄─────┼─────── │  ├── forVault             │      │
│  │  └── ownerProfile    │         │  └── forApp ─────────────┼──┐   │
│  └──────────┬───────────┘         └────────────┬─────────────┘  │   │
│             │                                  │                │   │
│             │         ┌────────────────────┐   │                │   │
│             └────────►│  Owner's Vault     │◄──┘                │   │
│                       │  (Nitro Enclave)   │                    │   │
│                       │  - Decrypts req    │                    │   │
│                       │  - Checks policy   │                    │   │
│                       │  - Returns result  │                    │   │
│                       └────────────────────┘                    │   │
│                                                                 │   │
│  ┌──────────────────────────────────────────────────────────────┘   │
│  │                                                                  │
│  │  ┌──────────────────────┐                                       │
│  │  │  Owner's Mobile App  │                                       │
│  └─►│  - Approve/deny      │                                       │
│     │  - View audit log    │                                       │
│     │  - Revoke agents     │                                       │
│     └──────────────────────┘                                       │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Key Insight: Agents Are Connections

Rather than creating an entirely new registration model, we treat an AI agent connection as a **variant of a user-to-user connection** with one critical difference: the agent side is automated (the Connector) rather than a person with a mobile app. This means:

- The existing MessageSpace infrastructure handles message routing
- The existing key exchange protocol secures the channel
- The existing connection lifecycle (invite → accept → key exchange → communicate) applies
- The vault already knows how to receive and process messages from connections

The only new pieces are:
1. A connection **type** field distinguishing agents from humans
2. The Agent Connector binary itself (agent-side)
3. Agent-specific UI in the mobile app (owner-side)
4. An agent request/response message schema

---

## 3. Agent Registration Flow

Registration follows the existing VettID connection invitation pattern, adapted for agents. The flow is designed to be simple (a single command for the operator) while giving the owner full visibility and control — including defining the connection contract only after reviewing the agent's actual details.

### 3.1 Prerequisites

- Owner has a provisioned VettID vault with an active OwnerSpace and MessageSpace
- Owner has the VettID mobile app installed and authenticated
- Agent operator has downloaded the Agent Connector binary

### 3.2 One-Time Shortlink

To avoid requiring operators to type long URIs and tokens into remote terminals, the invitation is delivered as a **one-time shortlink** hosted on the existing VettID web application:

```
https://vettid.dev/a/K7x9Qm
```

**Shortlink properties:**

- **Code format:** 6-character alphanumeric (Base62: a-z, A-Z, 0-9), providing ~56 billion possible combinations
- **TTL:** 2 minutes from creation. The link is deleted after expiry regardless of use.
- **Single-use:** Consumed and deleted on first successful resolution. A second request returns 404.
- **No secrets in the URL:** The shortlink code is a lookup key only. The actual invite token and MessageSpace URI are delivered in the JSON response body over TLS.
- **Rate-limited:** The resolve endpoint enforces rate limits per source IP (see Section 3.3).

**Shortlink lifecycle:**

```
 Owner's App                    vettid.dev API                   Agent Operator
 ───────────                    ──────────────                   ──────────────

 1. App sends create_agent_invitation
    to vault via NATS
    │
 2. Vault creates connection +
    invitation records, returns
    details to app:
    {
      connection_id, invitation_id,
      invite_token, owner_guid,
      vault_public_key, expires_at
    }
    │
 3. App calls POST /vault/agent/shortlink
    (authenticated with Cognito JWT):
    {
      owner_guid, invitation_id,
      invite_token, messagespace_uri,
      vault_public_key
    }
    │
 4. Lambda validates JWT, checks
    owner_guid matches caller,
    creates 2-min shortlink in DynamoDB
    │
 5. Returns to app:
    { code, url, expires_at }
    │
 6. App displays shortlink as:
    - Copyable text string
    - QR code (for local device use)
    │
 7. 2-minute countdown shown in app
    │                                                            6. Operator runs:
    │                                                               $ vettid-agent init vettid.dev/a/K7x9Qm
    │                                                               │
    │                                    7. GET /a/K7x9Qm          │
    │                                       (TLS, rate-limited)  ◄──┘
    │                                       │
    │                                    8. Validate:
    │                                       - Code exists?
    │                                       - TTL not expired?
    │                                       - Not already consumed?
    │                                       │
    │                                    9. Return payload (once):
    │                                       {
    │                                         "messagespace_uri":
    │                                           "nats://ms.vettid.dev:4222",
    │                                         "invite_token": "<256-bit>",
    │                                         "invitation_id": "<uuid>"
    │                                       }
    │                                       │
    │                                   10. Delete shortlink
    │                                       immediately
```

**Shortlink resolution endpoint:**

```
GET https://vettid.dev/a/{code}
Accept: application/json

Success (200, first call only):
{
  "messagespace_uri": "nats://ms.vettid.dev:4222",
  "invite_token": "<256-bit-base64url>",
  "invitation_id": "<uuid>"
}

Already consumed or expired (404):
{ "error": "not_found" }

Rate limited (429):
{ "error": "rate_limited", "retry_after_seconds": 30 }
```

### 3.3 Shortlink Anti-Scan Protection

With a 2-minute TTL and 6-character Base62 codes, brute-force scanning must be rendered impractical:

**Rate limiting (per source IP):**
- 5 requests per 30-second window to the `/a/` endpoint
- After 10 failed attempts (404s) within 5 minutes: block IP for 15 minutes
- Escalating blocks on repeated violations (15 min → 1 hour → 24 hours)

**Math on brute force:**
- 62^6 = ~56.8 billion possible codes
- At 5 requests/30s = 10 requests/minute per IP
- At any given moment, likely only 0-2 active shortlinks exist
- Probability of hitting a valid code in one attempt: ~1 in 28 billion
- Even with a botnet of 1,000 IPs: 10,000 req/min = ~5.3 million years to exhaust the space

**Additional measures:**
- Shortlink codes are generated using cryptographically secure randomness (not sequential)
- Failed resolution attempts are logged with source IP for monitoring
- Anomalous traffic patterns (many 404s from one IP range) trigger alerts
- Shortlink storage is ephemeral (in-memory cache like Redis with TTL, not persistent DB) — nothing to exfiltrate

### 3.4 Step-by-Step Registration Flow

```
 Owner (Mobile App)                    Agent Operator (CLI/Terminal)
 ──────────────────                    ────────────────────────────

 1. Owner taps "Connect Agent"
    in the VettID app
    │
 2. App sends request to vault
    via OwnerSpace.forVault:
    {
      type: "create_agent_invitation",
      ttl_seconds: 120
    }
    │
 3. Vault generates:
    - One-time invitation token (256-bit)
    - Invitation ID (for tracking)
    │
 4. App receives invitation details from vault
    and calls POST /vault/agent/shortlink
    (authenticated) to create shortlink
    │
 5. App displays to owner:
    ┌─────────────────────────────────┐
    │  Agent Invitation               │
    │                                 │
    │  vettid.dev/a/K7x9Qm           │
    │  [Copy]                         │
    │                                 │
    │  ┌─────────┐                    │
    │  │ QR Code │  (same link)       │
    │  └─────────┘                    │
    │                                 │
    │  ⏱ Expires in 1:47             │
    │                                 │
    │  [Cancel Invitation]            │
    └─────────────────────────────────┘
    │
    │                                    6. Operator installs connector
    │                                       and runs:
    │                                       $ vettid-agent init vettid.dev/a/K7x9Qm
    │                                       │
    │                                    7. Connector:
    │                                       a. Resolves shortlink → gets
    │                                          MessageSpace URI + invite token
    │                                          (shortlink consumed/deleted)
    │                                       b. Connects to ms.vettid.dev
    │                                          using invite token (TLS)
    │                                       c. Retrieves owner's public profile
    │                                          (includes owner public key)
    │                                       d. Generates X25519 keypair
    │                                          for this connection
    │                                       e. Collects registration details:
    │                                          - Agent type (interactive prompt
    │                                            or --type flag)
    │                                          - IP address (auto-detected)
    │                                          - Hostname
    │                                          - OS / platform
    │                                          - Binary fingerprint (SHA-256)
    │                                          - Machine fingerprint (HMAC-SHA256
    │                                            of hostname, machine-id, CPU,
    │                                            disk serial, MAC — see 3.6)
    │                                       f. Sends to owner's MessageSpace
    │                                          (encrypted with owner's public key):
    │                                          {
    │                                            type: "agent_connection_request",
    │                                            invitation_id: "<uuid>",
    │                                            agent_public_key: "<x25519_pub>",
    │                                            registration: {
    │                                              agent_type: "coding_assistant",
    │                                              ip_address: "203.0.113.42",
    │                                              hostname: "dev-server-01",
    │                                              platform: "linux/amd64",
    │                                              binary_fingerprint: "a7b3...f2d1",
    │                                              machine_fingerprint: "e4f8...b7c3"
    │                                            },
    │                                            timestamp: "<iso8601>"
    │                                          }
    │                                       g. Prints:
    │                                          "⏳ Waiting for owner approval..."
    │                                       h. Writes pending state to:
    │                                          ~/.vettid-agent/pending.json
    │
 8. Vault receives request via
    MessageSpace.forOwner
    │
 9. Vault forwards to app via
    OwnerSpace.forApp
    │
10. Owner receives push notification:
    "New agent connection pending"
    │
11. Owner reviews agent details:
    ┌─────────────────────────────────┐
    │  Agent Connection Request       │
    │                                 │
    │  Type: coding_assistant         │
    │  IP:   203.0.113.42             │
    │  Host: dev-server-01            │
    │  OS:   linux/amd64              │
    │  Fingerprint: a7b3...f2d1       │
    │  Machine:     e4f8...b7c3       │
    │                                 │
    │  ─── Connection Contract ───    │
    │                                 │
    │  Name this agent:               │
    │  [Claude Code Assistant     ]   │
    │                                 │
    │  Secret access:                 │
    │  ☑ API Keys                     │
    │  ☑ SSH Keys                     │
    │  ☐ Database Credentials         │
    │  ☐ Payment/Financial            │
    │                                 │
    │  Approval mode:                 │
    │  ○ Always ask me                │
    │  ● Auto-approve within contract │
    │  ○ Auto-approve all             │
    │                                 │
    │  Rate limit:                    │
    │  [60] requests per [hour  ▼]    │
    │                                 │
    │  [Approve & Connect]   [Deny]   │
    └─────────────────────────────────┘
    │
12. Owner taps "Approve & Connect"
    │
13. App sends to vault via
    OwnerSpace.forVault:
    {
      type: "approve_agent_connection",
      invitation_id: "<uuid>",
      contract: {
        agent_name: "Claude Code Assistant",
        scope: ["api_keys", "ssh_keys"],
        approval_mode: "auto_within_contract",
        rate_limit: { max: 60, per: "hour" }
      }
    }
    │
14. Vault performs key exchange:
    a. Generates connection-specific
       symmetric key (ChaCha20-Poly1305)
    b. Creates unique connection KeyID
    c. Encrypts connection key with
       agent's X25519 public key
    d. Stores connection metadata +
       contract in local NATS datastore:
       - agent name, type, public key, KeyID
       - registration details (IP, host, etc.)
       - contract (scope, approval mode, rate limit)
       - connection status: ACTIVE
       - creation timestamp
    e. Generates scoped MessageSpace
       token for the agent (write to
       forOwner, read responses)
    │
15. Vault sends to MessageSpace
    (encrypted with agent's public key):
    {
      type: "agent_connection_approved",
      connection_id: "<uuid>",
      connection_key_encrypted: "<key>",
      key_id: "<connection_key_id>",
      messagespace_token: "<scoped_token>",
      token_expires: "<iso8601>",
      contract: {
        scope: ["api_keys", "ssh_keys"],
        approval_mode: "auto_within_contract",
        rate_limit: { max: 60, per: "hour" }
      }
    }
    │
    │                                   16. Connector receives approval:
    │                                       a. Decrypts connection key with
    │                                          its private key
    │                                       b. Prompts for encryption passphrase:
    │                                          "Set passphrase for credential
    │                                           storage: ********"
    │                                       c. Stores credentials in encrypted
    │                                          local config:
    │                                          ~/.vettid-agent/connection.enc
    │                                          (Argon2id + ChaCha20)
    │                                       d. Establishes persistent NATS
    │                                          connection to ms.vettid.dev
    │                                       e. Starts local API listener
    │                                       f. Prints confirmation:
    │                                          "✓ Connected: Claude Code Assistant
    │                                           Vault owner: Jane D.
    │                                           Scope: api_keys, ssh_keys
    │                                           Approval: auto within contract
    │                                           Rate limit: 60/hour
    │                                           Local API: ~/.vettid-agent/agent.sock
    │                                           WebSocket: ws://127.0.0.1:7443/v1/ws
    │                                           WS Token:  vt_ws_a8Kx2mNp"

 REGISTRATION COMPLETE
 ─────────────────────
 The Agent Connector is now running and the AI agent
 can make requests via the local API.
```

### 3.5 Invitation Token Security

- Token is a 256-bit random value, Base64URL encoded
- Delivered only via the one-time shortlink over TLS (never in the URL itself)
- Single-use: consumed on first NATS connection attempt
- Bound to the specific invitation_id
- If unused, automatically expires when the shortlink TTL (2 minutes) elapses
- The vault tracks invitation state and rejects reuse even if the token were somehow replayed

### 3.6 Agent Fingerprinting

During registration, the Connector collects two distinct fingerprints that are sent to the vault and displayed to the owner for verification:

#### Binary Fingerprint

A SHA-256 hash of the Agent Connector binary itself:

```
binary_fingerprint = SHA256(agent_connector_binary)
```

This identifies the **software version** running on the agent side:
- The owner can verify it against published release hashes from VettID
- If the binary is updated (new version installed), the fingerprint changes and the vault notifies the owner on the next key rotation or health check
- A fingerprint mismatch without a corresponding version release is a tampering indicator

#### Machine Fingerprint

A composite hash of the machine's hardware and identity attributes:

```
machine_fingerprint = HMAC-SHA256(
  key: "vettid-agent-platform-v1",
  data: canonical_sort_and_join([
    "hostname:"   + hostname,
    "machine_id:" + machine_id,
    "cpu:"        + cpu_identifier,
    "disk:"       + root_disk_serial,
    "mac:"        + primary_mac_address
  ])
)
```

This identifies the **specific machine** where the Connector is installed:
- The owner sees a summary (hostname, IP, OS) during approval and the full hash is recorded in the vault
- If the Connector's credentials are copied to a different machine, the machine fingerprint won't match — and the credentials themselves are undecryptable because the platform key (derived from the same attributes) is mixed into the encryption key (see Section 9.5 for full details)
- Significant machine changes (3+ attributes differ) trigger an owner notification
- Minor changes (1 attribute, e.g., hostname rename) are handled by 4-of-5 tolerance with automatic re-derivation

#### What the vault stores at registration

```json
{
  "connection_id": "<uuid>",
  "agent_name": "Claude Code Assistant",
  "agent_type": "coding_assistant",
  "binary_fingerprint": "a7b3c1...f2d1",
  "machine_fingerprint": "e4f8a2...b7c3",
  "registration": {
    "ip_address": "203.0.113.42",
    "hostname": "dev-server-01",
    "platform": "linux/amd64"
  },
  "contract": { ... },
  "status": "ACTIVE",
  "created_at": "2026-02-08T16:00:00Z"
}
```

Both fingerprints are checked periodically during key rotation. A mismatch in either triggers an owner alert and can optionally auto-suspend the connection (configurable in the connection contract).

---

## 4. Agent Connector Program

### 4.1 Technology Choice

**Language:** Go (matches vettid-service-vault, excellent for single-binary distribution)

**Dependencies:**
- `nats.go` — NATS client library
- `golang.org/x/crypto` — X25519, ChaCha20-Poly1305, Argon2id
- `gorilla/websocket` — WebSocket server for browser-based agents
- Standard library for HTTP/Unix socket server

**Distribution:** Single static binary per platform (Linux amd64/arm64, macOS, Windows)

### 4.2 Directory Structure

```
~/.vettid-agent/
├── connection.enc          # Encrypted connection credentials
│                           # (connection key, KeyID, agent private key,
│                           #  MessageSpace token, vault public key)
├── config.toml             # Non-sensitive config (API listen address,
│                           #  log level, NATS endpoint)
├── agent.log               # Encrypted audit log of all requests
└── connector.lock          # PID lockfile (single instance)
```

### 4.3 Credential Encryption at Rest

All sensitive material in `connection.enc` is encrypted using:

```
passphrase + platform_key → Argon2id(passphrase || platform_key, salt) → 256-bit key → ChaCha20-Poly1305
```

The platform key is derived from machine-specific attributes (hostname, machine-id, CPU, disk serial, MAC address), binding the credentials to the specific machine where they were created. See Section 3.6 for fingerprint details and Section 9.5 for the full platform binding design.

The passphrase is provided at startup:
```bash
$ vettid-agent start --passphrase-file /run/secrets/vettid
# OR
$ VETTID_AGENT_PASSPHRASE=<passphrase> vettid-agent start
# OR interactive prompt
$ vettid-agent start
Enter passphrase: ********
```

For containerized deployments, the passphrase can come from a Kubernetes secret, Docker secret, or environment variable.

### 4.4 Local API

The Connector exposes a local-only API. **No external network access.**

**Default:** Unix socket at `~/.vettid-agent/agent.sock`
**Optional:** TCP on `127.0.0.1:7443` (localhost only, with mTLS option)

#### API Endpoints

```
POST /v1/secrets/request
  Request a secret from the owner's vault.

  Request Body:
  {
    "secret_type": "api_key",          // Category from approved scope
    "secret_name": "openai_api_key",   // Specific secret identifier
    "purpose": "Making API call to...",// Human-readable justification
    "ttl": 300,                        // Requested time-to-live (seconds)
    "action": "retrieve"               // "retrieve" | "use"
  }

  Response (if auto-approved by vault policy):
  {
    "status": "approved",
    "secret_value": "<decrypted_value>",  // Only if action=retrieve
    "expires_at": "2026-02-08T17:05:00Z",
    "request_id": "<uuid>"
  }

  Response (if requires owner approval):
  {
    "status": "pending_approval",
    "request_id": "<uuid>",
    "message": "Waiting for owner approval"
  }

  Response (if denied):
  {
    "status": "denied",
    "reason": "Secret not in approved scope"
  }

---

POST /v1/secrets/action
  Ask the vault to perform an action using a secret,
  without revealing the secret to the agent.

  Request Body:
  {
    "secret_type": "api_key",
    "secret_name": "stripe_api_key",
    "action": "http_request",
    "action_params": {
      "method": "POST",
      "url": "https://api.stripe.com/v1/charges",
      "headers": { "Content-Type": "application/x-www-form-urlencoded" },
      "body": "amount=2000&currency=usd"
    }
  }

  Response:
  {
    "status": "completed",
    "result": {
      "status_code": 200,
      "body": { ... }
    },
    "request_id": "<uuid>"
  }

  NOTE: The vault injects the secret (e.g., as a Bearer token)
  into the request and makes the call from within the enclave.
  The agent sees the result but never the key itself.

---

GET /v1/status
  Check connector health and connection state.

  Response:
  {
    "connected": true,
    "vault_name": "Jane's Vault",
    "connection_id": "abc123",
    "scope": ["api_keys", "ssh_keys"],
    "uptime_seconds": 3600,
    "last_key_rotation": "2026-02-08T12:00:00Z"
  }

---

GET /v1/requests/{request_id}
  Poll the status of a pending request.

  Response:
  {
    "status": "approved",          // "pending" | "approved" | "denied" | "expired"
    "secret_value": "<value>",     // Present only when approved + action=retrieve
    "resolved_at": "2026-02-08T16:01:30Z"
  }

---

POST /v1/connection/disconnect
  Cleanly disconnect from the vault. Notifies the vault,
  invalidates local credentials, cleans up.

---

WebSocket: ws://127.0.0.1:7443/v1/ws?token=<session_token>
  Full-duplex connection for browser-based agents.
  Uses the same request/response schema as REST endpoints
  wrapped in JSON-RPC style messages (see Section 9.4).

  Session token is generated at Connector startup and
  displayed in the terminal output. Regenerated on restart.

---

POST /v1/agents/send  (Phase 3+)
  Send a message to another agent connected to the same vault.
  Requires agent_comms permission in the connection contract
  and the target agent must be an approved peer.

  Request Body:
  {
    "to": "<target_agent_connection_id>",
    "payload": { ... },
    "correlation_id": "optional_thread_id"
  }

  Response:
  {
    "status": "delivered",
    "message_id": "<uuid>",
    "timestamp": "2026-02-08T16:05:00Z"
  }

---

GET /v1/agents/messages  (Phase 3+)
  Retrieve messages from other agents (polling).
  For WebSocket connections, messages are pushed automatically.

  Query params: ?since=<iso8601>&limit=50

  Response:
  {
    "messages": [
      {
        "message_id": "<uuid>",
        "from": "<sender_connection_id>",
        "from_name": "Data Pipeline Agent",
        "payload": { ... },
        "correlation_id": "thread_123",
        "timestamp": "2026-02-08T16:04:55Z"
      }
    ]
  }
```

### 4.5 Message Flow: Secret Request

```
AI Agent                Connector              NATS MessageSpace        Vault                  App
   │                       │                        │                     │                     │
   │ POST /v1/secrets/     │                        │                     │                     │
   │   request             │                        │                     │                     │
   │──────────────────────►│                        │                     │                     │
   │                       │                        │                     │                     │
   │                       │ Encrypt request with   │                     │                     │
   │                       │ connection key (KeyID)  │                     │                     │
   │                       │                        │                     │                     │
   │                       │ Publish to             │                     │                     │
   │                       │ MS.{guid}.forOwner     │                     │                     │
   │                       │───────────────────────►│                     │                     │
   │                       │                        │                     │                     │
   │                       │                        │ Vault subscribes    │                     │
   │                       │                        │────────────────────►│                     │
   │                       │                        │                     │                     │
   │                       │                        │                     │ Decrypt with        │
   │                       │                        │                     │ connection key      │
   │                       │                        │                     │                     │
   │                       │                        │                     │ Check policy:       │
   │                       │                        │                     │ - In scope?         │
   │                       │                        │                     │ - Auto-approve?     │
   │                       │                        │                     │ - Rate limit ok?    │
   │                       │                        │                     │                     │
   │                       │                        │                     │ IF auto-approve:    │
   │                       │                        │                     │   Fetch secret      │
   │                       │                        │                     │   Encrypt response  │
   │                       │                        │                     │                     │
   │                       │                        │                     │ IF needs approval:  │
   │                       │                        │                     │──────────────────► │
   │                       │                        │                     │  Push notification  │
   │                       │                        │                     │  "Agent requests    │
   │                       │                        │                     │   openai_api_key"   │
   │                       │                        │                     │                     │
   │                       │                        │                     │◄──────────────────  │
   │                       │                        │                     │  Owner approves     │
   │                       │                        │                     │                     │
   │                       │        Response msg    │                     │                     │
   │                       │◄───────────────────────┼─────────────────────│                     │
   │                       │                        │                     │                     │
   │                       │ Decrypt with           │                     │                     │
   │                       │ connection key         │                     │                     │
   │                       │                        │                     │                     │
   │  200 OK               │                        │                     │                     │
   │  { secret_value: ... }│                        │                     │                     │
   │◄──────────────────────│                        │                     │                     │
```

### 4.6 Key Rotation

The Connector participates in VettID's standard connection key rotation:

1. **Vault initiates rotation** — Sends a `key_rotation_initiate` message via MessageSpace with a new symmetric key, encrypted with the agent's X25519 public key
2. **Connector acknowledges** — Decrypts the new key, stores it, sends acknowledgement
3. **Cutover** — Both sides switch to the new key. Old key retained briefly for in-flight messages
4. **MessageSpace token refresh** — Vault issues a new scoped NATS token alongside key rotation

This follows the same periodic rotation cadence as user-to-user connections.

### 4.7 Local Audit Log

Every request through the Connector is logged to `agent.log` (encrypted with the connection key):

```json
{
  "timestamp": "2026-02-08T16:00:00Z",
  "request_id": "uuid",
  "action": "retrieve",
  "secret_type": "api_key",
  "secret_name": "openai_api_key",
  "status": "approved",
  "approval_type": "auto",
  "response_time_ms": 145
}
```

The vault also maintains its own audit log (three-layer audit as designed), giving both the agent operator and the vault owner independent records.

---

## 5. Security Analysis

### 5.1 Threat Model

| Threat | Mitigation |
|--------|------------|
| **Agent process compromised** | Agent never holds keys or NATS creds. Attacker can only make requests through the local API, which are subject to vault policy and rate limits. |
| **Connector process compromised** | Connection keys are encrypted at rest with Argon2id-derived key. In-memory keys are at risk, but the vault's per-request policy still governs what can be accessed. Owner can revoke instantly. |
| **Connector binary tampered** | Binary fingerprint mismatch detected on next key rotation or health check. Owner notified. Connection can be auto-suspended. |
| **Credentials stolen (file copy)** | Credentials encrypted with passphrase + platform key derived from machine fingerprint. Undecryptable on a different machine. Significant machine fingerprint mismatch (3+ attributes) triggers owner alert. |
| **Network interception (NATS)** | All messages encrypted with connection-specific ChaCha20-Poly1305 keys before hitting NATS. TLS on the NATS transport provides defense in depth. |
| **Shortlink code scanning** | 62^6 = ~56.8 billion codes, 2-minute TTL, single-use, rate-limited (5 req/30s per IP), escalating IP blocks. Even 1,000 IPs scanning continuously: ~5.3 million years to find one active code. See Section 3.3 for full analysis. |
| **Invitation token stolen** | Token is never in the URL — delivered over TLS in the shortlink response body. Shortlink is single-use with 2-minute TTL. Even with the token, owner must still explicitly approve after reviewing agent details. |
| **Replay attacks** | Each message includes a monotonic sequence number and timestamp. Vault rejects replayed messages. |
| **Agent impersonation** | Without the connection private key, an attacker cannot decrypt vault responses or encrypt valid requests. The KeyID is not exposed outside the connection. |
| **Owner's vault compromised** | Secrets are decrypted only inside the Nitro Enclave. Even a compromised vault host cannot access plaintext secrets. |

### 5.2 What the Agent Connector Does NOT Do

- **Does not store secrets** — Secrets pass through to the agent and are not cached
- **Does not make policy decisions** — All policy enforcement happens in the vault
- **Does not have admin access** — Cannot modify its own scope or permissions
- **Does not communicate with other agents directly** — Agent-to-agent messaging (Phase 3+) is mediated entirely by the vault; Connectors never connect to each other
- **Does not expose a public network interface** — Local-only API and WebSocket

### 5.3 Comparison to Service Vault Model

| Aspect | Service Vault | Agent Connector |
|--------|--------------|-----------------|
| **Deployment** | Full Go service with its own NATS, TLS certs, cloud hosting | Single binary, runs locally |
| **Cost** | Server hosting, TLS certs, monitoring | Zero — runs alongside the agent |
| **Complexity** | Organization-grade: manages many users | Single connection to one vault |
| **Security model** | Mutual TLS + NATS auth + encrypted messaging | Connection keys + local-only API + encrypted messaging |
| **Best for** | Businesses integrating with many VettID users | Individual owner granting access to their AI agents |
| **Scalability** | Handles thousands of connections | One agent ↔ one vault |

---

## 6. Implementation Plan

### Phase 1: Core Connector (MVP)

**Goal:** Agent can register, connect, and retrieve secrets via local API or WebSocket.

**Deliverables:**
1. `vettid-agent` Go binary with subcommands:
   - `init <shortlink>` — Resolve shortlink, register, and wait for approval
   - `start` — Start connector and local API
   - `status` — Check connection health
   - `revoke` — Self-disconnect and clean up
2. Local API: `/v1/secrets/request` (retrieve only), `/v1/status`
3. WebSocket endpoint: `ws://localhost:7443/v1/ws` with session token auth
4. Encrypted credential storage (Argon2id + ChaCha20) with platform key binding
5. Machine fingerprint collection and platform key derivation
6. NATS MessageSpace integration (publish requests, subscribe to responses)
7. Connection key exchange during registration
8. Shortlink creation via authenticated Lambda endpoint (POST /vault/agent/shortlink)
   called by mobile app after receiving invitation details from vault-manager.
   Resolution via public rate-limited endpoint (GET /vault/agent/shortlink/{code}).
   - DynamoDB storage with 2-minute TTL, single-use consumption
   - Rate limiting and IP-based escalating blocks on resolve endpoint
9. Mobile app: "Connect Agent" UI (invitation + shortlink generation, agent review screen, connection contract editor)
10. Vault: Agent connection message handlers (register, approve with contract, request, respond)

**Estimated effort:** 4-5 weeks

### Phase 2: Action Execution

**Goal:** Vault can execute actions using secrets on behalf of the agent.

**Deliverables:**
1. `/v1/secrets/action` endpoint — Agent describes an action, vault executes it
2. Vault-side action executor (HTTP requests, API calls within the enclave)
3. Action result sanitization (strip sensitive headers/tokens from responses)

**Estimated effort:** 2-3 weeks

### Phase 3: Agent-to-Agent + Hardening

**Goal:** Production-ready security, reliability, and agent-to-agent communication.

**Deliverables:**
1. Agent-to-agent messaging via vault mediation (`/v1/agents/send`, `/v1/agents/messages`)
2. Per-pair approval, rate limiting, daily volume caps, auto-suspend
3. Agent-to-agent audit trail with full payload storage and owner inspection UI
4. Mobile app: Agent communication permission UI, audit log viewer with payload inspector and message threading
5. Key rotation integration (periodic re-keying with vault)
6. Binary fingerprint verification on rotation
7. Rate limiting on local API
8. Reconnection logic (NATS disconnect handling, exponential backoff)
9. Audit log encryption and rotation
10. Graceful shutdown with in-flight request completion
11. Systemd/launchd service definitions for daemon mode
12. `vettid-agent rebind` command for machine fingerprint recovery

**Estimated effort:** 4-5 weeks

### Phase 4: Developer Experience

**Goal:** Easy adoption for agent developers.

**Deliverables:**
1. SDK/client libraries (Python, TypeScript, Go) for the local REST API and WebSocket
2. Docker image with connector pre-installed and platform key file support
3. Example integrations (Claude Code, LangChain, browser-based agents)
4. Documentation and quickstart guide
5. Kubernetes deployment manifests with pod identity integration

**Estimated effort:** 2-3 weeks

---

## 7. Configuration Reference

### config.toml

```toml
# VettID Agent Connector Configuration

[api]
# Local API listen address
# Options: "unix:///home/user/.vettid-agent/agent.sock" or "tcp://127.0.0.1:7443"
listen = "unix:///home/user/.vettid-agent/agent.sock"

# Enable mTLS for TCP mode (recommended if not using Unix socket)
mtls_enabled = false
# mtls_cert = "/path/to/agent-client.crt"
# mtls_key = "/path/to/agent-client.key"

[websocket]
# WebSocket endpoint for browser-based agents
enabled = true
listen = "127.0.0.1:7443"

# Origin validation (comma-separated allowed origins, or "*" for any localhost)
allowed_origins = "localhost,127.0.0.1"

[nats]
# MessageSpace server (set during registration)
messagespace_url = "nats://ms.vettid.dev:4222"

# TLS for NATS connection
tls_enabled = true

# Reconnect settings
max_reconnect_attempts = -1    # infinite
reconnect_wait_seconds = 2
max_reconnect_wait_seconds = 60

[security]
# Credential encryption
argon2_time = 3
argon2_memory_kb = 65536
argon2_threads = 4

# Request timeout (waiting for vault response)
request_timeout_seconds = 30

# Pending approval timeout (waiting for owner)
approval_timeout_seconds = 300

[logging]
level = "info"                 # debug | info | warn | error
encrypt_logs = true
max_log_size_mb = 50
max_log_files = 5
```

---

## 8. CLI Reference

```
vettid-agent — VettID Agent Connector

USAGE:
  vettid-agent <command> [options]

COMMANDS:
  init        Register with a vault using a shortlink
  start       Start the connector and local API
  status      Show connection status and health
  rebind      Re-bind credentials to current machine after hardware changes
  revoke      Disconnect from vault and clean up credentials
  version     Show version and binary fingerprint

INIT:
  vettid-agent init <shortlink> [--type <agent_type>] [--config-dir <path>]

  Resolves the one-time shortlink, connects to the owner's
  MessageSpace, performs key exchange, sends registration details,
  and waits for owner approval. On approval, prompts for an
  encryption passphrase and writes encrypted credentials.

  Arguments:
    <shortlink>            Shortlink from vault owner
                           (e.g., vettid.dev/a/K7x9Qm)

  Options:
    --type <agent_type>    Agent type (default: interactive prompt)
                           Options: coding_assistant, data_pipeline,
                           automation, monitoring, custom
    --config-dir <path>    Config directory (default: ~/.vettid-agent)
    --timeout <seconds>    Approval wait timeout (default: 300)

  Examples:
    $ vettid-agent init vettid.dev/a/K7x9Qm
    $ vettid-agent init vettid.dev/a/K7x9Qm --type coding_assistant

START:
  vettid-agent start [--passphrase-file <path>] [--daemon]

  Starts the connector. Decrypts credentials, connects to NATS,
  and begins serving the local API and WebSocket endpoint.

  Options:
    --passphrase-file <path>      Read passphrase from file
    --platform-key-file <path>    Platform key file for containers/VMs
                                  (replaces machine fingerprint)
    --daemon                      Run in background
    --config-dir <path>           Config directory (default: ~/.vettid-agent)

STATUS:
  vettid-agent status [--json]

  Shows current connection state, scope, contract details,
  uptime, and last activity.

REBIND:
  vettid-agent rebind [--config-dir <path>]

  Re-derives the platform key from the current machine's
  attributes and re-encrypts credentials. Use after hardware
  changes (NIC replacement, hostname change, etc.) that cause
  normal startup to fail.

  Requires passphrase and a live connection to the vault
  for re-verification. The vault is notified of the fingerprint
  change and the owner receives an alert.

REVOKE:
  vettid-agent revoke [--confirm]

  Sends disconnect notification to vault, invalidates local
  credentials, and removes encrypted config files.
```

---

## 9. Design Decisions (Resolved)

### 9.1 Multiple Vaults Per Agent — NO

**Decision:** One Connector connects to exactly one vault. Period.

**Rationale:**
- There is no concept of team vaults in VettID today — vaults are personal
- Allowing multi-vault access from a single agent creates a cross-vault data leakage risk: an agent connected to Vault A and Vault B could inadvertently (or maliciously) use a secret from A in a context meant for B
- If an operator needs an agent to access two owners' vaults, they run two Connector instances with separate config directories:
  ```bash
  $ vettid-agent init vettid.dev/a/K7x9Qm --config-dir ~/.vettid-agent/personal
  $ vettid-agent init vettid.dev/a/Mx2pTn --config-dir ~/.vettid-agent/work
  ```
  Each instance gets its own socket/port, its own keys, its own audit log. No shared state.

### 9.2 Agent-to-Agent Communication — YES (Owner-Approved)

**Decision:** Allow agents connected to the same vault to communicate with each other, subject to explicit owner approval and full audit trail.

**How it works:**

The vault acts as a message broker between agents, never allowing direct agent-to-agent connections. This keeps the owner in control and ensures every message is logged.

```
Agent A (Connector A)                    Vault                         Agent B (Connector B)
       │                                   │                                  │
       │  1. Send message to Agent B       │                                  │
       │  via local API:                   │                                  │
       │  POST /v1/agents/send             │                                  │
       │  {                                │                                  │
       │    "to": "agent_b_connection_id", │                                  │
       │    "payload": { ... }             │                                  │
       │  }                                │                                  │
       │──────────────────────────────────►│                                  │
       │                                   │                                  │
       │                                   │  2. Vault checks:               │
       │                                   │  - A has agent_comms permission? │
       │                                   │  - B has agent_comms permission? │
       │                                   │  - A↔B pair approved by owner?   │
       │                                   │  - Message size within limits?   │
       │                                   │  - Rate limit ok?               │
       │                                   │                                  │
       │                                   │  3. Log the message in audit     │
       │                                   │  (sender, recipient, size,       │
       │                                   │   timestamp, full payload)       │
       │                                   │                                  │
       │                                   │  4. Forward to Agent B           │
       │                                   │──────────────────────────────────►│
       │                                   │                                  │
```

**Connection contract additions for agent-to-agent:**

```
Agent Communication:
☐ Allow this agent to communicate with other agents

If enabled:
  Approved peers:     [Agent B ▼] [Add peer]
  Message size limit: [4] KB per message
  Rate limit:         [10] messages per [minute ▼]
  Daily volume cap:   [1000] messages
```

**Data volume controls (addresses the concern about chatty agents):**

- **Per-message size limit:** Configurable, default 4 KB. Prevents agents from streaming large payloads through the vault.
- **Per-pair rate limit:** e.g., 10 messages/minute between Agent A and Agent B. Prevents feedback loops.
- **Daily volume cap:** Total messages per agent per day. Hard cutoff — agent gets a `429 volume_exceeded` response.
- **Owner alerts:** If any agent hits 80% of its daily cap, the owner gets a notification.
- **Auto-suspend:** If an agent-to-agent pair exceeds its rate limit 3 times in an hour, the pair is auto-suspended and the owner is notified.

**Audit trail requirements:**

Every agent-to-agent message generates an audit record containing:
- Sender connection ID and agent name
- Recipient connection ID and agent name
- Timestamp
- Message size (bytes)
- **Full payload content** — stored encrypted in the vault's local NATS datastore
- Payload hash (SHA-256 — for integrity verification)
- Delivery status (delivered, rejected, rate_limited)
- Policy evaluation result
- Correlation ID (if provided, for threading related messages)

**Owner payload visibility:**

The owner can inspect the full content of any agent-to-agent message through the mobile app. This is essential — agents act on the owner's behalf, and the owner must be able to verify what is being communicated. The audit viewer provides:

- **Message timeline:** Chronological view of all agent-to-agent messages, filterable by agent pair, date range, or keyword
- **Conversation threading:** Messages with the same `correlation_id` are grouped into threads for readability
- **Payload inspector:** Tap any message to see the full JSON payload, with syntax highlighting and collapsible nested objects
- **Export:** Download message history as JSON or CSV for external analysis
- **Alerts:** Configurable notifications for messages matching specific patterns (e.g., agent sharing credentials, unexpected data types, error responses)

**Storage and retention:**

- Payloads are encrypted at rest in the vault's local NATS datastore using the vault's storage encryption key
- Retention period is configurable by the owner (default: 30 days)
- Older records are pruned automatically but can be exported before deletion
- The per-message size limit (default 4 KB) keeps storage costs bounded — at 1,000 messages/day with 4 KB payloads, that's roughly 120 MB per month of raw audit data

The owner can review the full agent-to-agent audit log in the mobile app, including message frequency graphs, volume trends, and the ability to drill into any individual message.

**Why this is safe:**
- Agents never talk directly — the vault mediates every message
- Each agent-to-agent pair must be explicitly approved by the owner
- **Owner can see every payload** — full message content is stored and inspectable, not just metadata. The owner always knows exactly what their agents are saying to each other
- Volume controls prevent runaway communication
- Owner can revoke any agent's communication permission instantly

**Phase:** This is a Phase 3+ feature. The core connector MVP does not include agent-to-agent communication.

### 9.3 Offline/Cache Mode — NO

**Decision:** No caching of vault responses. If the network is down, requests fail.

**Rationale:** Caching secrets — even temporarily — fundamentally compromises the zero-storage security model. The whole point is that the agent environment never holds secrets longer than needed for a single operation. If the network is unreliable, the operator needs to fix their connectivity, not ask us to weaken the security boundary.

**Error response when disconnected:**
```json
{
  "status": "error",
  "error": "vault_unreachable",
  "message": "Cannot reach vault. Check network connectivity.",
  "retry_after_seconds": 5
}
```

### 9.4 Browser-Based Agent Support — Connector WebSocket Only

**Decision:** Support browser-based agents via a WebSocket endpoint on the locally-running Connector. No cloud relay, no browser extensions, no alternatives. If you can't install the Connector and connect to localhost, you can't use VettID agent connectivity.

**Rationale:** Every alternative (cloud WebSocket bridge, SSE, browser extensions) either introduces a new trust boundary, adds infrastructure cost, or weakens the security model. The Connector running locally *is* the security boundary — removing it removes the guarantee. The WebSocket endpoint is simply a second interface to the same Connector that's already running, with the same security properties as the REST API.

#### WebSocket API (Connector, localhost)

```
WebSocket: ws://127.0.0.1:7443/v1/ws

Authentication:
  The WebSocket connection requires a one-time connection token
  generated by the Connector at startup, displayed in the terminal:

  "✓ Connector running
   Local API:   localhost:7443
   WebSocket:   ws://localhost:7443/v1/ws
   WS Token:    vt_ws_a8Kx2mNp  (valid this session only)"

  The browser agent includes this token in the WebSocket
  handshake or first message:

  ws://127.0.0.1:7443/v1/ws?token=vt_ws_a8Kx2mNp

Message format (JSON over WebSocket):

  → Request (browser to connector):
  {
    "id": "req_001",
    "method": "secrets.request",
    "params": {
      "secret_type": "api_key",
      "secret_name": "openai_api_key",
      "purpose": "Making API call",
      "action": "retrieve"
    }
  }

  ← Response (connector to browser):
  {
    "id": "req_001",
    "result": {
      "status": "approved",
      "secret_value": "<value>",
      "expires_at": "2026-02-08T17:05:00Z"
    }
  }

  ← Push notification (connector to browser):
  {
    "id": null,
    "event": "connection.key_rotated",
    "data": { "new_key_id": "..." }
  }
```

**CORS / browser security considerations:**
- The WebSocket listener binds to `127.0.0.1` only (not `0.0.0.0`)
- Origin header validation: only accepts connections from known origins or `localhost`
- The session token (`vt_ws_*`) prevents other local processes from hijacking the WebSocket
- Token is regenerated on each Connector restart

**Browser agent integration example (JavaScript):**
```javascript
const ws = new WebSocket('ws://127.0.0.1:7443/v1/ws?token=vt_ws_a8Kx2mNp');

ws.onopen = () => {
  ws.send(JSON.stringify({
    id: 'req_001',
    method: 'secrets.request',
    params: {
      secret_type: 'api_key',
      secret_name: 'github_token',
      purpose: 'Fetching repository data',
      action: 'retrieve'
    }
  }));
};

ws.onmessage = (event) => {
  const response = JSON.parse(event.data);
  if (response.result?.status === 'approved') {
    // Use the secret for the intended operation
  }
};
```

### 9.5 Platform Binding — Machine Fingerprint + Platform Key

**Decision:** Bind the Connector's encrypted credentials to the specific machine where it was installed, so that copying `connection.enc` to another machine renders it undecryptable.

#### Approach: Composite Machine Fingerprint

During `vettid-agent init`, the Connector collects machine-specific attributes and derives a **platform key** that is mixed into the credential encryption process. The credentials are encrypted with:

```
encryption_key = Argon2id(passphrase || platform_key, salt)
```

Where `platform_key` is derived from:

```
platform_key = HMAC-SHA256(
  key: "vettid-agent-platform-v1",
  data: canonical_sort_and_join([
    "hostname:"  + hostname,
    "machine_id:" + machine_id,
    "cpu:"       + cpu_identifier,
    "disk:"      + root_disk_serial,
    "mac:"       + primary_mac_address
  ])
)
```

**Attribute sources by platform:**

| Attribute | Linux | macOS | Windows |
|-----------|-------|-------|---------|
| `hostname` | `/etc/hostname` | `scutil --get LocalHostName` | `%COMPUTERNAME%` |
| `machine_id` | `/etc/machine-id` | `IOPlatformUUID` via ioreg | `MachineGuid` from registry |
| `cpu_identifier` | `/proc/cpuinfo` model + stepping | `sysctl machdep.cpu.brand_string` | `PROCESSOR_IDENTIFIER` env |
| `root_disk_serial` | `lsblk --nodeps -o SERIAL` | `diskutil info /` | `wmic diskdrive get serialnumber` |
| `primary_mac_address` | First non-loopback from `/sys/class/net/` | `ifconfig en0` | `getmac /v` |

**How it prevents credential theft:**

1. Attacker copies `~/.vettid-agent/connection.enc` to another machine
2. Attacker knows (or cracks) the passphrase
3. Decryption still fails because `platform_key` on the new machine produces a different value
4. The attacker would need to replicate the exact hostname, machine-id, CPU, disk serial, and MAC address — which is effectively impossible for a different physical or virtual machine

**Resilience to minor system changes:**

A concern with machine fingerprinting is that routine changes (OS update, NIC replacement, hostname change) could lock the user out. To handle this:

- **Tolerance threshold:** During decryption, the Connector tries the full 5-attribute fingerprint first. If that fails, it tries combinations of 4-of-5 attributes. If any 4-of-5 combination succeeds, credentials are decrypted and the fingerprint is immediately re-derived and the credentials re-encrypted with the updated full fingerprint.
- **Manual recovery:** `vettid-agent rebind` command that prompts for the passphrase, connects to the vault to re-verify the connection, and re-encrypts credentials with the current machine's fingerprint.
- **The vault knows:** The machine fingerprint (hashed) is sent to the vault during registration. If the fingerprint changes significantly (fewer than 3-of-5 match), the vault can flag it and notify the owner.

**For containerized/cloud environments:**

Containers and VMs have less stable machine identities. For these environments:

- **Kubernetes:** Use the Kubernetes-provided pod identity + node name + a mounted secret as the platform key source
- **Docker:** Bind-mount a host-generated key file into the container: `-v /etc/vettid-machine-key:/run/vettid-key:ro`
- **Cloud VMs (EC2, GCE):** Use instance identity document + instance ID as additional fingerprint attributes
- **Fallback:** If fewer than 3 attributes are available (e.g., minimal container), the Connector requires a `--platform-key-file` flag pointing to a file that provides the missing entropy. This file should be stored outside the container's filesystem (mounted secret, host volume, etc.)

```bash
# Containerized deployment
$ vettid-agent start \
    --passphrase-file /run/secrets/vettid-passphrase \
    --platform-key-file /run/secrets/vettid-platform-key
```

**Future enhancement:** For environments that support it (AWS Nitro, machines with TPM 2.0), the platform key can optionally be derived from hardware attestation. This upgrades the binding from "same machine attributes" to "cryptographic proof of specific hardware." This is an additive enhancement — the machine fingerprint approach works everywhere, and TPM/enclave binding layers on top for higher assurance.

---

## 10. Design Decisions Summary

| Question | Decision | Rationale |
|----------|----------|-----------|
| Multiple vaults per agent? | **No** — 1:1 only | No team vaults in VettID; prevents cross-vault leakage; run multiple instances if needed |
| Agent-to-agent comms? | **Yes** — owner-approved, fully audited | Vault mediates all messages; per-pair approval; full payload visibility for owner; volume controls; auto-suspend on abuse |
| Offline/cache mode? | **No** — fail if disconnected | Zero-storage principle is non-negotiable; fix your network |
| Browser agent support? | **Yes** — Connector WebSocket only | Localhost WebSocket on the Connector; no cloud relay; if you can't run the Connector, you can't connect |
| Platform binding? | **Machine fingerprint + platform key** | Credentials undecryptable on different machine; 4-of-5 tolerance for minor changes |

---

## 11. Summary

The VettID Agent Connector provides a simple, secure bridge between AI agents and VettID vaults by:

- **Reusing proven patterns** — Connection invitations, key exchange, and MessageSpace messaging, adapted for agent-specific needs with a one-time shortlink enrollment flow
- **Minimizing the trust boundary** — The agent never touches keys; the Connector never stores secrets; credentials are bound to the specific machine via platform key derivation
- **Keeping it lightweight** — A single Go binary with REST and WebSocket interfaces, no databases or cloud dependencies on the agent side
- **Preserving owner control** — Registration requires explicit approval with a connection contract; the owner defines scope, approval mode, and rate limits after reviewing the agent's actual details; revocation is instant
- **Full transparency** — Three-layer audit logging, with full payload visibility for owner-approved agent-to-agent communication

The communication model (AI Agent → Connector → NATS MessageSpace → Vault → Owner's App) leverages existing VettID infrastructure while keeping the new code surface small and auditable. The Connector is the only trust boundary on the agent side — if you can run it locally, you're in; if you can't, you're not.
