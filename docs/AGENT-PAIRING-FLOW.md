# Agent Pairing Flow

Canonical design for pairing a vettid-agent sidecar to a user's vault, authorizing a scope-bound session, extending via owner approval, and revoking.

Mirrors the desktop connection flow (`vettid-dev/docs/DESKTOP-CONNECTION-FLOW.md` for design intent; `vettid-desktop/src-tauri/src/registration/pairing.rs` for the *shipped* reference implementation — see "Doc-vs-shipped drift" below).

Last updated: 2026-05-23.

---

## Status

`vettid-agent init` currently returns `"not yet implemented"` (`internal/registration/flow.go:80-84`). The previous HTTP-broker pairing flow (`https://vett.id/<code>`) was removed in April because the domain was never registered. Every other internal of vettid-agent (NATS transport, ChaCha20-Poly1305 envelopes, sealed credential store, machine-bound platform key, local REST/WS surface) is hardened and working — `vettid-agent start` operates end-to-end **once a `connection.enc` file exists**. The work below is what produces that file.

---

## Locked decisions (2026-05-23)

1. **Strict session-expiry mirror.** On expiry, the agent's session key is wiped — it cannot decrypt vault traffic until the owner re-approves on the phone. A new local-API endpoint `POST /v1/pair/extend` lets the embedded AI agent self-trigger an extension request, but only the owner's phone tap actually grants it. Matches desktop design goal #3.

2. **Formal scope vocabulary, defined now.** No free-text strings. Initial set:
   - `secrets.catalog.read` — list secret aliases (no values)
   - `secrets.get` — read a secret value
   - `secrets.put` — write a secret
   - `agent.action.<tool>` — invoke a specific tool by name
   - `message.send` — send messages on the owner's behalf to specific connections
   - `message.recv` — observe inbound messages
   - `call.history` — read call history
   - `connection.list` — list owner's connections
   - `connection.get` — read details of a specific connection

   Phone scope picker shows human-readable labels and a per-scope description. `agent.action.<tool>` is parameterized; phone shows the requesting agent's declared toolset.

3. **Separate vault handlers, shared helpers.** New `enclave/vault-manager/agent_pairing.go` parallel to `device_pairing.go`. Helpers `GenerateAgentCredentials` and `deriveAgentSessionKey` share a core with their device equivalents parameterized on a domain constant (`DomainAgentSession = "vettid-agent-session-v1"`). Keeps scope-binding logic out of the device path; cleaner audit surface.

4. **Bootstrap Lambda extended for agent flavor.** Audited 2026-05-23 — see Phase 0 below for the actual shape (the Lambda lives at `cdk/lambda/handlers/vault/bootstrapDevicePairing.ts`, not `handlers/public/`). The Lambda is already device/agent-agnostic at the NATS-scope level; subject-prefix or stream-level isolation between device and agent invites is **not enforceable** with current JetStream scoping (`type` is a payload field, not a subject). Decision: accept `kind` in the JSON body of the existing endpoint, log it for audit, otherwise mint identical scope. Security boundary stays the unguessable 12-char code + 60s JWT TTL + 2-min invite TTL.

---

## Doc-vs-shipped drift (read this before mirroring)

The desktop design doc disagrees with the shipped desktop code in four places. The agent must mirror the *shipped* behavior, not the doc:

| Topic | Design doc | Shipped (`pairing.rs`) | Agent should follow |
| --- | --- | --- | --- |
| Guest NATS creds | Embedded in binary | Per-pair HTTP-minted (`pairing.rs:42`) | Shipped — agent calls bootstrap HTTP |
| Invite code length | 8 chars | 12 chars (`CreateDeviceInviteResponse.InviteCode`) | Shipped — 12 chars, dash-grouped display |
| KeyID identity | not specified | `key_id == connection_id`, **NOT** `session_id` (`pairing.rs:384-389`) | Shipped — known footgun, every encrypted op times out at the vault if wrong |
| Per-op encryption key | not specified | Session key; `connection_key = session_key` in stored creds (`pairing.rs:380`) | Shipped — `connection_key` rotates on each extend |

---

## Actors

- **Owner** — holds the phone, controls the vault.
- **Phone** — VettID mobile app, authenticated to the vault. Sole authority for granting / scope-binding agent sessions.
- **Operator** — runs the AI agent + the agent connector on a host machine. May or may not be the owner.
- **Agent** — the vettid-agent binary; headless sidecar process. No display.
- **Vault** — owner's Nitro Enclave vault-manager, reached via NATS on the owner's OwnerSpace.
- **Guest account** — pre-provisioned read-only NATS account, creds minted per-pair via bootstrap HTTP endpoint.

---

## Stages

### Stage 1 — Pairing invite (NATS entry)

```
Owner    Phone                              Vault                 JetStream            Agent (guest)
 |        |                                  |                       |                     |
 | tap "Connect Agent"                       |                       |                     |
 |------->|                                  |                       |                     |
 |        | agent.create-invite              |                       |                     |
 |        |--------------------------------->|                       |                     |
 |        |                                  | mint 12-char code     |                     |
 |        |                                  | mint scoped creds     |                     |
 |        |                                  | publish invite.<code> ----->|               |
 |        |                                  | (type:"vettid_agent") |                     |
 |        |        { invite_code, expires_at, connection_id }        |                     |
 |        |<---------------------------------|                       |                     |
 |<-------| show 12-char code on screen      |                       |                     |
 |                                                                                         |
 | paste code into `vettid-agent init <code>` --------------------------------------------->|
 |                                                                   |  fetchBootstrapCreds |
 |                                                                   |     (HTTP POST)      |
 |                                                                   |   read invite.<code> |
 |                                                                   |<---------------------|
 |                                                                   |  (as guest account)  |
 |                                                                   |--------------------->|
```

Vault publishes the invite **payload** containing the scoped JWT/seed agent will use for stage 2. Owner has not yet granted any data access.

### Stage 2 — Session authorization (scoped + key exchange)

```
Agent (scoped)                              Vault                                       Phone
 |   reconnect with scoped JWT/seed          |                                            |
 |   subscribe …forApp.agent.<conn>.activated|  (subscribe BEFORE publish — race-safe)    |
 |   subscribe …forApp.agent.<conn>.revoked  |                                            |
 |   generate ephemeral X25519 keypair       |                                            |
 |   generate 32-byte approval_token         |                                            |
 |   publish agent.request-session---------->|                                            |
 |   { approval_token, agent_pubkey,         |                                            |
 |     agent_metadata, requested_scope,      |  store DevicePendingAuth                   |
 |     requested_approval_mode }             |  publish agent.pending-authorization------>|
 |                                           |                              show metadata |
 |                                           |                              show binary    |
 |                                           |                              + machine     |
 |                                           |                              fingerprint   |
 |                                           |                              scope picker  |
 |                                           |                              duration      |
 |                                           |                              approval mode |
 |                                           |                                            |
 |                                           |  agent.authorize-session<------------------|
 |                                           |  { connection_id, approval_token,          |
 |                                           |    granted_scope, approval_mode,           |
 |                                           |    rate_limit, duration_seconds }          |
 |                                           |  X25519 + HKDF                             |
 |                                           |  write ConnectionContract                  |
 |                                           |  build DeviceSession                       |
 |   <---------- publish agent.session.activated                                          |
 |   { vault_pubkey, session_id, expires_at,                                              |
 |     duration_s, granted_scope, approval_mode, rate_limit }                             |
 |                                                                                        |
 |   HKDF derive session_key                                                              |
 |   salt = connection_id                                                                 |
 |   info = "vettid-agent-session-v1|<session_id>"                                        |
 |   ikm  = X25519(agent_priv, vault_pub)                                                 |
 |                                                                                        |
 |   write connection.enc with:                                                           |
 |     ConnectionKey = session_key                                                        |
 |     KeyID         = connection_id   (NOT session_id)                                   |
 |     Scope         = granted_scope                                                      |
 |     ApprovalMode  = approval_mode                                                      |
```

### Stage 3 — Extension / revocation

- **Extend** — agent posts `agent.extend-session` to `…forOwner.agent.<conn>.extend-session` with a *new* ephemeral keypair. Phone re-prompts (showing remaining seconds + new duration). Vault re-runs key exchange and publishes a fresh `agent.session.activated`. Stored `connection_key` is overwritten with the new session key. `connection_id` is preserved (so `KeyID` doesn't change).
- **End session** — agent posts `agent.end-session`. Vault wipes the in-memory session. Local `connection.enc` is deleted.
- **Revoke** — either side can publish `agent.revoke`. Owner-initiated revocation lands on `…forApp.agent.<conn>.revoked` (agent already subscribed at stage 2 start) and triggers local cred wipe + daemon shutdown.

---

## Authorization model — what the phone shows

Phone receives `agent.pending-authorization` with this payload:

```
{
  "connection_id":   "<uuid>",
  "approval_token":  "<32-byte hex>",
  "agent_pubkey":    "<x25519 pubkey>",
  "agent_metadata": {
    "hostname":           "<string>",
    "platform":           "linux|darwin|windows",
    "os_name":            "<string>",
    "os_version":         "<string>",
    "binary_fingerprint": "<sha256 of vettid-agent binary>",
    "machine_fingerprint":"<sha256 of stable machine identifiers>",
    "app_version":        "<semver>",
    "agent_type":         "<operator-declared label, e.g. 'claude-code', 'cursor', 'self-hosted-llm'>"
  },
  "requested_scope":          ["secrets.catalog.read", "secrets.get", "agent.action.web-search"],
  "requested_approval_mode":  "always_ask" | "auto_within_contract",
  "requested_duration_s":     3600
}
```

Phone displays:

1. **Identity card** — agent_type label, hostname, OS, app_version
2. **Fingerprint block** — binary + machine fingerprints, formatted as 4-block-of-8-hex with hover-to-copy
3. **Scope picker** — each `requested_scope` token rendered as a labeled toggle, default-on; owner can de-select. Adding scopes beyond the requested set is **not** permitted from this screen (would require a fresh `request-session`)
4. **Approval mode** — radio: "Ask me every time" / "Auto-approve within contract" (the latter only enabled if `requested_approval_mode == "auto_within_contract"`)
5. **Duration** — picker capped at 24h for v1 (strict-mirror decision)
6. **Approve / Deny** — Approve sends `agent.authorize-session`; Deny publishes `agent.revoke` with reason

The owner authorizes by **tap on phone**, no QR. The trust anchor is the agent's binary + machine fingerprint shown on the phone — owner verifies these out-of-band match what the operator told them.

---

## Phased implementation plan

### Phase 0 — Bootstrap Lambda audit — DONE 2026-05-23

**Lambda:** `vettid-dev/cdk/lambda/handlers/vault/bootstrapDevicePairing.ts` (the canonical plan originally guessed `handlers/public/`; corrected).
**Route:** `cdk/lib/vault-stack.ts:1732` → `POST /pair/device/bootstrap`. No authorizer. Lambda wired at `:426`.
**Current contract:**
- Request body: `{ "code": "<12 chars, ABCDEFGHJKLMNPQRSTUVWXYZ23456789>" }`
- Response: `{ nats_endpoint, jwt, seed, expires_in: 60 }`
- Mints a fresh ephemeral NATS user keypair per call, signs a 60s-TTL JWT with the guest account seed from Secrets Manager (`vettid/nats/operator-key` → `guest_account_seed`, 5-min Lambda-container cache).
- JWT scope: JetStream RPC on the `INVITATIONS` stream (`$JS.API.STREAM.INFO.INVITATIONS`, `$JS.API.CONSUMER.CREATE.INVITATIONS[.>]`, `$JS.API.CONSUMER.DURABLE.CREATE.INVITATIONS.>`, `$JS.API.CONSUMER.MSG.NEXT.INVITATIONS.>`, `$JS.API.CONSUMER.DELETE.INVITATIONS.>`) + `_INBOX.>`. Subscribe scope: `_INBOX.>` only.
- **Deliberately does NOT verify the code exists** in JetStream (avoids being an "is X a live invite" oracle). Preserve this property for agents.

**Findings:**

1. **Already device/agent-agnostic at the NATS layer.** A desktop bootstrap response could read any `invite.<code>` payload — there is no per-`type` JetStream isolation today.
2. **Payload-type filtering at the NATS scope level is NOT achievable.** `type:"vettid_agent"` is a payload field, not a subject. NATS JWT scope governs subjects only; the JetStream consumer `filter_subject` is client-chosen at create time and not validated against scope. True device/agent isolation would require *either* a separate JetStream subject prefix *and* enforcement at the publish path, *or* a separate stream (e.g., `AGENT_INVITATIONS`). Neither buys much over the existing boundary.
3. **Today's security boundary** is the unguessable invite code (12 chars × log2(32) alphabet ≈ 60 bits) + 2-min invite TTL + 60s JWT TTL. Same boundary works for agent invites unchanged.
4. **Current `HandleCreateAgentInvite` (connections.go:1994) is unusable for the new flow** — confirmed. Mints the dead 32-byte shortlink token, does not publish to JetStream, does not mint scoped creds. Phase 1 rewrites from scratch.
5. **No Lambda-level rate limiting.** Only API Gateway stage throttling. Tracked as a follow-up (see "Open follow-ups not blocking this work" below).

**Decision (locked 2026-05-23):** Same Lambda, accept `kind` in the JSON body (default `"device"` for backwards compat with the shipped desktop). Differentiate logs/audit by `kind`; mint identical scope. Defer subject-prefix or separate-stream isolation — not worth the publish-path churn for the same effective security boundary.

**Touchpoints for the actual change (done in Phase 1's CDK pass or earlier):**
- `bootstrapDevicePairing.ts:84-96` — read `kind` from body, validate `kind ∈ {"device","agent"}`, default `"device"`.
- `bootstrapDevicePairing.ts:101-105` — add `kind` to the `console.info` log block.
- `bootstrapDevicePairing.ts:135` — embed `kind` in the JWT name prefix for traceability (e.g., `agent-bootstrap-<code-prefix>-…`).
- No CDK changes required (same route, same Lambda).

### Phase 1 — Vault handlers + Android invite creation (no agent code yet)

**Why first:** the agent can't be tested end-to-end until the vault publishes invites in the new shape. Vault changes are also the lowest-risk to roll back.

Files to create / modify:

- `vettid-dev/enclave/vault-manager/connections.go` — rewrite `HandleCreateAgentInvite` (currently lines 1994-2081, still mints opaque base64 token for defunct `vettid.com/agent?t=…` shortlink) following `HandleCreateDeviceInvite` (line 4015). New response shape: `{ connection_id, invite_code, nats_endpoint, expires_at }`. Store `ConnectionRecord{ConnectionType: agent, Status: "pending_pairing"}`.

- `vettid-dev/enclave/vault-manager/agent_pairing.go` *(new)* — parallel to `device_pairing.go`. Handlers:
  - `HandleAgentRequestSession` — store `AgentPendingAuth`, publish `agent.pending-authorization` to `forApp.agent.<conn>`
  - `HandleAgentAuthorizeSession` — X25519 + HKDF (domain `vettid-agent-session-v1`), write `record.Contract = &ConnectionContract{Scope, ApprovalMode, RateLimit}` from request payload, publish `agent.session.activated` on `forApp.agent.<conn>.activated`. **Phone is the only authority that writes `record.Contract`** — agent's `requested_scope` is a hint only.
  - `HandleAgentExtendSession`, `HandleAgentEndSession`, `HandleAgentRevoke`

- `vettid-dev/enclave/vault-manager/messages.go` — add `handleAgentOperation` switch (mirror `handleDeviceOperation` at line 1502) covering `create-invite`, `cancel-invite`, `request-session`, `authorize-session`, `extend-session`, `end-session`, `revoke`.

- Shared helper extraction: factor a `deriveSessionKey(domain string, connID, sessID string, priv, pub []byte) ([]byte, error)` out of the existing device path so both flows call it with their domain constant.

- `vettid-android/app/src/main/java/com/vettid/app/features/agents/CreateAgentInvitationViewModel.kt` — replace lines 54-80: message-type `agent.create-invitation` → `agent.create-invite`, display the 12-char code (dash-grouped) instead of building the dead shortlink.

**Verification gate:** Android can request and display a working 12-char agent invite code; INVITATIONS stream shows `invite.<code>` with `type:"vettid_agent"` and a valid scoped-creds payload.

### Phase 2 — Agent stage-1 (guest bootstrap + invite read)

Files to create / modify in `vettid-agent`:

- `internal/registration/pairing.go` *(new)* — mirror `vettid-desktop/src-tauri/src/registration/pairing.rs` structure in Go. Functions:
  - `fetchBootstrapCreds(kind string) (*GuestCreds, error)` — HTTP POST to bootstrap endpoint with `kind=agent`. URL configurable via `VETTID_BOOTSTRAP_URL` env var. Default `https://api.vettid.dev/pair/agent/bootstrap`.
  - `resolveInvite(code string) (*InviteSession, *PairingRuntime, error)` — connect via guest creds with TLS-first, JetStream pull-consumer on `INVITATIONS` filtered to `invite.<CODE-UPPERCASED>`, `DeliverPolicy::LastPerSubject`, single fetch with 5s deadline, parse `InvitePayload`, generate ephemeral X25519 keypair + 32-byte approval token.

- `internal/nats/client.go` — add `NewGuestClient` and `FetchInviteFromStream`. TLS-first connect is mandatory against the AWS NLB — Go nats.go equivalent is `tls://` URL + `TLSConfig`. Verify against live infra.

- `cmd/vettid-agent/main.go` — `newInitCmd` (lines 84-133): replace `flow.NewFlow(...).Run()` with the new two-stage orchestration. Print progress to stderr: `resolving invite ▸ request-session sent ▸ awaiting owner approval ▸ activated`.

- `internal/registration/flow.go` — delete the `Run()` stub. State enum stays useful for stage progression.

### Phase 3 — Agent stage-2 (request-session, key exchange, sealed write)

- `internal/registration/pairing.go` — add `completePairing(session, runtime, fingerprint, configDir, requestedScope) (*PairingOutcome, error)`:
  - Reconnect NATS with scoped JWT/seed
  - Subscribe to `forApp.agent.<conn>.activated` and `.revoked` **before** publishing request-session
  - Publish `agent.request-session` with metadata + requested_scope + requested_approval_mode + requested_duration_s
  - Wait up to 300s (configurable via `--timeout`)
  - On `activated`: HKDF derive (salt=connection_id, info=`vettid-agent-session-v1|<session_id>`)
  - **KeyID = connection_id, NOT session_id** — known footgun
  - Populate `credential.ConnectionCredentials` including `Scope`, `ApprovalMode`. `ConnectionKey = session_key`.
  - Collect passphrase via `term.ReadPassword` (same path as `start` at `main.go:170`), call `credential.Save`.

- `internal/fingerprint/` — confirm `machine.go` + `binary.go` produce stable fingerprints (Track C work already audited these — `C #65 + #112` documented the threat model). Add `agent_type` from a new `--agent-type` flag on `init`.

### Phase 4 — Mobile UX for agent authorization

- `vettid-android/app/src/main/java/com/vettid/app/features/agents/AuthorizeAgentViewModel.kt` *(new)* — parallel to `AuthorizeDeviceViewModel`. Listens to a new `ownerSpaceClient.agentPendingAuth: SharedFlow<…>`. Posts `agent.authorize-session` with phone-locked-in scope/mode/duration.

- `vettid-android/app/src/main/java/com/vettid/app/features/agents/AuthorizeAgentScreen.kt` *(new)* — composable rendering the identity card, fingerprint block, scope picker, approval-mode toggle, duration picker, Approve/Deny buttons. Auto-pops on `agentPendingAuth` emission.

- `vettid-android/core/nats/OwnerSpaceClient` — subscribe to `forApp.agent.<conn>.pending-authorization`, surface as `agentPendingAuth`.

- Scope vocabulary rendering — add a const map `AgentScopeLabels: Map<String, ScopeMeta>` with human-readable label + description for each of the 9 scope tokens.

### Phase 5 — Extension, revoke, tests, docs

- `internal/registration/pairing.go` — `startExtension(configDir)` and `publishRevoke(configDir, reason)`. Mirror `pairing.rs:473` and `:599`.

- `cmd/vettid-agent/main.go` — wire `revoke` (stub at line 316) to `publishRevoke` + delete `connection.enc`. Wire `status` (stub at line 291) to read `connection.enc` and report `{connection_id, session_expires_at, seconds_remaining, scope, approval_mode}`.

- `internal/api/` — add `POST /v1/pair/extend` to the local REST surface. The embedded AI agent calls this when it detects a 401-equivalent from the vault; the handler triggers an `agent.extend-session` publish and returns a status code reflecting whether the phone owner approved.

- `internal/registration/pairing_test.go` *(new)* — integration test against an embedded NATS test server. Covers happy path, denied-by-owner, timeout, race-on-revoke-during-pair.

- `README.md` — remove the "pending redesign" warning (lines 28-34). Add real "Quick Start" walkthrough.

- `docs/vettid-agent-connector-design.md` §3 — update with the new flow. Keep the April deprecation note as historical context.

---

## Open follow-ups not blocking this work

- **Per-tool scope grammar.** `agent.action.<tool>` is parameterized but the toolset itself isn't versioned. If a tool's parameter shape changes, granted scopes might silently mean something different. Worth a follow-up design pass after Phase 5.
- **Cross-device agent visibility.** Owner with multiple phones — does each see `agent.pending-authorization`? Today, OwnerSpaceClient subscribes per device. Confirm during Phase 4 implementation.
- **Bootstrap rate-limiting.** A leaked agent binary calling `fetchBootstrapCreds` in a loop should be rate-limited at the Lambda. Phase 0 audit confirmed only API Gateway stage throttling is in place (no per-IP). Deferred from this work; track separately. Likely DynamoDB-backed per-IP token bucket on `bootstrapDevicePairing.ts`.

---

## Critical files (for quick navigation)

**vettid-agent (this repo):**
- `internal/registration/flow.go` → delete stub `Run()`
- `internal/registration/pairing.go` *(new)*
- `cmd/vettid-agent/main.go` → wire `init`, `revoke`, `status`
- `internal/nats/client.go` → guest-NATS + JetStream + TLS-first
- `internal/api/` → `POST /v1/pair/extend`

**vettid-dev:**
- `enclave/vault-manager/connections.go:1994` → rewrite `HandleCreateAgentInvite`
- `enclave/vault-manager/agent_pairing.go` *(new)* — parallel to `device_pairing.go`
- `enclave/vault-manager/messages.go:1502-ish` → add `handleAgentOperation`
- `cdk/lambda/handlers/public/` → bootstrap Lambda, add `kind=agent` branch

**vettid-android:**
- `features/agents/CreateAgentInvitationViewModel.kt:54-80` → replace shortlink-building
- `features/agents/AuthorizeAgentViewModel.kt` *(new)*
- `features/agents/AuthorizeAgentScreen.kt` *(new)*
- `core/nats/OwnerSpaceClient` → subscribe `agentPendingAuth`

**vettid-desktop (reference only, do not modify):**
- `src-tauri/src/registration/pairing.rs` → shipped reference for two-stage flow
- `src-tauri/src/commands/auth.rs:61` → Tauri entry pattern
