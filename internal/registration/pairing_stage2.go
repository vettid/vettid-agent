// Two-stage agent pairing flow — stage 2.
//
// Protocol reference: vettid-agent/docs/AGENT-PAIRING-FLOW.md.
//
// Stage 1 (pairing.go) gave us scoped NATS creds plus an ephemeral X25519
// keypair. Stage 2 picks up from there:
//
//   1. Reconnect to NATS as the scoped user.
//   2. Subscribe to forApp.agent.<conn>.activated AND .revoked BEFORE
//      publishing — the vault may publish activated before we'd otherwise
//      finish setting up the subscription, which would lose the event.
//   3. Publish agent.request-session with our pubkey + approval_token +
//      agent_metadata + the requested_* hints (final values are written by
//      the phone — see locked decision #2 in the protocol doc).
//   4. Wait for activation (or revocation, or timeout).
//   5. HKDF(salt=connection_id, info="vettid-agent-session-v1|<sessID>",
//      ikm=X25519(agent_priv, vault_pub)) → session_key.
//   6. Seal ConnectionCredentials to connection.enc with the user's
//      passphrase. KeyID = connection_id (NOT session_id; see doc-vs-shipped
//      drift table in the protocol doc — every encrypted op the vault sees
//      is looked up by connections/{KeyID} and will return "connection not
//      found" if we put session_id there).

package registration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/hkdf"

	"github.com/vettid/vettid-agent/internal/credential"
	"github.com/vettid/vettid-agent/internal/crypto"
	"github.com/vettid/vettid-agent/internal/fingerprint"
)

// DomainAgentSession is the HKDF info-prefix the vault uses when deriving
// session keys for agent connections — see vault-manager/agent_pairing.go
// DomainAgentSession. The full info string is "<domain>|<session_id>".
const DomainAgentSession = "vettid-agent-session-v1"

// DefaultRequestedDurationSecs matches the vault's DefaultSessionDurationSeconds
// (1h). The owner can still bump or trim it on the phone — this is just the
// hint we send up with the request.
const DefaultRequestedDurationSecs int64 = 60 * 60

// DefaultApprovalWait is the wall-clock deadline for stage 2. Matches the
// desktop's ACTIVATION_TIMEOUT_SECS. Callers can override via the
// CompletePairingOptions.Timeout field.
const DefaultApprovalWait = 300 * time.Second

// AgentMetadata is the identity card the phone shows when prompting the
// owner to approve a stage-2 session. Field names match vault-manager's
// AgentMetadata (connections.go) exactly — JSON tags here are normative.
type AgentMetadata struct {
	AgentType          string `json:"agent_type"`
	BinaryFingerprint  string `json:"binary_fingerprint"`
	MachineFingerprint string `json:"machine_fingerprint"`
	Hostname           string `json:"hostname,omitempty"`
	Platform           string `json:"platform,omitempty"`
	OSName             string `json:"os_name,omitempty"`
	OSVersion          string `json:"os_version,omitempty"`
	AppVersion         string `json:"app_version,omitempty"`
}

// CollectAgentMetadata gathers the identity card from the running binary +
// host machine. Errors are non-fatal individually — if a single field can't
// be collected (e.g. binary unreadable in a hardened sandbox) the call
// returns the partial card and a wrapped error the caller can downgrade
// to a warning. The two truly required fields (binary + machine fp) MUST
// be populated; if either is empty the function returns an error since the
// phone shows them as the trust anchor.
func CollectAgentMetadata(agentType, appVersion string) (*AgentMetadata, error) {
	if agentType == "" {
		return nil, errors.New("agent_type is required")
	}

	binaryFP, err := fingerprint.BinaryFingerprint()
	if err != nil {
		return nil, fmt.Errorf("binary fingerprint: %w", err)
	}
	if binaryFP == "" {
		return nil, errors.New("binary fingerprint empty")
	}

	attrs, err := fingerprint.CollectMachineAttributes()
	if err != nil {
		return nil, fmt.Errorf("collect machine attributes: %w", err)
	}
	machineFP := fingerprint.ComputeMachineFingerprintHex(attrs)
	if machineFP == "" {
		return nil, errors.New("machine fingerprint empty")
	}

	hostname, _ := os.Hostname()
	osName, osVersion := detectOS()

	return &AgentMetadata{
		AgentType:          agentType,
		BinaryFingerprint:  binaryFP,
		MachineFingerprint: machineFP,
		Hostname:           hostname,
		Platform:           fingerprint.Platform(),
		OSName:             osName,
		OSVersion:          osVersion,
		AppVersion:         appVersion,
	}, nil
}

// detectOS reads /etc/os-release on Linux for a friendly OS name + version.
// Returns ("", "") on platforms where that file doesn't exist; the phone
// falls back to the platform string in that case.
func detectOS() (name, version string) {
	if runtime.GOOS != "linux" {
		// macOS / Windows: we'd need sw_vers / ver respectively. Leave
		// blank for now — Platform() ("darwin/arm64") carries enough.
		return "", ""
	}
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "", ""
	}
	for _, line := range splitLines(string(data)) {
		k, v, ok := splitKV(line)
		if !ok {
			continue
		}
		switch k {
		case "NAME":
			name = stripQuotes(v)
		case "VERSION_ID":
			version = stripQuotes(v)
		}
	}
	return name, version
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

func splitKV(line string) (string, string, bool) {
	for i := 0; i < len(line); i++ {
		if line[i] == '=' {
			return line[:i], line[i+1:], true
		}
	}
	return "", "", false
}

func stripQuotes(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

// PairingOutcome is the public-facing result of a successful CompletePairing.
// Sensitive material (the session key, the agent's private key) has already
// been sealed to disk by Save and is intentionally not exposed here.
type PairingOutcome struct {
	ConnectionID    string
	SessionID       string
	ExpiresAt       int64
	DurationSeconds int64
	GrantedScope    []string
	ApprovalMode    string
}

// CompletePairingOptions configures stage 2.
//
// Timeout caps how long we'll wait for the activation event. Defaults to
// DefaultApprovalWait.
//
// RequestedScope / RequestedApprovalMode / RequestedDurationSecs are HINTS
// — the phone is free to narrow scope or pick a different duration. The
// final values the vault writes into record.Contract come from the owner's
// authorize payload, not from these.
type CompletePairingOptions struct {
	Timeout               time.Duration
	RequestedScope        []string
	RequestedApprovalMode string // "always_ask" | "auto_within_contract"
	RequestedDurationSecs int64
}

// sessionActivatedPayload mirrors the JSON published by
// vault-manager/agent_pairing.go HandleAgentAuthorizeSession.
type sessionActivatedPayload struct {
	Type          string   `json:"type"` // "agent.session.activated"
	ConnectionID  string   `json:"connection_id"`
	SessionID     string   `json:"session_id"`
	VaultPubKey   string   `json:"vault_pubkey"` // hex, 32 bytes
	ExpiresAt     int64    `json:"expires_at"`
	DurationSecs  int64    `json:"duration_s"`
	GrantedScope  []string `json:"granted_scope"`
	ApprovalMode  string   `json:"approval_mode"`
}

// agentRequestSessionEnvelope is the wrapper the vault's forOwner-routing
// expects. Mirrors the desktop's pairing.rs envelope so unwrapPayload on
// the vault side picks out the inner payload.
type agentRequestSessionEnvelope struct {
	ID        string                    `json:"id"`
	Type      string                    `json:"type"`
	Timestamp string                    `json:"timestamp"`
	Payload   agentRequestSessionInner  `json:"payload"`
}

type agentRequestSessionInner struct {
	ConnectionID          string         `json:"connection_id"`
	ApprovalToken         string         `json:"approval_token"`
	AgentPubKey           string         `json:"agent_pubkey"`
	AgentMetadata         *AgentMetadata `json:"agent_metadata"`
	RequestedScope        []string       `json:"requested_scope,omitempty"`
	RequestedApprovalMode string         `json:"requested_approval_mode,omitempty"`
	RequestedDurationSecs int64          `json:"requested_duration_s,omitempty"`
}

// deriveAgentSessionKey derives the 32-byte AEAD session key from the
// X25519 shared secret. Inputs must match vault-manager's
// deriveSessionKey(DomainAgentSession, ...) exactly:
//
//   salt = connection_id  (per-pair binding)
//   info = "vettid-agent-session-v1|<session_id>"  (per-session separation)
//   ikm  = ECDH(agent_priv, vault_pub)
//
// Any mismatch here means the agent and vault derive different keys and
// every subsequent encrypted op fails to decrypt — silently, from the
// caller's perspective. This is the most consequential single block in
// the agent.
func deriveAgentSessionKey(sharedSecret []byte, connectionID, sessionID string) ([]byte, error) {
	if len(sharedSecret) == 0 {
		return nil, errors.New("shared secret must not be empty")
	}
	if connectionID == "" || sessionID == "" {
		return nil, errors.New("connection_id and session_id are required")
	}
	info := DomainAgentSession + "|" + sessionID
	r := hkdf.New(sha256.New, sharedSecret, []byte(connectionID), []byte(info))
	key := make([]byte, crypto.KeySize)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("HKDF expand: %w", err)
	}
	return key, nil
}

// connectScoped opens a NATS connection using the per-pair scoped JWT/seed
// the vault attached to the invite payload. Single-shot: MaxReconnects=0 so
// transient failures fail fast and bubble up to the caller instead of
// silently retrying past the activation deadline.
func connectScoped(natsURL, jwt, seed string) (*nats.Conn, error) {
	opts := []nats.Option{
		nats.UserJWTAndSeed(jwt, seed),
		nats.Name("vettid-agent-pairing"),
		nats.Timeout(10 * time.Second),
		nats.MaxReconnects(0),
		nats.Secure(),
		// See connectGuest in pairing.go for the explanation —
		// the NLB requires TLS-from-byte-0.
		nats.TLSHandshakeFirst(),
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
			log.Debug().Err(err).Msg("nats async error during stage-2 pairing")
		}),
	}
	conn, err := nats.Connect(natsURL, opts...)
	if err != nil {
		return nil, fmt.Errorf("scoped connect to %s: %w", natsURL, err)
	}
	return conn, nil
}

// CompletePairing runs stage 2 end-to-end and persists the resulting
// connection.enc. Returns the activation envelope as a PairingOutcome on
// success.
//
// The caller is responsible for zeroing runtime via runtime.Zero() (whether
// this returns success or error). passphrase + platformKey are NOT zeroed
// here — the caller owns them and likely needs them for further setup.
func CompletePairing(
	ctx context.Context,
	session *InviteSession,
	runtimeState *PairingRuntime,
	metadata *AgentMetadata,
	opts CompletePairingOptions,
	configDir string,
	passphrase, platformKey []byte,
) (*PairingOutcome, error) {
	if session == nil || runtimeState == nil || metadata == nil {
		return nil, errors.New("session, runtime, and metadata are required")
	}
	if session.ConnectionID != runtimeState.ConnectionID {
		return nil, errors.New("session/runtime connection_id mismatch — bug in caller")
	}
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultApprovalWait
	}
	if opts.RequestedDurationSecs <= 0 {
		opts.RequestedDurationSecs = DefaultRequestedDurationSecs
	}
	if opts.RequestedApprovalMode == "" {
		opts.RequestedApprovalMode = "always_ask"
	}

	conn, err := connectScoped(session.NATSURL, session.ScopedJWT, session.ScopedSeed)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Subscribe BEFORE publishing — otherwise the vault may publish
	// .activated before our subscription is registered, dropping the
	// only event we care about. Asynchronous subscriptions are fine here
	// because we drain via a channel below.
	activatedSubj := fmt.Sprintf("MessageSpace.%s.forApp.agent.%s.activated",
		session.OwnerSpace, session.ConnectionID)
	revokedSubj := fmt.Sprintf("MessageSpace.%s.forApp.agent.%s.revoked",
		session.OwnerSpace, session.ConnectionID)

	// Buffered so a fast vault doesn't block its publish thread on us.
	// Capacity 4 is generous — we only expect one event per subject.
	activatedCh := make(chan *nats.Msg, 4)
	revokedCh := make(chan *nats.Msg, 4)

	activatedSub, err := conn.ChanSubscribe(activatedSubj, activatedCh)
	if err != nil {
		return nil, fmt.Errorf("subscribe activated: %w", err)
	}
	defer activatedSub.Unsubscribe()

	revokedSub, err := conn.ChanSubscribe(revokedSubj, revokedCh)
	if err != nil {
		return nil, fmt.Errorf("subscribe revoked: %w", err)
	}
	defer revokedSub.Unsubscribe()

	// Force a flush so both subscriptions are registered with the server
	// before we publish. Without it, nats.go can batch the SUB frames
	// behind the publish, hitting the race we tried to avoid.
	if err := conn.FlushTimeout(5 * time.Second); err != nil {
		return nil, fmt.Errorf("flush subscriptions: %w", err)
	}

	requestIDBytes, err := crypto.GenerateRandomBytes(16)
	if err != nil {
		return nil, fmt.Errorf("generate request id: %w", err)
	}
	envelope := agentRequestSessionEnvelope{
		ID:        hex.EncodeToString(requestIDBytes),
		Type:      "agent.request-session",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Payload: agentRequestSessionInner{
			ConnectionID:          session.ConnectionID,
			ApprovalToken:         session.ApprovalToken,
			AgentPubKey:           hex.EncodeToString(runtimeState.AgentKeyPair.PublicKey[:]),
			AgentMetadata:         metadata,
			RequestedScope:        opts.RequestedScope,
			RequestedApprovalMode: opts.RequestedApprovalMode,
			RequestedDurationSecs: opts.RequestedDurationSecs,
		},
	}
	envBytes, err := json.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("marshal request-session envelope: %w", err)
	}

	requestSubj := fmt.Sprintf("MessageSpace.%s.forOwner.agent.%s.request-session",
		session.OwnerSpace, session.ConnectionID)
	if err := conn.Publish(requestSubj, envBytes); err != nil {
		return nil, fmt.Errorf("publish request-session: %w", err)
	}
	if err := conn.FlushTimeout(5 * time.Second); err != nil {
		return nil, fmt.Errorf("flush request-session: %w", err)
	}

	log.Info().
		Str("subject", requestSubj).
		Str("connection_id", session.ConnectionID).
		Msg("Stage-2 request-session published; awaiting owner approval")

	// Wait for activation, revocation, ctx cancel, or timeout.
	deadline := time.NewTimer(opts.Timeout)
	defer deadline.Stop()

	var activated *sessionActivatedPayload
	for activated == nil {
		select {
		case msg := <-activatedCh:
			var p sessionActivatedPayload
			if err := json.Unmarshal(msg.Data, &p); err != nil {
				log.Warn().Err(err).Msg("Ignoring malformed activation payload")
				continue
			}
			if p.ConnectionID != session.ConnectionID {
				// Shouldn't happen — the subscription subject is conn-scoped
				// — but cheap to verify and a useful invariant for tests.
				log.Warn().
					Str("got", p.ConnectionID).
					Str("want", session.ConnectionID).
					Msg("Activation connection_id mismatch — ignoring")
				continue
			}
			activated = &p
		case msg := <-revokedCh:
			reason := tryExtractRevokedReason(msg.Data)
			return nil, fmt.Errorf("owner denied authorization: %s", reason)
		case <-deadline.C:
			return nil, fmt.Errorf("timed out after %s waiting for owner approval", opts.Timeout)
		case <-ctx.Done():
			return nil, fmt.Errorf("pairing cancelled: %w", ctx.Err())
		}
	}

	vaultPub, err := hex.DecodeString(activated.VaultPubKey)
	if err != nil || len(vaultPub) != crypto.KeySize {
		return nil, fmt.Errorf("vault pubkey not 32 hex bytes (len=%d, err=%v)", len(vaultPub), err)
	}

	shared, err := crypto.ComputeSharedSecret(runtimeState.AgentKeyPair.PrivateKey[:], vaultPub)
	if err != nil {
		return nil, fmt.Errorf("X25519 ECDH: %w", err)
	}
	defer crypto.ZeroBytes(shared)

	sessionKey, err := deriveAgentSessionKey(shared, session.ConnectionID, activated.SessionID)
	if err != nil {
		return nil, fmt.Errorf("derive session key: %w", err)
	}
	defer crypto.ZeroBytes(sessionKey)

	// SECURITY: KeyID = ConnectionID, NOT SessionID. Every encrypted op
	// the vault receives is looked up by connections/{KeyID} on storage.
	// Storing session_id here would make every op fail with "connection
	// not found" — the foot-gun called out in AGENT-PAIRING-FLOW.md's
	// doc-vs-shipped drift table.
	creds := &credential.ConnectionCredentials{
		ConnectionID:           session.ConnectionID,
		ConnectionKey:          sessionKey,
		KeyID:                  session.ConnectionID,
		AgentPrivateKey:        append([]byte(nil), runtimeState.AgentKeyPair.PrivateKey[:]...),
		AgentPublicKey:         append([]byte(nil), runtimeState.AgentKeyPair.PublicKey[:]...),
		VaultPublicKey:         vaultPub,
		JWT:                    session.ScopedJWT,
		Seed:                   session.ScopedSeed,
		MessageSpaceURL:        session.NATSURL,
		OwnerGUID:              session.OwnerSpace,
		Scope:                  activated.GrantedScope,
		ApprovalMode:           activated.ApprovalMode,
		SessionID:              activated.SessionID,
		SessionExpiresAt:       activated.ExpiresAt,
		SessionDurationSeconds: activated.DurationSecs,
	}
	defer creds.Zero()

	if err := credential.Save(configDir, creds, passphrase, platformKey); err != nil {
		return nil, fmt.Errorf("save credentials: %w", err)
	}

	log.Info().
		Str("connection_id", session.ConnectionID).
		Str("session_id", activated.SessionID).
		Int64("expires_at", activated.ExpiresAt).
		Int("scope_count", len(activated.GrantedScope)).
		Str("approval_mode", activated.ApprovalMode).
		Msg("Stage-2 activation received; credentials sealed")

	return &PairingOutcome{
		ConnectionID:    session.ConnectionID,
		SessionID:       activated.SessionID,
		ExpiresAt:       activated.ExpiresAt,
		DurationSeconds: activated.DurationSecs,
		GrantedScope:    activated.GrantedScope,
		ApprovalMode:    activated.ApprovalMode,
	}, nil
}

// tryExtractRevokedReason peels a human-readable reason out of the revoked
// payload if one's present. The vault may publish either a structured
// {connection_id, reason} or a bare ack — handle both.
func tryExtractRevokedReason(data []byte) string {
	var p struct {
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(data, &p); err == nil && p.Reason != "" {
		return p.Reason
	}
	return "revoked"
}
