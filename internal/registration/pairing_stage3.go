// Two-stage agent pairing flow — stage 3 (extend / revoke / end-session).
//
// Protocol reference: vettid-agent/docs/AGENT-PAIRING-FLOW.md §"Stage 3 —
// Extension / revocation".
//
// All three operations reuse the per-pair scoped JWT/seed sealed at init
// time (see ConnectionCredentials.JWT/Seed). Extend does a full
// X25519+HKDF rotation under the existing connection_id; revoke and
// end-session are fire-and-forget publishes with no key derivation.

package registration

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/rs/zerolog/log"

	"github.com/vettid/vettid-agent/internal/credential"
	"github.com/vettid/vettid-agent/internal/crypto"
)

// ExtendOutcome carries the new session state after a successful extend
// round-trip. The caller decides what to do with it — the offline CLI
// path writes it to disk; the local-API hot-rotate path swaps the
// running Server's in-memory state AND persists to disk.
//
// SessionKey is the freshly-derived 32-byte session key. Caller MUST
// zero it after writing it into the credential store (and/or after the
// Server has taken ownership via RotateSession).
type ExtendOutcome struct {
	SessionKey      []byte
	SessionID       string
	ExpiresAt       int64
	DurationSeconds int64
	GrantedScope    []string
	ApprovalMode    string
	VaultPubKey     []byte // 32 bytes; informational, stored for diagnostics
	AgentKeyPair    *crypto.X25519KeyPair
}

// Zero wipes the sensitive material in an ExtendOutcome. Safe to call
// multiple times and on a nil receiver.
func (o *ExtendOutcome) Zero() {
	if o == nil {
		return
	}
	crypto.ZeroBytes(o.SessionKey)
	if o.AgentKeyPair != nil {
		o.AgentKeyPair.Zero()
	}
}

// ExtendSession runs an agent.extend-session round-trip against the
// vault and returns the new session state without writing anything to
// disk. Caller is responsible for persistence (and for zeroing the
// SessionKey once it's safely stored).
//
// The flow mirrors CompletePairing but uses the existing connection_id
// + a fresh ephemeral X25519 keypair + a fresh approval_token. Vault
// reuses the connection record, rotates the session key, and increments
// KeyRotationCount.
//
// opts.Timeout caps how long we wait for the activation event (default
// DefaultApprovalWait). opts.RequestedScope / RequestedApprovalMode /
// RequestedDurationSecs are hints — the phone is the authority.
func ExtendSession(
	ctx context.Context,
	creds *credential.ConnectionCredentials,
	opts CompletePairingOptions,
) (*ExtendOutcome, error) {
	if creds == nil {
		return nil, errors.New("creds is required")
	}
	if creds.ConnectionID == "" || creds.OwnerGUID == "" || creds.MessageSpaceURL == "" {
		return nil, errors.New("creds missing connection_id, owner_guid, or message_space_url — re-pair required")
	}
	if creds.JWT == "" || creds.Seed == "" {
		return nil, errors.New("creds missing NATS JWT/seed — re-pair required")
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

	// Fresh ephemeral keypair + approval token per extend, same
	// rotation semantics as the desktop. The vault stores the new
	// pubkey in AgentPendingAuth.AgentPubKey before re-running ECDH.
	kp, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		return nil, fmt.Errorf("generate keypair: %w", err)
	}
	approvalRaw, err := crypto.GenerateRandomBytes(32)
	if err != nil {
		kp.Zero()
		return nil, fmt.Errorf("generate approval token: %w", err)
	}
	approvalHex := hex.EncodeToString(approvalRaw)
	crypto.ZeroBytes(approvalRaw)

	conn, err := connectScoped(creds.MessageSpaceURL, creds.JWT, creds.Seed)
	if err != nil {
		kp.Zero()
		return nil, err
	}
	defer conn.Close()

	activatedSubj := fmt.Sprintf("MessageSpace.%s.forApp.agent.%s.activated",
		creds.OwnerGUID, creds.ConnectionID)
	revokedSubj := fmt.Sprintf("MessageSpace.%s.forApp.agent.%s.revoked",
		creds.OwnerGUID, creds.ConnectionID)
	activatedCh := make(chan *nats.Msg, 4)
	revokedCh := make(chan *nats.Msg, 4)
	activatedSub, err := conn.ChanSubscribe(activatedSubj, activatedCh)
	if err != nil {
		kp.Zero()
		return nil, fmt.Errorf("subscribe activated: %w", err)
	}
	defer activatedSub.Unsubscribe()
	revokedSub, err := conn.ChanSubscribe(revokedSubj, revokedCh)
	if err != nil {
		kp.Zero()
		return nil, fmt.Errorf("subscribe revoked: %w", err)
	}
	defer revokedSub.Unsubscribe()
	if err := conn.FlushTimeout(5 * time.Second); err != nil {
		kp.Zero()
		return nil, fmt.Errorf("flush subscriptions: %w", err)
	}

	requestIDBytes, err := crypto.GenerateRandomBytes(16)
	if err != nil {
		kp.Zero()
		return nil, fmt.Errorf("generate request id: %w", err)
	}
	// Agent-initiated extend reuses the agent.request-session envelope,
	// not a distinct agent.extend-session subject. Rationale:
	//
	// vault-manager/agent_pairing.go HandleAgentRequestSession allows
	// requests for connections in either "pending_pairing" or "active"
	// status — it always overwrites AgentPendingAuth. When the owner
	// approves on the phone, the existing AuthorizeAgentScreen posts
	// agent.authorize-session which calls HandleAgentAuthorizeSession,
	// which overwrites AgentSession with a fresh sessionID + a freshly-
	// derived session key. Net effect: agent.request-session against an
	// active connection IS the extend operation.
	//
	// HandleAgentExtendSession (a distinct path) exists for the case
	// where the phone wants to differentiate "extend" from "first auth"
	// in its UI and explicitly preserve KeyRotationCount semantics.
	// Phase 5 punts on that distinction — the AuthorizeAgentScreen
	// renders identically for init vs extend. Owner sees "Authorize
	// agent" again; backend rotates the key correctly either way.
	envelope := agentRequestSessionEnvelope{
		ID:        hex.EncodeToString(requestIDBytes),
		Type:      "agent.request-session",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Payload: agentRequestSessionInner{
			ConnectionID:          creds.ConnectionID,
			ApprovalToken:         approvalHex,
			AgentPubKey:           hex.EncodeToString(kp.PublicKey[:]),
			AgentMetadata:         nil, // metadata unchanged from init; vault keeps the existing record
			RequestedScope:        opts.RequestedScope,
			RequestedApprovalMode: opts.RequestedApprovalMode,
			RequestedDurationSecs: opts.RequestedDurationSecs,
		},
	}
	envBytes, err := json.Marshal(envelope)
	if err != nil {
		kp.Zero()
		return nil, fmt.Errorf("marshal extend envelope: %w", err)
	}

	extendSubj := fmt.Sprintf("MessageSpace.%s.forOwner.agent.%s.request-session",
		creds.OwnerGUID, creds.ConnectionID)
	if err := conn.Publish(extendSubj, envBytes); err != nil {
		kp.Zero()
		return nil, fmt.Errorf("publish extend (request-session): %w", err)
	}
	if err := conn.FlushTimeout(5 * time.Second); err != nil {
		kp.Zero()
		return nil, fmt.Errorf("flush extend: %w", err)
	}

	log.Info().
		Str("subject", extendSubj).
		Str("connection_id", creds.ConnectionID).
		Msg("Extend (request-session re-publish) sent; awaiting owner approval")

	deadline := time.NewTimer(opts.Timeout)
	defer deadline.Stop()

	var activated *sessionActivatedPayload
	for activated == nil {
		select {
		case msg := <-activatedCh:
			var p sessionActivatedPayload
			if err := json.Unmarshal(msg.Data, &p); err != nil {
				log.Warn().Err(err).Msg("Ignoring malformed extend activation payload")
				continue
			}
			if p.ConnectionID != creds.ConnectionID {
				log.Warn().
					Str("got", p.ConnectionID).
					Str("want", creds.ConnectionID).
					Msg("Extend activation connection_id mismatch — ignoring")
				continue
			}
			activated = &p
		case msg := <-revokedCh:
			reason := tryExtractRevokedReason(msg.Data)
			kp.Zero()
			return nil, fmt.Errorf("owner denied extend: %s", reason)
		case <-deadline.C:
			kp.Zero()
			return nil, fmt.Errorf("timed out after %s waiting for owner approval on extend", opts.Timeout)
		case <-ctx.Done():
			kp.Zero()
			return nil, fmt.Errorf("extend cancelled: %w", ctx.Err())
		}
	}

	vaultPub, err := hex.DecodeString(activated.VaultPubKey)
	if err != nil || len(vaultPub) != crypto.KeySize {
		kp.Zero()
		return nil, fmt.Errorf("vault pubkey not 32 hex bytes (len=%d, err=%v)", len(vaultPub), err)
	}
	shared, err := crypto.ComputeSharedSecret(kp.PrivateKey[:], vaultPub)
	if err != nil {
		kp.Zero()
		return nil, fmt.Errorf("X25519 ECDH: %w", err)
	}
	defer crypto.ZeroBytes(shared)

	sessionKey, err := deriveAgentSessionKey(shared, creds.ConnectionID, activated.SessionID)
	if err != nil {
		kp.Zero()
		return nil, fmt.Errorf("derive new session key: %w", err)
	}

	log.Info().
		Str("connection_id", creds.ConnectionID).
		Str("old_session_id", creds.SessionID).
		Str("new_session_id", activated.SessionID).
		Int64("expires_at", activated.ExpiresAt).
		Msg("Extend activation received")

	return &ExtendOutcome{
		SessionKey:      sessionKey,
		SessionID:       activated.SessionID,
		ExpiresAt:       activated.ExpiresAt,
		DurationSeconds: activated.DurationSecs,
		GrantedScope:    activated.GrantedScope,
		ApprovalMode:    activated.ApprovalMode,
		VaultPubKey:     vaultPub,
		AgentKeyPair:    kp,
	}, nil
}

// PublishRevoke fires agent.revoke at the vault and returns. Best-effort
// — the agent's local credentials may already be unusable (e.g. the
// passphrase was forgotten and this is being called from a "force
// logout" code path).
//
// Caller is expected to wipe connection.enc afterward via
// credential.Delete; this function does NOT touch disk.
//
// reason flows through to the vault's audit log + the forApp.agent.<conn>
// .revoked payload so the owner sees why their agent went away.
func PublishRevoke(ctx context.Context, creds *credential.ConnectionCredentials, reason string) error {
	if creds == nil || creds.ConnectionID == "" || creds.OwnerGUID == "" {
		return errors.New("creds missing required fields for revoke")
	}
	if creds.JWT == "" || creds.Seed == "" {
		return errors.New("creds missing NATS JWT/seed")
	}

	conn, err := connectScoped(creds.MessageSpaceURL, creds.JWT, creds.Seed)
	if err != nil {
		return err
	}
	defer conn.Close()

	return publishAgentControl(ctx, conn, creds, "agent.revoke", "revoke", reason)
}

// PublishEndSession fires agent.end-session at the vault — the soft
// counterpart to revoke. Vault wipes the active session key + flips
// AgentSession.Status to "expired" but keeps the connection record so
// the agent can restart a session without re-pairing.
//
// Useful for graceful shutdowns where the operator wants to stop the
// daemon temporarily without forcing a full re-pair on next start.
func PublishEndSession(ctx context.Context, creds *credential.ConnectionCredentials, reason string) error {
	if creds == nil || creds.ConnectionID == "" || creds.OwnerGUID == "" {
		return errors.New("creds missing required fields for end-session")
	}
	if creds.JWT == "" || creds.Seed == "" {
		return errors.New("creds missing NATS JWT/seed")
	}

	conn, err := connectScoped(creds.MessageSpaceURL, creds.JWT, creds.Seed)
	if err != nil {
		return err
	}
	defer conn.Close()

	return publishAgentControl(ctx, conn, creds, "agent.end-session", "end-session", reason)
}

// publishAgentControl is the shared body for revoke + end-session.
// Both have the same payload shape ({connection_id, reason}) and the
// same need for a flush so the frame actually reaches the server before
// we close the connection.
func publishAgentControl(
	_ context.Context,
	conn *nats.Conn,
	creds *credential.ConnectionCredentials,
	envelopeType, subjectSuffix, reason string,
) error {
	requestIDBytes, err := crypto.GenerateRandomBytes(16)
	if err != nil {
		return fmt.Errorf("generate request id: %w", err)
	}
	inner := map[string]string{
		"connection_id": creds.ConnectionID,
	}
	if reason != "" {
		inner["reason"] = reason
	}
	envelope := map[string]any{
		"id":        hex.EncodeToString(requestIDBytes),
		"type":      envelopeType,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"payload":   inner,
	}
	envBytes, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("marshal %s envelope: %w", envelopeType, err)
	}
	subject := fmt.Sprintf("MessageSpace.%s.forOwner.agent.%s.%s",
		creds.OwnerGUID, creds.ConnectionID, subjectSuffix)
	if err := conn.Publish(subject, envBytes); err != nil {
		return fmt.Errorf("publish %s: %w", envelopeType, err)
	}
	// Bare publish is fire-and-forget; without an explicit Flush the
	// frame can be dropped at close() time. Mirrors the desktop's
	// publish_end_session / publish_revoke flush-on-the-way-out
	// pattern.
	if err := conn.FlushTimeout(5 * time.Second); err != nil {
		// Non-fatal — log but don't fail, since the caller is on a
		// "tearing down anyway" path and the vault may resync via
		// expiry. The flush failure is worth knowing about though.
		log.Warn().Err(err).Str("subject", subject).Msg(envelopeType + ": flush failed (frame may not have reached server)")
	}
	log.Info().
		Str("subject", subject).
		Str("connection_id", creds.ConnectionID).
		Str("reason", reason).
		Msg("Published " + envelopeType)
	return nil
}
