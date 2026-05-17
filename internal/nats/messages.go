package nats

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// MessageType constants for NATS envelope types.

type MessageType string

const (
	MsgAgentConnectionRequest MessageType = "agent_connection_request"
	MsgAgentConnectionApproved MessageType = "agent_connection_approved"
	MsgAgentConnectionDenied   MessageType = "agent_connection_denied"
	MsgSecretRequest          MessageType = "agent_secret_request"
	MsgSecretResponse         MessageType = "agent_secret_response"
	MsgKeyRotationInitiate    MessageType = "key_rotation_initiate"
	MsgKeyRotationAck         MessageType = "key_rotation_ack"
	MsgAgentSecretCatalog     MessageType = "agent_secret_catalog"    // vault → agent: pushed catalog
	MsgAgentCatalogRequest    MessageType = "agent_catalog_request"   // agent → vault: refresh request
	MsgAgentActionRequest     MessageType = "agent_action_request"    // agent → vault: use-in-enclave
	MsgAgentActionResponse    MessageType = "agent_action_response"   // vault → agent: action result
	MsgAgentMessage           MessageType = "agent_message"           // agent → vault: text/approval message
	MsgAgentMessageResponse   MessageType = "agent_message_response"  // vault → agent: user reply
)

type Envelope struct {
	Type      MessageType `json:"type"`
	KeyID     string      `json:"key_id"`
	Payload   []byte      `json:"payload"` // Encrypted
	Timestamp time.Time   `json:"timestamp"`
	Sequence  uint64      `json:"sequence"`
}

type AgentRegistration struct {
	AgentType          string `json:"agent_type"`
	IPAddress          string `json:"ip_address"`
	Hostname           string `json:"hostname"`
	Platform           string `json:"platform"`
	BinaryFingerprint  string `json:"binary_fingerprint"`
	MachineFingerprint string `json:"machine_fingerprint"`
}

type ConnectionRequest struct {
	InvitationID   string            `json:"invitation_id"`
	AgentPublicKey []byte            `json:"agent_public_key"`
	Registration   AgentRegistration `json:"registration"`
	Timestamp      time.Time         `json:"timestamp"`
}

type ConnectionApproval struct {
	ConnectionID string   `json:"connection_id"`
	KeyID        string   `json:"key_id"`
	Contract     Contract `json:"contract"`
}

type ConnectionDenial struct {
	Reason string `json:"reason"`
}

type Contract struct {
	Scope        []string  `json:"scope"`
	ApprovalMode string    `json:"approval_mode"`
	RateLimit    RateLimit `json:"rate_limit"`
}

type RateLimit struct {
	Max int    `json:"max"`
	Per string `json:"per"`
}

type SecretRequest struct {
	RequestID  string `json:"request_id"`
	SecretID   string `json:"secret_id,omitempty"`   // preferred: from catalog
	SecretType string `json:"secret_type,omitempty"` // fallback: category
	SecretName string `json:"secret_name,omitempty"` // fallback: name
	Purpose    string `json:"purpose"`
	TTL        int    `json:"ttl"`
	Action     string `json:"action"` // "retrieve"
}

type SecretResponse struct {
	RequestID   string `json:"request_id"`
	Status      string `json:"status"` // "approved", "denied", "pending_approval"
	SecretValue string `json:"secret_value,omitempty"`
	ExpiresAt   string `json:"expires_at,omitempty"`
	Reason      string `json:"reason,omitempty"`
}

// SecretCatalogEntry describes a single secret available to the agent.
type SecretCatalogEntry struct {
	SecretID       string   `json:"secret_id"`
	Name           string   `json:"name"`
	Category       string   `json:"category"`
	Description    string   `json:"description,omitempty"`
	Tags           []string `json:"tags,omitempty"`
	AllowedActions []string `json:"allowed_actions"` // ["retrieve"], ["use"], or ["retrieve","use"]
	UpdatedAt      string   `json:"updated_at,omitempty"`
}

// SecretCatalog is a versioned list of secrets pushed from the vault.
type SecretCatalog struct {
	Entries   []SecretCatalogEntry `json:"entries"`
	Version   uint64               `json:"version"`
	UpdatedAt string               `json:"updated_at"`
}

// CatalogRefreshRequest asks the vault to re-push the catalog.
type CatalogRefreshRequest struct {
	CurrentVersion uint64 `json:"current_version"`
}

// ActionRequest sends an operation to be executed in the enclave using a secret.
type ActionRequest struct {
	RequestID string          `json:"request_id"`
	SecretID  string          `json:"secret_id"`
	Action    string          `json:"action"`  // "http_request", "sign"
	Purpose   string          `json:"purpose"`
	Params    json.RawMessage `json:"params"` // action-specific parameters
}

// HTTPRequestParams specifies an HTTP request to be made by the enclave.
type HTTPRequestParams struct {
	Method          string            `json:"method"`
	URL             string            `json:"url"`
	Headers         map[string]string `json:"headers,omitempty"`
	Body            string            `json:"body,omitempty"`
	SecretPlacement string            `json:"secret_placement"` // "bearer", "header", "query", "basic_auth"
	SecretField     string            `json:"secret_field,omitempty"`
}

// SignRequestParams specifies data to be signed by the enclave.
type SignRequestParams struct {
	Data      string `json:"data"`      // base64-encoded
	Algorithm string `json:"algorithm"` // "ed25519", "hmac-sha256"
}

// ActionResponse is the vault's response to an ActionRequest.
type ActionResponse struct {
	RequestID string          `json:"request_id"`
	Status    string          `json:"status"` // "completed", "denied", "error"
	Result    json.RawMessage `json:"result,omitempty"`
	Reason    string          `json:"reason,omitempty"`
}

// HTTPResponseResult is the result of an HTTP request executed by the enclave.
type HTTPResponseResult struct {
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers,omitempty"`
	Body       string            `json:"body"`
}

// SignResult is the result of a signing operation executed by the enclave.
type SignResult struct {
	Signature string `json:"signature"` // base64-encoded
	Algorithm string `json:"algorithm"`
}

// AgentTextMessage is a message sent from the agent to the vault owner.
type AgentTextMessage struct {
	MessageID   string          `json:"message_id"`
	ContentType string          `json:"content_type"` // "text" or "approval_request"
	Content     string          `json:"content"`
	Approval    json.RawMessage `json:"approval,omitempty"`
}

// ApprovalPayload is the structured content for an approval_request message.
type ApprovalPayload struct {
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Options     []string          `json:"options"` // e.g., ["approve", "deny"]
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// AgentMessageResponse is a reply from the vault owner to an agent message.
type AgentMessageResponse struct {
	MessageID    string `json:"message_id"`
	ReplyTo      string `json:"reply_to,omitempty"`
	ReplyContent string `json:"reply_content,omitempty"`
	Action       string `json:"action,omitempty"` // "approve" or "deny" for approval responses
}

// EncodeEnvelope marshals an Envelope with the given fields and current timestamp.
func EncodeEnvelope(msgType MessageType, keyID string, payload []byte, seq uint64) ([]byte, error) {
	env := Envelope{
		Type:      msgType,
		KeyID:     keyID,
		Payload:   payload,
		Timestamp: time.Now().UTC(),
		Sequence:  seq,
	}

	data, err := json.Marshal(&env)
	if err != nil {
		return nil, fmt.Errorf("encode envelope: %w", err)
	}
	return data, nil
}

// DecodeEnvelope unmarshals data into an Envelope and validates required fields.
func DecodeEnvelope(data []byte) (*Envelope, error) {
	var env Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("decode envelope: %w", err)
	}

	if env.Type == "" {
		return nil, fmt.Errorf("decode envelope: missing type field")
	}

	return &env, nil
}

// SECURITY (#56 + #57): bounds for inbound envelope validation.
//   • maxInboundSkew: how far in the past/future a timestamp may sit
//     before we treat the envelope as a replay attempt. The vault
//     stamps Timestamp at publish; clock skew across enclave +
//     parent + agent in steady state is well under a minute, but we
//     leave a wider window to survive load-related queue delays.
//   • maxFutureSkew: a separate, tighter cap on future-skew because
//     no honest sender produces messages from the future.
const (
	maxInboundSkew = 5 * time.Minute
	maxFutureSkew  = 30 * time.Second
)

// EnvelopeValidator enforces:
//
//	#56 — monotonic inbound sequence numbers. The vault stamps Sequence
//	      on every outbound envelope; the agent refuses any inbound
//	      Sequence that is not strictly greater than the previous
//	      accepted one. Defeats replay of captured envelopes.
//	#57 — bounded inbound Timestamp. Refuses envelopes whose Timestamp
//	      is more than maxInboundSkew in the past or maxFutureSkew in
//	      the future. Defeats long-stored replays even if the attacker
//	      could mint a fresh-looking Sequence (they can't, but defence
//	      in depth).
//
// The validator is process-scoped — there is only one MessageSpace
// subscription per agent instance — and is reset on every agent
// restart (sequence-counter persistence across restarts is the
// vault's job; the agent crashing and resubscribing is not a replay).
type EnvelopeValidator struct {
	mu          sync.Mutex
	lastSeqSeen uint64
	now         func() time.Time
}

func NewEnvelopeValidator() *EnvelopeValidator {
	return &EnvelopeValidator{now: time.Now}
}

// Validate rejects envelopes that fail sequence or timestamp checks.
// Returns nil on accept. Updates lastSeqSeen on accept; rejects do
// not advance the counter so a transient out-of-order packet doesn't
// permanently lock out a legitimate later one.
func (v *EnvelopeValidator) Validate(env *Envelope) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	now := v.now().UTC()
	if env.Timestamp.IsZero() {
		return fmt.Errorf("envelope timestamp missing")
	}
	age := now.Sub(env.Timestamp)
	if age > maxInboundSkew {
		return fmt.Errorf("envelope too old: %s past tolerance", age-maxInboundSkew)
	}
	if -age > maxFutureSkew {
		return fmt.Errorf("envelope future-dated: %s ahead of tolerance", -age-maxFutureSkew)
	}

	if env.Sequence == 0 {
		return fmt.Errorf("envelope sequence missing")
	}
	if env.Sequence <= v.lastSeqSeen {
		return fmt.Errorf("envelope sequence %d <= last seen %d (replay?)", env.Sequence, v.lastSeqSeen)
	}
	v.lastSeqSeen = env.Sequence
	return nil
}
