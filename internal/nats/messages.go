package nats

import (
	"encoding/json"
	"fmt"
	"time"
)

type MessageType string

const (
	MsgAgentConnectionRequest MessageType = "agent_connection_request"
	MsgAgentConnectionApproved MessageType = "agent_connection_approved"
	MsgAgentConnectionDenied   MessageType = "agent_connection_denied"
	MsgSecretRequest          MessageType = "agent_secret_request"
	MsgSecretResponse         MessageType = "agent_secret_response"
	MsgKeyRotationInitiate    MessageType = "key_rotation_initiate"
	MsgKeyRotationAck         MessageType = "key_rotation_ack"
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
	ConnectionID          string   `json:"connection_id"`
	ConnectionKeyEncrypted []byte  `json:"connection_key_encrypted"`
	KeyID                 string   `json:"key_id"`
	MessageSpaceToken     string   `json:"messagespace_token"`
	TokenExpires          string   `json:"token_expires"`
	Contract              Contract `json:"contract"`
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
	SecretType string `json:"secret_type"`
	SecretName string `json:"secret_name"`
	Purpose    string `json:"purpose"`
	TTL        int    `json:"ttl"`
	Action     string `json:"action"` // "retrieve" or "use"
}

type SecretResponse struct {
	RequestID   string `json:"request_id"`
	Status      string `json:"status"` // "approved", "denied", "pending_approval"
	SecretValue string `json:"secret_value,omitempty"`
	ExpiresAt   string `json:"expires_at,omitempty"`
	Reason      string `json:"reason,omitempty"`
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
