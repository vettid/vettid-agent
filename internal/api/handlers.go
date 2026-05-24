package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/vettid/vettid-agent/internal/credential"
	"github.com/vettid/vettid-agent/internal/crypto"
	vettidnats "github.com/vettid/vettid-agent/internal/nats"
	"github.com/vettid/vettid-agent/internal/registration"
)

func registerRoutes(mux *http.ServeMux, s *Server) {
	mux.HandleFunc("GET /v1/secrets", s.handleListSecrets)
	mux.HandleFunc("POST /v1/secrets/request", s.handleSecretRequest)
	mux.HandleFunc("POST /v1/secrets/use", s.handleSecretUse)
	mux.HandleFunc("POST /v1/secrets/refresh", s.handleCatalogRefresh)
	mux.HandleFunc("GET /v1/requests/{requestID}", s.handleGetRequest)
	mux.HandleFunc("GET /v1/status", s.handleStatus)
	mux.HandleFunc("GET /v1/ws", s.handleWebSocket)
	mux.HandleFunc("POST /v1/messages/send", s.handleSendMessage)
	mux.HandleFunc("GET /v1/messages/inbox", s.handleMessagesInbox)
	mux.HandleFunc("POST /v1/connection/disconnect", s.handleDisconnect)
	mux.HandleFunc("POST /v1/pair/extend", s.handlePairExtend)
}

// handleMessagesInbox drains the in-memory buffer of owner→agent chat
// messages. The buffer is fed by the NATS dispatch loop in main.go
// (case MsgAgentMessageResponse). Default behavior is drain — the
// returned messages are removed from the buffer. Pass ?peek=1 to read
// without draining; useful for polling the count without consuming.
//
// Response shape:
//
//	{"messages": [...], "dropped_since_last_drain": 0}
//
// `dropped_since_last_drain` is non-zero when the buffer's bounded
// capacity (256) is reached and the oldest message was evicted to
// make room. AI processes can detect this and warn the owner that
// messages may have been lost.
func (s *Server) handleMessagesInbox(w http.ResponseWriter, r *http.Request) {
	peek := r.URL.Query().Get("peek") == "1"
	var msgs []OwnerMessage
	var dropped uint64
	if peek {
		msgs, dropped = s.inbox.Peek()
	} else {
		msgs, dropped = s.inbox.Drain()
	}
	if msgs == nil {
		msgs = []OwnerMessage{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"messages":                 msgs,
		"dropped_since_last_drain": dropped,
	})
}

// handleListSecrets returns catalog entries (metadata only). Optional ?category= filter.
func (s *Server) handleListSecrets(w http.ResponseWriter, r *http.Request) {
	category := r.URL.Query().Get("category")

	var entries []vettidnats.SecretCatalogEntry
	if category != "" {
		entries = s.catalog.ListByCategory(category)
	} else {
		entries = s.catalog.List()
	}

	if entries == nil {
		entries = []vettidnats.SecretCatalogEntry{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"secrets":         entries,
		"catalog_version": s.catalog.Version(),
	})
}

// secretRequestBody is the JSON body for POST /v1/secrets/request.
type secretRequestBody struct {
	SecretID   string `json:"secret_id"`
	SecretType string `json:"secret_type"`
	SecretName string `json:"secret_name"`
	Purpose    string `json:"purpose"`
	TTL        int    `json:"ttl"`
}

// handleSecretRequest retrieves a secret value from the vault.
func (s *Server) handleSecretRequest(w http.ResponseWriter, r *http.Request) {
	var body secretRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid request body",
		})
		return
	}

	// Require either secret_id or (secret_type + secret_name)
	if body.SecretID == "" && (body.SecretType == "" || body.SecretName == "") {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "secret_id or both secret_type and secret_name are required",
		})
		return
	}

	// If secret_id provided, validate against catalog
	if body.SecretID != "" {
		entry := s.catalog.Get(body.SecretID)
		if entry != nil {
			if !actionAllowed(entry.AllowedActions, "retrieve") {
				writeJSON(w, http.StatusForbidden, map[string]string{
					"error": "this secret is use-only; retrieve is not allowed",
				})
				return
			}
		}
		// If not in catalog, let the vault decide (catalog may be stale)
	}

	if body.Purpose == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "purpose is required",
		})
		return
	}

	if body.TTL <= 0 {
		body.TTL = 300 // default 5 minutes
	}

	// Generate request ID
	requestID, err := generateRequestID()
	if err != nil {
		log.Error().Err(err).Msg("Failed to generate request ID")
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "internal error",
		})
		return
	}

	secretReq := &vettidnats.SecretRequest{
		RequestID:  requestID,
		SecretID:   body.SecretID,
		SecretType: body.SecretType,
		SecretName: body.SecretName,
		Purpose:    body.Purpose,
		TTL:        body.TTL,
		Action:     "retrieve",
	}

	// Register in tracker before publishing
	ch := s.tracker.Add(requestID, 0)

	// Encrypt and publish via NATS
	if s.natsClient == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "NATS client not connected",
		})
		return
	}

	snap := s.Snapshot()
	seq := s.nextSequence()
	if err := s.natsClient.PublishSecretRequest(secretReq, snap.ConnKey, snap.KeyID, seq); err != nil {
		log.Error().Err(err).Msg("Failed to publish secret request")
		writeJSON(w, http.StatusBadGateway, map[string]string{
			"error": "failed to send request to vault",
		})
		return
	}

	// Wait for response
	select {
	case result := <-ch:
		switch result.Status {
		case StatusApproved:
			resp := map[string]any{
				"status":     "approved",
				"request_id": result.RequestID,
			}
			if result.SecretValue != "" {
				resp["secret_value"] = result.SecretValue
				// SECURITY: zero the secret value in the tracked result after writing
				defer func() { result.SecretValue = "" }()
			}
			if result.ExpiresAt != "" {
				resp["expires_at"] = result.ExpiresAt
			}
			writeJSON(w, http.StatusOK, resp)
		case StatusPendingApproval:
			writeJSON(w, http.StatusAccepted, map[string]any{
				"status":     "pending_approval",
				"request_id": requestID,
				"message":    "Waiting for owner approval",
			})
		case StatusDenied:
			writeJSON(w, http.StatusForbidden, map[string]any{
				"status":     "denied",
				"request_id": requestID,
				"reason":     result.Reason,
			})
		case StatusTimeout:
			writeJSON(w, http.StatusGatewayTimeout, map[string]any{
				"status":     "timeout",
				"request_id": requestID,
				"reason":     "vault did not respond in time",
			})
		default:
			writeJSON(w, http.StatusBadGateway, map[string]any{
				"status":     "error",
				"request_id": requestID,
				"reason":     result.Reason,
			})
		}
	case <-r.Context().Done():
		writeJSON(w, http.StatusGatewayTimeout, map[string]string{
			"error": "request cancelled",
		})
	}
}

// actionUseBody is the JSON body for POST /v1/secrets/use.
type actionUseBody struct {
	SecretID string          `json:"secret_id"`
	Action   string          `json:"action"` // "http_request" or "sign"
	Purpose  string          `json:"purpose"`
	Params   json.RawMessage `json:"params"`
}

// handleSecretUse executes an action with a secret inside the enclave.
func (s *Server) handleSecretUse(w http.ResponseWriter, r *http.Request) {
	var body actionUseBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid request body",
		})
		return
	}

	if body.SecretID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "secret_id is required",
		})
		return
	}

	if body.Action != "http_request" && body.Action != "sign" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "action must be 'http_request' or 'sign'",
		})
		return
	}

	if body.Purpose == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "purpose is required",
		})
		return
	}

	if len(body.Params) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "params is required",
		})
		return
	}

	// Validate against catalog
	entry := s.catalog.Get(body.SecretID)
	if entry != nil {
		if !actionAllowed(entry.AllowedActions, "use") {
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error": "use-in-enclave is not allowed for this secret",
			})
			return
		}
	}

	// Validate params based on action type
	if body.Action == "http_request" {
		var params vettidnats.HTTPRequestParams
		if err := json.Unmarshal(body.Params, &params); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "invalid http_request params",
			})
			return
		}
		if params.URL == "" || params.Method == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "http_request params require method and url",
			})
			return
		}
		if params.SecretPlacement == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "http_request params require secret_placement",
			})
			return
		}
	} else if body.Action == "sign" {
		var params vettidnats.SignRequestParams
		if err := json.Unmarshal(body.Params, &params); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "invalid sign params",
			})
			return
		}
		if params.Data == "" || params.Algorithm == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "sign params require data and algorithm",
			})
			return
		}
	}

	requestID, err := generateRequestID()
	if err != nil {
		log.Error().Err(err).Msg("Failed to generate request ID")
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "internal error",
		})
		return
	}

	actionReq := &vettidnats.ActionRequest{
		RequestID: requestID,
		SecretID:  body.SecretID,
		Action:    body.Action,
		Purpose:   body.Purpose,
		Params:    body.Params,
	}

	ch := s.tracker.Add(requestID, 0)

	if s.natsClient == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "NATS client not connected",
		})
		return
	}

	snap := s.Snapshot()
	seq := s.nextSequence()
	if err := s.natsClient.PublishActionRequest(actionReq, snap.ConnKey, snap.KeyID, seq); err != nil {
		log.Error().Err(err).Msg("Failed to publish action request")
		writeJSON(w, http.StatusBadGateway, map[string]string{
			"error": "failed to send request to vault",
		})
		return
	}

	select {
	case result := <-ch:
		switch result.Status {
		case StatusCompleted:
			resp := map[string]any{
				"status":     "completed",
				"request_id": result.RequestID,
			}
			if result.Result != nil {
				resp["result"] = result.Result
			}
			writeJSON(w, http.StatusOK, resp)
		case StatusDenied:
			writeJSON(w, http.StatusForbidden, map[string]any{
				"status":     "denied",
				"request_id": requestID,
				"reason":     result.Reason,
			})
		case StatusTimeout:
			writeJSON(w, http.StatusGatewayTimeout, map[string]any{
				"status":     "timeout",
				"request_id": requestID,
				"reason":     "vault did not respond in time",
			})
		default:
			writeJSON(w, http.StatusBadGateway, map[string]any{
				"status":     "error",
				"request_id": requestID,
				"reason":     result.Reason,
			})
		}
	case <-r.Context().Done():
		writeJSON(w, http.StatusGatewayTimeout, map[string]string{
			"error": "request cancelled",
		})
	}
}

// handleCatalogRefresh requests a catalog refresh from the vault.
func (s *Server) handleCatalogRefresh(w http.ResponseWriter, r *http.Request) {
	if s.natsClient == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "NATS client not connected",
		})
		return
	}

	req := &vettidnats.CatalogRefreshRequest{
		CurrentVersion: s.catalog.Version(),
	}

	snap := s.Snapshot()
	seq := s.nextSequence()
	if err := s.natsClient.PublishCatalogRequest(req, snap.ConnKey, snap.KeyID, seq); err != nil {
		log.Error().Err(err).Msg("Failed to publish catalog refresh request")
		writeJSON(w, http.StatusBadGateway, map[string]string{
			"error": "failed to send refresh request to vault",
		})
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]string{
		"status":  "accepted",
		"message": "catalog refresh requested",
	})
}

// handleGetRequest returns the current status of a tracked request.
func (s *Server) handleGetRequest(w http.ResponseWriter, r *http.Request) {
	requestID := r.PathValue("requestID")
	if requestID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "request ID is required",
		})
		return
	}

	result := s.tracker.Get(requestID)
	if result == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{
			"error": "request not found",
		})
		return
	}

	// SECURITY: zero secret value after writing response
	if result.SecretValue != "" {
		defer func() { result.SecretValue = "" }()
	}

	writeJSON(w, http.StatusOK, result)
}

// handleStatus returns connection health and metadata.
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	snap := s.Snapshot()
	uptime := time.Since(s.startTime).Seconds()

	resp := map[string]any{
		"connected":       s.natsClient != nil,
		"connection_id":   snap.ConnectionID,
		"scope":           snap.Scope,
		"approval_mode":   snap.ApprovalMode,
		"catalog_version": s.catalog.Version(),
		"catalog_secrets": s.catalog.Count(),
		"uptime_seconds":  math.Round(uptime),
	}
	if snap.SessionID != "" {
		resp["session_id"] = snap.SessionID
	}
	if snap.ExpiresAt > 0 {
		resp["session_expires_at"] = snap.ExpiresAt
		secondsRemaining := snap.ExpiresAt - time.Now().Unix()
		if secondsRemaining < 0 {
			secondsRemaining = 0
		}
		resp["session_seconds_remaining"] = secondsRemaining
	}
	if snap.DurationSeconds > 0 {
		resp["session_duration_seconds"] = snap.DurationSeconds
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleSendMessage sends a text message or approval request to the vault owner.
func (s *Server) handleSendMessage(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Content     string          `json:"content"`
		ContentType string          `json:"content_type"` // "text" (default) or "approval_request"
		Approval    json.RawMessage `json:"approval,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}

	if req.Content == "" && req.Approval == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "content or approval is required"})
		return
	}
	if req.ContentType == "" {
		req.ContentType = "text"
	}

	messageID, err := generateRequestID()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate message ID"})
		return
	}

	msg := &vettidnats.AgentTextMessage{
		MessageID:   messageID,
		ContentType: req.ContentType,
		Content:     req.Content,
		Approval:    req.Approval,
	}

	snap := s.Snapshot()
	seq := s.nextSequence()
	if err := s.natsClient.PublishMessage(msg, snap.ConnKey, snap.KeyID, seq); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("failed to send: %v", err)})
		return
	}

	// Register in tracker if approval request (caller may want to wait for response)
	if req.ContentType == "approval_request" {
		s.tracker.Add(messageID, 5*time.Minute) // 5 min timeout for approval
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message_id": messageID,
		"status":     "sent",
	})
}

// extendRequestBody is the JSON body for POST /v1/pair/extend. All
// fields are optional — sensible defaults come from the existing
// session.
type extendRequestBody struct {
	RequestedDurationSeconds int64    `json:"requested_duration_seconds"`
	RequestedScope           []string `json:"requested_scope"`
	RequestedApprovalMode    string   `json:"requested_approval_mode"`
	// TimeoutSeconds caps how long the embedded AI agent is willing to
	// wait for the owner to approve. Defaults to 300s (the registration
	// package default). Bounded server-side at [10s, 600s] to keep a
	// misbehaving caller from holding an HTTP socket open indefinitely.
	TimeoutSeconds int64 `json:"timeout_seconds"`
}

// handlePairExtend triggers an agent.request-session round-trip
// against the vault, waits for the owner to re-approve on their phone,
// hot-rotates the running daemon's session key in-memory, and (if
// configured) persists the rotated credentials to connection.enc.
//
// Embedded AI agents call this when they detect a session expiring
// soon (or have already hit a vault error indicating the session is
// dead). The endpoint blocks until activation, denial, or timeout —
// the AI is expected to surface a "waiting for phone approval" UI
// while it's open.
//
// On success the response carries the new session metadata; the
// caller's next encrypted op uses the rotated key automatically (every
// handler reads through Snapshot() before each publish).
func (s *Server) handlePairExtend(w http.ResponseWriter, r *http.Request) {
	if s.scopedJWT == "" || s.scopedSeed == "" || s.messageSpaceURL == "" {
		// Server was constructed without the persistence material —
		// /v1/pair/extend isn't usable. This branch exists so older
		// callers of NewServer (or tests) get a clean 501 rather than
		// a confusing "missing NATS creds" deeper in the registration
		// path.
		writeJSON(w, http.StatusNotImplemented, map[string]string{
			"error": "server not configured for hot-rotate (extend disabled)",
		})
		return
	}

	var body extendRequestBody
	if r.Body != nil && r.ContentLength != 0 {
		// Body is optional — a bare POST is the common "use defaults"
		// case. Reject malformed JSON but tolerate an empty body.
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
	}
	if body.RequestedApprovalMode == "" {
		// Default to the policy already in force — most callers don't
		// want to renegotiate approval semantics on extend.
		body.RequestedApprovalMode = s.Snapshot().ApprovalMode
	}
	timeout := time.Duration(body.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = registration.DefaultApprovalWait
	}
	if timeout < 10*time.Second {
		timeout = 10 * time.Second
	}
	if timeout > 10*time.Minute {
		timeout = 10 * time.Minute
	}

	// Build a transient ConnectionCredentials snapshot for the
	// registration helper. The handler doesn't have access to the
	// passphrase, so this lives entirely in memory and is never sealed
	// via this object (the persister closure does the seal).
	snap := s.Snapshot()
	creds := &credential.ConnectionCredentials{
		ConnectionID:           snap.ConnectionID,
		ConnectionKey:          snap.ConnKey,
		KeyID:                  snap.KeyID,
		AgentPrivateKey:        s.agentPriv,
		AgentPublicKey:         s.agentPub,
		VaultPublicKey:         s.vaultPub,
		JWT:                    s.scopedJWT,
		Seed:                   s.scopedSeed,
		MessageSpaceURL:        s.messageSpaceURL,
		OwnerGUID:              snap.OwnerGUID,
		Scope:                  snap.Scope,
		ApprovalMode:           snap.ApprovalMode,
		SessionID:              snap.SessionID,
		SessionExpiresAt:       snap.ExpiresAt,
		SessionDurationSeconds: snap.DurationSeconds,
	}

	// Tie the helper's deadline to the HTTP request's context so a
	// disconnected client (AI agent crashed, parent process killed)
	// cancels the round-trip promptly rather than holding the pull
	// consumer + NATS connection until timeout. 30s grace above the
	// approval-wait window lets ExtendSession run its bookkeeping
	// (subscribe-flush, HKDF, etc.) after the inner deadline fires.
	ctx, cancel := context.WithTimeout(r.Context(), timeout+30*time.Second)
	defer cancel()

	outcome, err := registration.ExtendSession(ctx, creds, registration.CompletePairingOptions{
		Timeout:               timeout,
		RequestedScope:        body.RequestedScope,
		RequestedApprovalMode: body.RequestedApprovalMode,
		RequestedDurationSecs: body.RequestedDurationSeconds,
	})
	if err != nil {
		log.Warn().Err(err).Msg("pair/extend failed")
		// Map a few common shapes to a useful status code. Anything
		// else is 502 Bad Gateway — the vault is reachable but didn't
		// give us a clean activation.
		status := http.StatusBadGateway
		if isDeniedError(err) {
			status = http.StatusForbidden
		} else if isTimeoutError(err) {
			status = http.StatusGatewayTimeout
		}
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}

	// Adopt the new session in memory before doing anything else. From
	// this point on, every handler sees the rotated key.
	s.RotateSession(
		outcome.SessionKey,
		outcome.GrantedScope,
		outcome.ApprovalMode,
		outcome.SessionID,
		outcome.ExpiresAt,
		outcome.DurationSeconds,
	)
	// Update the persistence material in step — vaultPub and the
	// agent keypair changed too, and the persister needs to seal the
	// fresh values.
	s.sessionMu.Lock()
	s.agentPriv = append([]byte(nil), outcome.AgentKeyPair.PrivateKey[:]...)
	s.agentPub = append([]byte(nil), outcome.AgentKeyPair.PublicKey[:]...)
	s.vaultPub = outcome.VaultPubKey
	s.sessionMu.Unlock()

	persisted := false
	if s.persist != nil {
		persistCreds := &credential.ConnectionCredentials{
			ConnectionID:           snap.ConnectionID,
			ConnectionKey:          outcome.SessionKey,
			KeyID:                  snap.KeyID,
			AgentPrivateKey:        append([]byte(nil), outcome.AgentKeyPair.PrivateKey[:]...),
			AgentPublicKey:         append([]byte(nil), outcome.AgentKeyPair.PublicKey[:]...),
			VaultPublicKey:         outcome.VaultPubKey,
			JWT:                    s.scopedJWT,
			Seed:                   s.scopedSeed,
			MessageSpaceURL:        s.messageSpaceURL,
			OwnerGUID:              snap.OwnerGUID,
			Scope:                  outcome.GrantedScope,
			ApprovalMode:           outcome.ApprovalMode,
			SessionID:              outcome.SessionID,
			SessionExpiresAt:       outcome.ExpiresAt,
			SessionDurationSeconds: outcome.DurationSeconds,
		}
		if perr := s.persist(persistCreds); perr != nil {
			log.Warn().Err(perr).Msg("pair/extend: in-memory rotate OK but persist failed; restart will require manual extend")
		} else {
			persisted = true
		}
		// The persistCreds object owns copies — zero them now that
		// they've been written. The Server-held copies of agentPriv
		// remain live.
		persistCreds.Zero()
	}

	resp := map[string]any{
		"connection_id":            snap.ConnectionID,
		"session_id":               outcome.SessionID,
		"expires_at":               outcome.ExpiresAt,
		"duration_seconds":         outcome.DurationSeconds,
		"granted_scope":            outcome.GrantedScope,
		"approval_mode":            outcome.ApprovalMode,
		"hot_rotated":              true,
		"persisted":                persisted,
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleDisconnect(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusNotImplemented, map[string]string{
		"error": "not yet implemented",
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// SECURITY (#114): surface encode failures rather than swallow them.
	// A short-write or hostile io.Pipe peer would otherwise produce a
	// successful-looking response while the client got a truncated /
	// malformed body — masks bugs and complicates incident triage.
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Warn().Err(err).Int("status", status).Msg("writeJSON: encode failed")
	}
}

// generateRequestID returns a 128-bit random hex string.
func generateRequestID() (string, error) {
	b, err := crypto.GenerateRandomBytes(16)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// actionAllowed checks if the given action is in the allowed_actions list.
func actionAllowed(allowedActions []string, action string) bool {
	for _, a := range allowedActions {
		if a == action {
			return true
		}
	}
	return false
}

// isDeniedError matches the error shape registration.ExtendSession returns
// when the owner taps Deny — "owner denied extend: <reason>".
func isDeniedError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "owner denied")
}

// isTimeoutError matches the timeout-on-approval shape from
// registration.ExtendSession. Doesn't catch every timeout (network-level
// errors look different), but those are correctly classified as 502s by
// the default branch.
func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "timed out") || strings.Contains(msg, "deadline exceeded")
}
