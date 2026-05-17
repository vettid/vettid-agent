package api

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/vettid/vettid-agent/internal/crypto"
	vettidnats "github.com/vettid/vettid-agent/internal/nats"
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
	mux.HandleFunc("POST /v1/connection/disconnect", s.handleDisconnect)
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

	seq := s.nextSequence()
	if err := s.natsClient.PublishSecretRequest(secretReq, s.connKey, s.keyID, seq); err != nil {
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

	seq := s.nextSequence()
	if err := s.natsClient.PublishActionRequest(actionReq, s.connKey, s.keyID, seq); err != nil {
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

	seq := s.nextSequence()
	if err := s.natsClient.PublishCatalogRequest(req, s.connKey, s.keyID, seq); err != nil {
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
	uptime := time.Since(s.startTime).Seconds()

	writeJSON(w, http.StatusOK, map[string]any{
		"connected":       s.natsClient != nil,
		"connection_id":   s.connectionID,
		"scope":           s.scope,
		"approval_mode":   s.approvalMode,
		"catalog_version": s.catalog.Version(),
		"catalog_secrets": s.catalog.Count(),
		"uptime_seconds":  math.Round(uptime),
	})
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

	seq := s.nextSequence()
	if err := s.natsClient.PublishMessage(msg, s.connKey, s.keyID, seq); err != nil {
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
