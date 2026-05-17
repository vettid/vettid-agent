package api

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/rs/zerolog/log"

	vettidnats "github.com/vettid/vettid-agent/internal/nats"
)

// newUpgrader creates a WebSocket upgrader with origin validation.
func newUpgrader(allowedOrigins []string) websocket.Upgrader {
	return websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			origin := r.Header.Get("Origin")
			if origin == "" {
				// No origin header — allow (non-browser clients)
				return true
			}
			for _, allowed := range allowedOrigins {
				if origin == allowed ||
					origin == "http://"+allowed ||
					origin == "https://"+allowed {
					return true
				}
			}
			log.Warn().Str("origin", origin).Msg("WebSocket origin rejected")
			return false
		},
	}
}

// wsRequest is a JSON-RPC style request from a WebSocket client.
type wsRequest struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

// wsResponse is a JSON-RPC style response to a WebSocket client.
type wsResponse struct {
	ID     json.RawMessage `json:"id"`
	Result any             `json:"result,omitempty"`
	Error  *wsError        `json:"error,omitempty"`
}

type wsError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// wsConn wraps a websocket.Conn with a write mutex for thread-safe writes.
type wsConn struct {
	conn *websocket.Conn
	mu   sync.Mutex
}

func (wc *wsConn) writeJSON(v any) error {
	wc.mu.Lock()
	defer wc.mu.Unlock()
	return wc.conn.WriteJSON(v)
}

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// SECURITY (#61): WebSocket session token must arrive in the
	// Authorization header (Bearer scheme) or the X-VettID-Token
	// header. Previously the token rode the URL query string —
	// which gets logged into access logs, browser history, and
	// process-args style telemetry — exposing the secret to any
	// component that can read those streams.
	//
	// Backwards-compat path: still accept ?token= for one release
	// so existing clients keep working; log a Warn so the migration
	// is visible to operators. Remove the query-string path once
	// every shipped client has moved.
	var token string
	if auth := r.Header.Get("Authorization"); auth != "" {
		const bearer = "Bearer "
		if len(auth) > len(bearer) && auth[:len(bearer)] == bearer {
			token = auth[len(bearer):]
		}
	}
	if token == "" {
		token = r.Header.Get("X-VettID-Token")
	}
	if token == "" {
		token = r.URL.Query().Get("token")
		if token != "" {
			log.Warn().Msg("WebSocket token supplied via deprecated ?token= query string — switch to Authorization: Bearer or X-VettID-Token header")
		}
	}
	if token == "" || token != s.wsToken {
		http.Error(w, "invalid or missing token", http.StatusUnauthorized)
		return
	}

	wsUpgrader := newUpgrader(s.allowedOrigins)
	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Error().Err(err).Msg("WebSocket upgrade failed")
		return
	}
	defer conn.Close()

	// SECURITY (#113): connCtx is cancelled when this handler returns
	// (client disconnect, network error, server shutdown). The
	// per-request goroutines below select on <-connCtx.Done() so they
	// don't park forever waiting on a tracker channel that will never
	// resolve. Without this cancel, a client that connects → fires a
	// secrets.request → drops the TCP socket leaks one goroutine per
	// request indefinitely.
	connCtx, cancelConn := context.WithCancel(r.Context())
	defer cancelConn()

	wc := &wsConn{conn: conn}
	log.Info().Msg("WebSocket client connected")

	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				log.Info().Msg("WebSocket client disconnected")
			} else {
				log.Error().Err(err).Msg("WebSocket read error")
			}
			return
		}

		var req wsRequest
		if err := json.Unmarshal(message, &req); err != nil {
			wc.writeJSON(wsResponse{
				Error: &wsError{Code: -32700, Message: "parse error"},
			})
			continue
		}

		if req.Method == "" {
			wc.writeJSON(wsResponse{
				ID:    req.ID,
				Error: &wsError{Code: -32600, Message: "method is required"},
			})
			continue
		}

		// Dispatch based on method — blocking methods run in goroutines.
		// Each blocking handler receives connCtx so it can bail out
		// when the client disconnects.
		switch req.Method {
		case "secrets.list":
			s.wsHandleListSecrets(wc, req)
		case "secrets.request":
			go s.wsHandleSecretRequest(connCtx, wc, req)
		case "secrets.use":
			go s.wsHandleSecretUse(connCtx, wc, req)
		case "secrets.refresh":
			s.wsHandleCatalogRefresh(wc, req)
		case "requests.get":
			s.wsHandleGetRequest(wc, req)
		case "status":
			s.wsHandleStatus(wc, req)
		default:
			wc.writeJSON(wsResponse{
				ID:    req.ID,
				Error: &wsError{Code: -32601, Message: "method not found"},
			})
		}
	}
}

func (s *Server) wsHandleListSecrets(wc *wsConn, req wsRequest) {
	var params struct {
		Category string `json:"category"`
	}
	if req.Params != nil {
		json.Unmarshal(req.Params, &params)
	}

	var entries any
	if params.Category != "" {
		entries = s.catalog.ListByCategory(params.Category)
	} else {
		entries = s.catalog.List()
	}

	wc.writeJSON(wsResponse{
		ID: req.ID,
		Result: map[string]any{
			"secrets":         entries,
			"catalog_version": s.catalog.Version(),
		},
	})
}

func (s *Server) wsHandleSecretRequest(ctx context.Context, wc *wsConn, req wsRequest) {
	var body secretRequestBody
	if err := json.Unmarshal(req.Params, &body); err != nil {
		wc.writeJSON(wsResponse{
			ID:    req.ID,
			Error: &wsError{Code: -32602, Message: "invalid params"},
		})
		return
	}

	if body.SecretID == "" && (body.SecretType == "" || body.SecretName == "") {
		wc.writeJSON(wsResponse{
			ID:    req.ID,
			Error: &wsError{Code: -32602, Message: "secret_id or both secret_type and secret_name required"},
		})
		return
	}

	if body.SecretID != "" {
		entry := s.catalog.Get(body.SecretID)
		if entry != nil && !actionAllowed(entry.AllowedActions, "retrieve") {
			wc.writeJSON(wsResponse{
				ID:    req.ID,
				Error: &wsError{Code: -32003, Message: "this secret is use-only; retrieve is not allowed"},
			})
			return
		}
	}

	if body.Purpose == "" {
		wc.writeJSON(wsResponse{
			ID:    req.ID,
			Error: &wsError{Code: -32602, Message: "purpose is required"},
		})
		return
	}

	if body.TTL <= 0 {
		body.TTL = 300
	}

	requestID, err := generateRequestID()
	if err != nil {
		wc.writeJSON(wsResponse{
			ID:    req.ID,
			Error: &wsError{Code: -32000, Message: "internal error"},
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

	ch := s.tracker.Add(requestID, 0)

	if s.natsClient == nil {
		wc.writeJSON(wsResponse{
			ID:    req.ID,
			Error: &wsError{Code: -32001, Message: "NATS client not connected"},
		})
		return
	}

	seq := s.nextSequence()
	if err := s.natsClient.PublishSecretRequest(secretReq, s.connKey, s.keyID, seq); err != nil {
		wc.writeJSON(wsResponse{
			ID:    req.ID,
			Error: &wsError{Code: -32002, Message: "failed to send request to vault"},
		})
		return
	}

	// SECURITY (#113): bail out if the WS client disconnected while
	// we were waiting on the vault.
	var result *TrackedResult
	select {
	case result = <-ch:
	case <-ctx.Done():
		log.Debug().Str("request_id", requestID).Msg("WS secrets.request abandoned — client disconnected")
		return
	}

	resp := map[string]any{
		"status":     result.Status,
		"request_id": result.RequestID,
	}
	if result.SecretValue != "" {
		resp["secret_value"] = result.SecretValue
		// SECURITY: zero after sending
		defer func() { result.SecretValue = "" }()
	}
	if result.ExpiresAt != "" {
		resp["expires_at"] = result.ExpiresAt
	}
	if result.Reason != "" {
		resp["reason"] = result.Reason
	}

	wc.writeJSON(wsResponse{ID: req.ID, Result: resp})
}

func (s *Server) wsHandleSecretUse(ctx context.Context, wc *wsConn, req wsRequest) {
	var body actionUseBody
	if err := json.Unmarshal(req.Params, &body); err != nil {
		wc.writeJSON(wsResponse{
			ID:    req.ID,
			Error: &wsError{Code: -32602, Message: "invalid params"},
		})
		return
	}

	if body.SecretID == "" {
		wc.writeJSON(wsResponse{
			ID:    req.ID,
			Error: &wsError{Code: -32602, Message: "secret_id is required"},
		})
		return
	}

	if body.Action != "http_request" && body.Action != "sign" {
		wc.writeJSON(wsResponse{
			ID:    req.ID,
			Error: &wsError{Code: -32602, Message: "action must be 'http_request' or 'sign'"},
		})
		return
	}

	if body.Purpose == "" {
		wc.writeJSON(wsResponse{
			ID:    req.ID,
			Error: &wsError{Code: -32602, Message: "purpose is required"},
		})
		return
	}

	if len(body.Params) == 0 {
		wc.writeJSON(wsResponse{
			ID:    req.ID,
			Error: &wsError{Code: -32602, Message: "params is required"},
		})
		return
	}

	entry := s.catalog.Get(body.SecretID)
	if entry != nil && !actionAllowed(entry.AllowedActions, "use") {
		wc.writeJSON(wsResponse{
			ID:    req.ID,
			Error: &wsError{Code: -32003, Message: "use-in-enclave is not allowed for this secret"},
		})
		return
	}

	requestID, err := generateRequestID()
	if err != nil {
		wc.writeJSON(wsResponse{
			ID:    req.ID,
			Error: &wsError{Code: -32000, Message: "internal error"},
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
		wc.writeJSON(wsResponse{
			ID:    req.ID,
			Error: &wsError{Code: -32001, Message: "NATS client not connected"},
		})
		return
	}

	seq := s.nextSequence()
	if err := s.natsClient.PublishActionRequest(actionReq, s.connKey, s.keyID, seq); err != nil {
		wc.writeJSON(wsResponse{
			ID:    req.ID,
			Error: &wsError{Code: -32002, Message: "failed to send request to vault"},
		})
		return
	}

	// SECURITY (#113): bail out if the WS client disconnected while
	// we were waiting on the vault.
	var result *TrackedResult
	select {
	case result = <-ch:
	case <-ctx.Done():
		log.Debug().Str("request_id", requestID).Msg("WS secrets.use abandoned — client disconnected")
		return
	}

	resp := map[string]any{
		"status":     result.Status,
		"request_id": result.RequestID,
	}
	if result.Result != nil {
		resp["result"] = result.Result
	}
	if result.Reason != "" {
		resp["reason"] = result.Reason
	}

	wc.writeJSON(wsResponse{ID: req.ID, Result: resp})
}

func (s *Server) wsHandleCatalogRefresh(wc *wsConn, req wsRequest) {
	if s.natsClient == nil {
		wc.writeJSON(wsResponse{
			ID:    req.ID,
			Error: &wsError{Code: -32001, Message: "NATS client not connected"},
		})
		return
	}

	catalogReq := &vettidnats.CatalogRefreshRequest{
		CurrentVersion: s.catalog.Version(),
	}

	seq := s.nextSequence()
	if err := s.natsClient.PublishCatalogRequest(catalogReq, s.connKey, s.keyID, seq); err != nil {
		wc.writeJSON(wsResponse{
			ID:    req.ID,
			Error: &wsError{Code: -32002, Message: "failed to send refresh request"},
		})
		return
	}

	wc.writeJSON(wsResponse{
		ID: req.ID,
		Result: map[string]string{
			"status":  "accepted",
			"message": "catalog refresh requested",
		},
	})
}

func (s *Server) wsHandleGetRequest(wc *wsConn, req wsRequest) {
	var params struct {
		RequestID string `json:"request_id"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil || params.RequestID == "" {
		wc.writeJSON(wsResponse{
			ID:    req.ID,
			Error: &wsError{Code: -32602, Message: "request_id is required"},
		})
		return
	}

	result := s.tracker.Get(params.RequestID)
	if result == nil {
		wc.writeJSON(wsResponse{
			ID:    req.ID,
			Error: &wsError{Code: -32004, Message: "request not found"},
		})
		return
	}

	// SECURITY: zero secret value after sending
	if result.SecretValue != "" {
		defer func() { result.SecretValue = "" }()
	}

	wc.writeJSON(wsResponse{ID: req.ID, Result: result})
}

func (s *Server) wsHandleStatus(wc *wsConn, req wsRequest) {
	uptime := time.Since(s.startTime).Seconds()

	wc.writeJSON(wsResponse{
		ID: req.ID,
		Result: map[string]any{
			"connected":       s.natsClient != nil,
			"connection_id":   s.connectionID,
			"scope":           s.scope,
			"approval_mode":   s.approvalMode,
			"catalog_version": s.catalog.Version(),
			"catalog_secrets": s.catalog.Count(),
			"uptime_seconds":  math.Round(uptime),
		},
	})
}
