// Package api provides the local REST API and WebSocket server
// for the VettID Agent Connector.
package api

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/vettid/vettid-agent/internal/credential"
	vettidnats "github.com/vettid/vettid-agent/internal/nats"
)

type Server struct {
	httpServer     *http.Server
	listener       net.Listener
	wsToken        string
	allowedOrigins []string
	// SECURITY (#63): when the API listens on TCP every inbound REST
	// request is also required to carry the wsToken in the
	// Authorization: Bearer / X-VettID-Token header. Unix-socket mode
	// skips this — the socket file's 0600 perms (set in Start()) are
	// the authentication surface.
	requireRESTAuth bool
	natsClient      *vettidnats.Client

	// Persistence + identity material needed by /v1/pair/extend. These
	// don't rotate, so they live alongside the rotatable sessionState
	// rather than inside it. NATS creds (JWT/Seed) survive across
	// extends — the per-pair scope was minted at init time and isn't
	// revoked unless the connection itself is revoked.
	messageSpaceURL string
	scopedJWT       string
	scopedSeed      string
	agentPriv       []byte
	agentPub        []byte
	vaultPub        []byte
	persist         Persister

	// Session state (rotatable). Phase 5 split this out so the
	// /v1/pair/extend endpoint can hot-rotate the session key after a
	// successful extend round-trip without forcing a process restart.
	//
	// Every handler reads through Snapshot(); the extend handler swaps
	// via RotateSession(). The mutex is RW because the snapshot is hot
	// (every request) and the swap is cold (once per session lifetime).
	//
	// The stored ConnectionID + OwnerGUID never change after init —
	// they're under the same mutex purely so a single read snapshot
	// gets a consistent view of every credential field at once.
	sessionMu    sync.RWMutex
	sessionState sessionState

	catalog   *CatalogCache
	tracker   *RequestTracker
	inbox     *MessageInbox
	sequence  atomic.Uint64
	startTime time.Time

	// Set of currently-connected WebSocket clients. BroadcastEvent
	// iterates this to push server-originated events (owner messages,
	// future: session lifecycle, etc.) to every connected AI
	// process. Registered after the WS upgrade succeeds; unregistered
	// when the per-conn read loop returns (defer in handleWebSocket).
	wsClientsMu sync.RWMutex
	wsClients   map[*wsConn]struct{}
}

// sessionState is the rotatable credential view a handler sees. Pulled
// via Server.Snapshot(); zero value is meaningless (always set in
// NewServer before any handler runs).
type sessionState struct {
	ConnKey         []byte
	KeyID           string
	ConnectionID    string
	OwnerGUID       string
	Scope           []string
	ApprovalMode    string
	SessionID       string
	ExpiresAt       int64
	DurationSeconds int64
}

// Persister re-seals the rotated credentials to disk after a successful
// hot-rotate via POST /v1/pair/extend. main.go provides a closure that
// captures the passphrase + platform key so the API package doesn't
// have to know about secrets it can't justify holding.
//
// Returning a non-nil error from the persister is non-fatal — the
// running daemon has already adopted the new session key in memory, so
// returning success keeps the AI agent unblocked. The error is logged
// for operator visibility, and the next `vettid-agent extend` (or
// daemon restart) reconciles disk. Persister implementations should
// log internally too if they want detail beyond what the handler logs.
type Persister func(creds *credential.ConnectionCredentials) error

type ServerConfig struct {
	Listen         string // "unix:///path/to/socket" or "tcp://127.0.0.1:7443"
	WSToken        string
	AllowedOrigins []string // WebSocket origin validation
	NATSClient     *vettidnats.Client
	ConnKey        []byte
	KeyID          string
	ConnectionID   string
	OwnerGUID      string
	Scope          []string
	ApprovalMode   string
	// Optional session-state fields (added Phase 5 for /v1/pair/extend
	// + `status`). Existing callers that don't set these still work —
	// status simply reports "session info unavailable".
	SessionID              string
	SessionExpiresAt       int64
	SessionDurationSeconds int64
	RequestTimeout         time.Duration

	// MessageSpaceURL / JWT / Seed / AgentPrivateKey / AgentPublicKey /
	// VaultPublicKey carry the rest of ConnectionCredentials that the
	// /v1/pair/extend handler needs to build a fresh InviteSession for
	// the rotate round-trip (without re-reading the encrypted store).
	MessageSpaceURL string
	JWT             string
	Seed            string
	AgentPrivateKey []byte
	AgentPublicKey  []byte
	VaultPublicKey  []byte

	// Persist re-seals the rotated credentials back to disk. If nil,
	// the /v1/pair/extend endpoint succeeds at hot-rotating in-memory
	// but returns a `persisted:false` flag so the caller knows the
	// next daemon restart will have to re-extend.
	Persist Persister
}

func NewServer(cfg *ServerConfig) (*Server, error) {
	mux := http.NewServeMux()

	requestTimeout := cfg.RequestTimeout
	if requestTimeout == 0 {
		requestTimeout = 30 * time.Second
	}

	// SECURITY (#62): cap inbound request bodies at maxRequestBytes
	// so a misbehaving client (or an adversarial AI tool acting as one)
	// can't blow up the agent's RSS by streaming megabytes into a
	// secret-request handler. Real requests are well under 64 KB.
	// SECURITY (#110): rate-limit chained outside the body cap so a
	// flood of valid-sized requests also fails fast.
	// SECURITY (#63): TCP listener requires REST auth on top of the
	// body+rate guards. Decided by listen-prefix below.
	requireREST := strings.HasPrefix(cfg.Listen, "tcp://")
	rateLimiter := newAPIRateLimiter()
	var chained http.Handler = bodyLimitMiddleware(mux, maxRequestBytes)
	chained = rateLimitMiddleware(chained, rateLimiter)
	if requireREST {
		chained = restAuthMiddleware(chained, cfg.WSToken)
	}

	s := &Server{
		httpServer:      &http.Server{Handler: chained},
		wsToken:         cfg.WSToken,
		allowedOrigins:  cfg.AllowedOrigins,
		requireRESTAuth: requireREST,
		natsClient:      cfg.NATSClient,
		sessionState: sessionState{
			ConnKey:         cfg.ConnKey,
			KeyID:           cfg.KeyID,
			ConnectionID:    cfg.ConnectionID,
			OwnerGUID:       cfg.OwnerGUID,
			Scope:           cfg.Scope,
			ApprovalMode:    cfg.ApprovalMode,
			SessionID:       cfg.SessionID,
			ExpiresAt:       cfg.SessionExpiresAt,
			DurationSeconds: cfg.SessionDurationSeconds,
		},
		messageSpaceURL: cfg.MessageSpaceURL,
		scopedJWT:       cfg.JWT,
		scopedSeed:      cfg.Seed,
		agentPriv:       cfg.AgentPrivateKey,
		agentPub:        cfg.AgentPublicKey,
		vaultPub:        cfg.VaultPublicKey,
		persist:         cfg.Persist,
		catalog:         NewCatalogCache(),
		tracker:   NewRequestTracker(requestTimeout),
		inbox:     NewMessageInbox(),
		wsClients: make(map[*wsConn]struct{}),
		startTime: time.Now(),
	}

	registerRoutes(mux, s)

	return s, nil
}

// Snapshot returns a consistent view of the rotatable session state.
// Cheap (RLock + struct copy); call once per handler invocation rather
// than re-snapshotting between reads so all the returned fields refer
// to the same vault-side AgentSession.
//
// The returned ConnKey slice header is a copy — but the underlying
// byte array IS the live key. Handlers should not mutate it (encrypt /
// decrypt don't); they may pass it directly to the crypto package
// which only reads.
func (s *Server) Snapshot() sessionState {
	s.sessionMu.RLock()
	defer s.sessionMu.RUnlock()
	return s.sessionState
}

// RotateSession swaps the active session state under the write lock.
//
// Called by the /v1/pair/extend handler after a successful extend
// round-trip with the vault. The old ConnKey's underlying bytes are NOT
// zeroed here — an in-flight handler that captured the old slice
// before the swap still holds a pointer to those bytes, and zeroing
// would corrupt its encrypt. The old slice gets GC'd naturally once
// every in-flight handler returns.
//
// The non-rotating fields (ConnectionID, KeyID, OwnerGUID) are
// preserved from the prior snapshot — the extend flow never changes
// them, but defensively keeping the old values means a caller that
// forgets to populate the next field doesn't accidentally blank it.
func (s *Server) RotateSession(newConnKey []byte, newScope []string, newApprovalMode, newSessionID string, newExpiresAt, newDurationSeconds int64) {
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	s.sessionState.ConnKey = newConnKey
	s.sessionState.Scope = newScope
	s.sessionState.ApprovalMode = newApprovalMode
	s.sessionState.SessionID = newSessionID
	s.sessionState.ExpiresAt = newExpiresAt
	s.sessionState.DurationSeconds = newDurationSeconds
}

func (s *Server) Start(listenAddr string) error {
	var (
		network string
		address string
	)

	if strings.HasPrefix(listenAddr, "unix://") {
		network = "unix"
		address = strings.TrimPrefix(listenAddr, "unix://")
		// Remove existing socket file
		os.Remove(address)
	} else if strings.HasPrefix(listenAddr, "tcp://") {
		network = "tcp"
		address = strings.TrimPrefix(listenAddr, "tcp://")
	} else {
		return fmt.Errorf("unsupported listen address: %s (use unix:// or tcp://)", listenAddr)
	}

	ln, err := net.Listen(network, address)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", listenAddr, err)
	}

	// Set restrictive permissions on Unix socket
	if network == "unix" {
		if err := os.Chmod(address, 0600); err != nil {
			ln.Close()
			return fmt.Errorf("chmod socket: %w", err)
		}
	}

	s.listener = ln
	log.Info().Str("listen", listenAddr).Msg("API server started")

	go func() {
		if err := s.httpServer.Serve(ln); err != http.ErrServerClosed {
			log.Error().Err(err).Msg("API server error")
		}
	}()

	return nil
}

func (s *Server) Stop(ctx context.Context) error {
	s.tracker.Stop()
	return s.httpServer.Shutdown(ctx)
}

// Tracker returns the request tracker for resolving NATS responses.
func (s *Server) Tracker() *RequestTracker {
	return s.tracker
}

// Catalog returns the secret catalog cache.
func (s *Server) Catalog() *CatalogCache {
	return s.catalog
}

// Inbox returns the in-memory buffer of owner→agent chat messages.
// Pushed to by the NATS dispatch loop when MsgAgentMessageResponse
// arrives; drained by GET /v1/messages/inbox.
func (s *Server) Inbox() *MessageInbox {
	return s.inbox
}

// nextSequence returns the next monotonic sequence number for NATS messages.
func (s *Server) nextSequence() uint64 {
	return s.sequence.Add(1)
}

// SECURITY (#63): bearer-token auth for REST endpoints when the API
// listens on TCP. Skips /v1/ws because the WebSocket handler does its
// own token validation (and gorilla/websocket reads the Authorization
// header before the upgrade anyway). Also skips OPTIONS preflights so
// browser clients can negotiate CORS without a credential.
func restAuthMiddleware(next http.Handler, token string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions || r.URL.Path == "/v1/ws" {
			next.ServeHTTP(w, r)
			return
		}
		supplied := extractBearerToken(r)
		if supplied == "" || supplied != token {
			log.Warn().Str("path", r.URL.Path).Str("method", r.Method).Msg("REST auth failed — rejecting")
			w.Header().Set("WWW-Authenticate", `Bearer realm="vettid-agent"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// extractBearerToken pulls a token from Authorization: Bearer or
// X-VettID-Token. Mirrors the WebSocket handler's order so a single
// shipping client only has to set one header.
func extractBearerToken(r *http.Request) string {
	if auth := r.Header.Get("Authorization"); auth != "" {
		const bearer = "Bearer "
		if len(auth) > len(bearer) && auth[:len(bearer)] == bearer {
			return auth[len(bearer):]
		}
	}
	return r.Header.Get("X-VettID-Token")
}

// SECURITY (#62): cap on inbound request bodies for the local REST API.
// 1 MiB is several orders of magnitude over the largest legitimate
// request (secret-request payloads are < 4 KB), but small enough that
// even a hostile client can't drain RSS by streaming.
const maxRequestBytes = 1 << 20

// bodyLimitMiddleware wraps every inbound request body in
// http.MaxBytesReader before the handler reads from r.Body. Reads past
// the limit fail the underlying ReadAt with a *http.MaxBytesError
// which the JSON decoder propagates as the request's own error — the
// handler returns whatever 4xx it had ready (typically 400 Bad
// Request). Skips the WebSocket upgrade path because gorilla/websocket
// hijacks the conn before reading bodies.
func bodyLimitMiddleware(next http.Handler, limit int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, limit)
		}
		next.ServeHTTP(w, r)
	})
}
