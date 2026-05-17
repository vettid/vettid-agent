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
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"

	vettidnats "github.com/vettid/vettid-agent/internal/nats"
)

type Server struct {
	httpServer     *http.Server
	listener       net.Listener
	wsToken        string
	allowedOrigins []string
	natsClient     *vettidnats.Client
	connKey        []byte
	keyID          string
	connectionID   string
	ownerGUID      string
	scope          []string
	approvalMode   string
	catalog        *CatalogCache
	tracker        *RequestTracker
	sequence       atomic.Uint64
	startTime      time.Time
}

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
	RequestTimeout time.Duration
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
	bounded := bodyLimitMiddleware(mux, maxRequestBytes)

	s := &Server{
		httpServer:     &http.Server{Handler: bounded},
		wsToken:        cfg.WSToken,
		allowedOrigins: cfg.AllowedOrigins,
		natsClient:     cfg.NATSClient,
		connKey:        cfg.ConnKey,
		keyID:          cfg.KeyID,
		connectionID:   cfg.ConnectionID,
		ownerGUID:      cfg.OwnerGUID,
		scope:          cfg.Scope,
		approvalMode:   cfg.ApprovalMode,
		catalog:        NewCatalogCache(),
		tracker:        NewRequestTracker(requestTimeout),
		startTime:      time.Now(),
	}

	registerRoutes(mux, s)

	return s, nil
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

// nextSequence returns the next monotonic sequence number for NATS messages.
func (s *Server) nextSequence() uint64 {
	return s.sequence.Add(1)
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
