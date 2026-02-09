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

	s := &Server{
		httpServer:     &http.Server{Handler: mux},
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
