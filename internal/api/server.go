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

	"github.com/rs/zerolog/log"
)

type Server struct {
	httpServer *http.Server
	listener   net.Listener
	wsToken    string
}

type ServerConfig struct {
	Listen  string // "unix:///path/to/socket" or "tcp://127.0.0.1:7443"
	WSToken string
}

func NewServer(cfg *ServerConfig) (*Server, error) {
	mux := http.NewServeMux()

	s := &Server{
		httpServer: &http.Server{Handler: mux},
		wsToken:    cfg.WSToken,
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
	return s.httpServer.Shutdown(ctx)
}
