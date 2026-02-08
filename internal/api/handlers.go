package api

import (
	"encoding/json"
	"net/http"
)

func registerRoutes(mux *http.ServeMux, s *Server) {
	mux.HandleFunc("POST /v1/secrets/request", s.handleSecretRequest)
	mux.HandleFunc("GET /v1/status", s.handleStatus)
	mux.HandleFunc("GET /v1/requests/{requestID}", s.handleGetRequest)
	mux.HandleFunc("POST /v1/connection/disconnect", s.handleDisconnect)
}

func (s *Server) handleSecretRequest(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusNotImplemented, map[string]string{
		"error": "not yet implemented",
	})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusNotImplemented, map[string]string{
		"error": "not yet implemented",
	})
}

func (s *Server) handleGetRequest(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusNotImplemented, map[string]string{
		"error": "not yet implemented",
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
	json.NewEncoder(w).Encode(v)
}
