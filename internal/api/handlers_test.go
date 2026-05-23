package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-agent/internal/nats"
)

// newTestServer creates a Server with minimal config for handler testing.
// No NATS client is connected (nil).
func newTestServer() *Server {
	return &Server{
		catalog: NewCatalogCache(),
		tracker: NewRequestTracker(5 * time.Second),
		sessionState: sessionState{
			ConnectionID: "test-conn-id",
			Scope:        []string{"api_keys", "ssh_keys"},
			ApprovalMode: "auto_within_contract",
		},
		startTime: time.Now(),
	}
}

func TestHandleStatus(t *testing.T) {
	s := newTestServer()
	defer s.tracker.Stop()

	req := httptest.NewRequest("GET", "/v1/status", nil)
	w := httptest.NewRecorder()

	s.handleStatus(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var body map[string]any
	json.NewDecoder(w.Body).Decode(&body)

	if body["connection_id"] != "test-conn-id" {
		t.Errorf("expected connection_id 'test-conn-id', got %v", body["connection_id"])
	}
	if body["connected"] != false {
		t.Errorf("expected connected=false (no NATS client), got %v", body["connected"])
	}
	if body["approval_mode"] != "auto_within_contract" {
		t.Errorf("expected approval_mode 'auto_within_contract', got %v", body["approval_mode"])
	}
}

func TestHandleListSecrets_Empty(t *testing.T) {
	s := newTestServer()
	defer s.tracker.Stop()

	req := httptest.NewRequest("GET", "/v1/secrets", nil)
	w := httptest.NewRecorder()

	s.handleListSecrets(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var body map[string]any
	json.NewDecoder(w.Body).Decode(&body)

	secrets, ok := body["secrets"].([]any)
	if !ok {
		t.Fatal("expected secrets to be an array")
	}
	if len(secrets) != 0 {
		t.Errorf("expected empty array, got %d entries", len(secrets))
	}
}

func TestHandleListSecrets_WithEntries(t *testing.T) {
	s := newTestServer()
	defer s.tracker.Stop()

	s.catalog.Update(&nats.SecretCatalog{
		Version: 1,
		Entries: []nats.SecretCatalogEntry{
			{SecretID: "s1", Name: "key1", Category: "api_keys", AllowedActions: []string{"retrieve"}},
			{SecretID: "s2", Name: "ssh1", Category: "ssh_keys", AllowedActions: []string{"use"}},
		},
	})

	// List all
	req := httptest.NewRequest("GET", "/v1/secrets", nil)
	w := httptest.NewRecorder()
	s.handleListSecrets(w, req)

	var body map[string]any
	json.NewDecoder(w.Body).Decode(&body)
	secrets := body["secrets"].([]any)
	if len(secrets) != 2 {
		t.Errorf("expected 2 secrets, got %d", len(secrets))
	}

	// Filter by category
	req = httptest.NewRequest("GET", "/v1/secrets?category=ssh_keys", nil)
	w = httptest.NewRecorder()
	s.handleListSecrets(w, req)

	json.NewDecoder(w.Body).Decode(&body)
	secrets = body["secrets"].([]any)
	if len(secrets) != 1 {
		t.Errorf("expected 1 ssh_keys secret, got %d", len(secrets))
	}
}

func TestHandleSecretRequest_NoNATS(t *testing.T) {
	s := newTestServer()
	defer s.tracker.Stop()

	body := `{"secret_type":"api_key","secret_name":"test","purpose":"testing","ttl":60}`
	req := httptest.NewRequest("POST", "/v1/secrets/request", strings.NewReader(body))
	w := httptest.NewRecorder()

	s.handleSecretRequest(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 (no NATS), got %d", w.Code)
	}
}

func TestHandleSecretRequest_MissingFields(t *testing.T) {
	s := newTestServer()
	defer s.tracker.Stop()

	// Missing purpose
	body := `{"secret_type":"api_key","secret_name":"test","ttl":60}`
	req := httptest.NewRequest("POST", "/v1/secrets/request", strings.NewReader(body))
	w := httptest.NewRecorder()
	s.handleSecretRequest(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing purpose, got %d", w.Code)
	}

	// Missing identifiers
	body = `{"purpose":"testing","ttl":60}`
	req = httptest.NewRequest("POST", "/v1/secrets/request", strings.NewReader(body))
	w = httptest.NewRecorder()
	s.handleSecretRequest(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing identifiers, got %d", w.Code)
	}
}

func TestHandleSecretRequest_UseOnlySecret(t *testing.T) {
	s := newTestServer()
	defer s.tracker.Stop()

	s.catalog.Update(&nats.SecretCatalog{
		Version: 1,
		Entries: []nats.SecretCatalogEntry{
			{SecretID: "s1", Name: "prod_key", Category: "api_keys", AllowedActions: []string{"use"}},
		},
	})

	body := `{"secret_id":"s1","purpose":"testing","ttl":60}`
	req := httptest.NewRequest("POST", "/v1/secrets/request", strings.NewReader(body))
	w := httptest.NewRecorder()
	s.handleSecretRequest(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for use-only secret, got %d", w.Code)
	}
}

func TestHandleSecretUse_MissingFields(t *testing.T) {
	s := newTestServer()
	defer s.tracker.Stop()

	// Missing secret_id
	body := `{"action":"http_request","purpose":"test","params":{}}`
	req := httptest.NewRequest("POST", "/v1/secrets/use", strings.NewReader(body))
	w := httptest.NewRecorder()
	s.handleSecretUse(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}

	// Invalid action
	body = `{"secret_id":"s1","action":"invalid","purpose":"test","params":{}}`
	req = httptest.NewRequest("POST", "/v1/secrets/use", strings.NewReader(body))
	w = httptest.NewRecorder()
	s.handleSecretUse(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid action, got %d", w.Code)
	}
}

func TestHandleSecretUse_RetrieveOnlySecret(t *testing.T) {
	s := newTestServer()
	defer s.tracker.Stop()

	s.catalog.Update(&nats.SecretCatalog{
		Version: 1,
		Entries: []nats.SecretCatalogEntry{
			{SecretID: "s1", Name: "dev_key", Category: "api_keys", AllowedActions: []string{"retrieve"}},
		},
	})

	body := `{"secret_id":"s1","action":"http_request","purpose":"test","params":{"method":"GET","url":"https://api.example.com","secret_placement":"bearer"}}`
	req := httptest.NewRequest("POST", "/v1/secrets/use", strings.NewReader(body))
	w := httptest.NewRecorder()
	s.handleSecretUse(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for retrieve-only secret, got %d", w.Code)
	}
}

func TestHandleCatalogRefresh_NoNATS(t *testing.T) {
	s := newTestServer()
	defer s.tracker.Stop()

	req := httptest.NewRequest("POST", "/v1/secrets/refresh", nil)
	w := httptest.NewRecorder()
	s.handleCatalogRefresh(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 (no NATS), got %d", w.Code)
	}
}

func TestHandleGetRequest_NotFound(t *testing.T) {
	s := newTestServer()
	defer s.tracker.Stop()

	req := httptest.NewRequest("GET", "/v1/requests/nonexistent", nil)
	req.SetPathValue("requestID", "nonexistent")
	w := httptest.NewRecorder()
	s.handleGetRequest(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestHandleGetRequest_Found(t *testing.T) {
	s := newTestServer()
	defer s.tracker.Stop()

	s.tracker.Add("test-req-1", 0)
	s.tracker.Resolve("test-req-1", &TrackedResult{
		Status:    StatusApproved,
		RequestID: "test-req-1",
	})

	req := httptest.NewRequest("GET", "/v1/requests/test-req-1", nil)
	req.SetPathValue("requestID", "test-req-1")
	w := httptest.NewRecorder()
	s.handleGetRequest(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var body TrackedResult
	json.NewDecoder(w.Body).Decode(&body)
	if body.Status != StatusApproved {
		t.Errorf("expected StatusApproved, got %s", body.Status)
	}
}

func TestActionAllowed(t *testing.T) {
	tests := []struct {
		allowed []string
		action  string
		want    bool
	}{
		{[]string{"retrieve", "use"}, "retrieve", true},
		{[]string{"retrieve", "use"}, "use", true},
		{[]string{"retrieve"}, "use", false},
		{[]string{"use"}, "retrieve", false},
		{[]string{}, "retrieve", false},
		{nil, "retrieve", false},
	}

	for _, tt := range tests {
		got := actionAllowed(tt.allowed, tt.action)
		if got != tt.want {
			t.Errorf("actionAllowed(%v, %q) = %v, want %v", tt.allowed, tt.action, got, tt.want)
		}
	}
}

func TestGenerateRequestID(t *testing.T) {
	id1, err := generateRequestID()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(id1) != 32 { // 16 bytes = 32 hex chars
		t.Errorf("expected 32 char hex ID, got %d chars: %q", len(id1), id1)
	}

	id2, err := generateRequestID()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id1 == id2 {
		t.Error("expected unique IDs, got duplicates")
	}
}
