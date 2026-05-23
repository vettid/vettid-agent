package registration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestValidateInviteCode(t *testing.T) {
	cases := []struct {
		name      string
		input     string
		want      string
		wantError bool
	}{
		{"happy 12 chars uppercase", "ABCD2EFG3HJK", "ABCD2EFG3HJK", false},
		{"normalize to uppercase", "abcd2efg3hjk", "ABCD2EFG3HJK", false},
		{"trim whitespace", "  ABCD2EFG3HJK  ", "ABCD2EFG3HJK", false},
		{"with dashes — invalid (dashes are display only)", "ABCD-2EFG-3HJK", "", true},
		{"too short", "ABC", "", true},
		{"too long", "ABCD2EFG3HJK4", "", true},
		{"contains O (excluded)", "ABCDOEFG3HJK", "", true},
		{"contains 0 (excluded)", "ABCD0EFG3HJK", "", true},
		{"contains 1 (excluded)", "ABCD1EFG3HJK", "", true},
		{"contains I (excluded)", "ABCDIEFG3HJK", "", true},
		{"empty", "", "", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ValidateInviteCode(tc.input)
			if tc.wantError {
				if err == nil {
					t.Fatalf("expected error for %q, got %q", tc.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.input, err)
			}
			if got != tc.want {
				t.Fatalf("ValidateInviteCode(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestBootstrapURL_DefaultAndOverride(t *testing.T) {
	t.Setenv("VETTID_BOOTSTRAP_URL", "")
	if got := bootstrapURL(); got != DefaultBootstrapURL {
		t.Errorf("bootstrapURL() default = %q, want %q", got, DefaultBootstrapURL)
	}

	t.Setenv("VETTID_BOOTSTRAP_URL", "http://localhost:9999/pair/agent/bootstrap")
	if got := bootstrapURL(); got != "http://localhost:9999/pair/agent/bootstrap" {
		t.Errorf("bootstrapURL() override = %q", got)
	}

	// Unset for any later tests in this package.
	os.Unsetenv("VETTID_BOOTSTRAP_URL")
}

func TestFetchBootstrapCreds_SendsKindAndCode(t *testing.T) {
	var capturedBody map[string]string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", got)
		}
		if err := json.NewDecoder(r.Body).Decode(&capturedBody); err != nil {
			http.Error(w, "decode", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(BootstrapResponse{
			NATSEndpoint: "tls://nats.example.test:443",
			JWT:          "fake-jwt",
			Seed:         "SUFAKESEED",
			ExpiresIn:    60,
		})
	}))
	defer srv.Close()

	t.Setenv("VETTID_BOOTSTRAP_URL", srv.URL)

	out, err := FetchBootstrapCreds(context.Background(), "ABCD2EFG3HJK", PairingKindAgent)
	if err != nil {
		t.Fatalf("FetchBootstrapCreds err: %v", err)
	}

	if capturedBody["code"] != "ABCD2EFG3HJK" {
		t.Errorf("body.code = %q, want ABCD2EFG3HJK", capturedBody["code"])
	}
	if capturedBody["kind"] != "agent" {
		t.Errorf("body.kind = %q, want agent", capturedBody["kind"])
	}
	if out.NATSEndpoint != "tls://nats.example.test:443" || out.JWT != "fake-jwt" || out.Seed != "SUFAKESEED" {
		t.Errorf("response fields not parsed: %+v", out)
	}
}

func TestFetchBootstrapCreds_NonSuccessSurfacesBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("invalid invite code"))
	}))
	defer srv.Close()
	t.Setenv("VETTID_BOOTSTRAP_URL", srv.URL)

	_, err := FetchBootstrapCreds(context.Background(), "ABCD2EFG3HJK", PairingKindAgent)
	if err == nil {
		t.Fatal("expected error on 400 status")
	}
	if !strings.Contains(err.Error(), "400") || !strings.Contains(err.Error(), "invalid invite code") {
		t.Errorf("error should include status + body, got: %v", err)
	}
}

func TestFetchBootstrapCreds_RejectsEmptyFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// JWT missing — Lambda would never emit this, but we defend against it.
		_, _ = w.Write([]byte(`{"nats_endpoint":"tls://x:443","seed":"S","expires_in":60}`))
	}))
	defer srv.Close()
	t.Setenv("VETTID_BOOTSTRAP_URL", srv.URL)

	_, err := FetchBootstrapCreds(context.Background(), "ABCD2EFG3HJK", PairingKindAgent)
	if err == nil {
		t.Fatal("expected error when JWT field is empty")
	}
	if !strings.Contains(err.Error(), "missing required field") {
		t.Errorf("error should flag missing field, got: %v", err)
	}
}

func TestInvitePayload_ParseAndValidate(t *testing.T) {
	// Mirrors the JSON the vault publishes from
	// connections.go HandleCreateAgentInvite.
	raw := []byte(`{
	  "type": "vettid_agent",
	  "connection_id": "conn-deadbeefdeadbeefdeadbeefdeadbeef",
	  "jwt": "scoped-jwt",
	  "seed": "SUSCOPEDSEED",
	  "owner_space": "abc-owner-guid",
	  "message_space": "MessageSpace.abc-owner-guid.forApp.agent.conn-x.>",
	  "expires_at": "2026-05-23T18:00:00Z",
	  "label": "claude-code"
	}`)

	var p InvitePayload
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.Type != "vettid_agent" {
		t.Errorf("type = %q", p.Type)
	}
	if p.ConnectionID == "" || p.JWT == "" || p.Seed == "" || p.OwnerSpace == "" {
		t.Errorf("required fields not populated: %+v", p)
	}
	if p.Label != "claude-code" {
		t.Errorf("label = %q", p.Label)
	}
}

func TestPairingRuntime_ZeroIsIdempotent(t *testing.T) {
	r := &PairingRuntime{
		ApprovalToken: []byte("0123456789abcdef0123456789abcdef"),
	}
	r.Zero()
	r.Zero() // second call must not panic
	for _, b := range r.ApprovalToken {
		if b != 0 {
			t.Fatalf("approval token byte not zeroed: %x", r.ApprovalToken)
		}
	}

	// Nil receiver is also safe.
	var nilRuntime *PairingRuntime
	nilRuntime.Zero()
}
