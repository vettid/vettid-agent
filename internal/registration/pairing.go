// Two-stage agent pairing flow — stage 1.
//
// Protocol reference: vettid-agent/docs/AGENT-PAIRING-FLOW.md.
//
// Stage 1 — invite resolution via guest NATS account:
//   1. User types a 12-char invite code displayed by the phone app.
//   2. We POST {code, kind:"agent"} to the public bootstrap Lambda; it mints
//      a 60s-TTL JWT scoped to JetStream consumer ops on the INVITATIONS
//      stream. Same Lambda the desktop uses.
//   3. We connect to NATS using those guest creds (TLS-immediate against
//      tls://nats.vettid.dev:443).
//   4. We fetch the single invite.<code> message from the INVITATIONS stream
//      with an ephemeral pull consumer (DeliverLastPerSubject, max 1, 5s).
//   5. The payload gives us scoped NATS creds bound to a new connection_id —
//      the keys for stage 2.
//
// Stage 2 (CompletePairing) is wired up in a separate file once Phase 3
// lands. For now, ResolveInvite + the generated runtime state are sufficient
// to round-trip stage 1 in isolation.
package registration

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/rs/zerolog/log"

	"github.com/vettid/vettid-agent/internal/crypto"
)

// DefaultBootstrapURL is the public endpoint that mints short-lived guest
// NATS credentials. Override at runtime via the VETTID_BOOTSTRAP_URL env var
// for testing against a local CDK deploy.
const DefaultBootstrapURL = "https://api.vettid.dev/pair/device/bootstrap"

// PairingKindAgent is the value the agent sends in the bootstrap body's
// `kind` field so the Lambda can tag its logs / JWT name accordingly.
// The Lambda accepts {"device","agent"} and defaults to "device" for
// backwards-compatibility with shipped desktop binaries.
const PairingKindAgent = "agent"

// inviteCodeAlphabet mirrors the vault's vault-manager/nats_credentials.go
// shortCodeAlphabet — ambiguity-safe 32-char set, no 0/O/1/I/L/lowercase.
const inviteCodeAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// inviteCodePattern is the regex form of inviteCodeAlphabet, 12 chars.
var inviteCodePattern = regexp.MustCompile(`^[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{12}$`)

// fetchInviteTimeout is the wall-clock deadline for the JetStream pull
// consumer's single fetch. Matches the desktop's 5s.
const fetchInviteTimeout = 5 * time.Second

// bootstrapHTTPTimeout is the wall-clock deadline for the HTTP POST.
const bootstrapHTTPTimeout = 10 * time.Second

// BootstrapResponse is the exact wire shape of POST /pair/.../bootstrap.
// See vettid-dev/cdk/lambda/handlers/vault/bootstrapDevicePairing.ts.
type BootstrapResponse struct {
	NATSEndpoint string `json:"nats_endpoint"` // tls://nats.vettid.dev:443
	JWT          string `json:"jwt"`
	Seed         string `json:"seed"`
	ExpiresIn    int    `json:"expires_in"` // seconds, typically 60
}

// InvitePayload is the wire shape of the message the vault publishes to
// invite.<code> on the INVITATIONS JetStream. Must match
// vault-manager/connections.go HandleCreateAgentInvite.
type InvitePayload struct {
	Type         string `json:"type"` // "vettid_agent" (we reject anything else)
	ConnectionID string `json:"connection_id"`
	JWT          string `json:"jwt"`          // scoped NATS creds for stage 2
	Seed         string `json:"seed"`         // scoped NATS seed for stage 2
	OwnerSpace   string `json:"owner_space"`
	MessageSpace string `json:"message_space"`
	ExpiresAt    string `json:"expires_at"`
	Label        string `json:"label,omitempty"`
}

// InviteSession is the result of a successful stage-1 resolution. The
// scoped JWT/seed inside are what stage 2 reconnects with.
type InviteSession struct {
	ConnectionID  string
	OwnerSpace    string
	NATSURL       string // tls://nats.vettid.dev:443
	ScopedJWT     string
	ScopedSeed    string
	ApprovalToken string // hex, 32 bytes
}

// PairingRuntime carries the ephemeral key material we generated for
// stage 2 (the X25519 keypair + the hex approval token). The private key
// MUST be zeroed by the caller once stage 2 completes or fails.
type PairingRuntime struct {
	AgentKeyPair  *crypto.X25519KeyPair
	ApprovalToken []byte // 32 raw bytes (also hex-encoded as InviteSession.ApprovalToken)
	ConnectionID  string
}

// Zero wipes the private key material. Safe to call multiple times.
func (r *PairingRuntime) Zero() {
	if r == nil {
		return
	}
	if r.AgentKeyPair != nil {
		r.AgentKeyPair.Zero()
	}
	crypto.ZeroBytes(r.ApprovalToken)
}

// ValidateInviteCode checks that `code` matches the 12-char ambiguity-safe
// alphabet. Returns the canonical (uppercased) form so callers don't have to
// normalize at every call site.
func ValidateInviteCode(code string) (string, error) {
	up := strings.ToUpper(strings.TrimSpace(code))
	if !inviteCodePattern.MatchString(up) {
		return "", fmt.Errorf("invalid invite code (must be 12 characters from %s)", inviteCodeAlphabet)
	}
	return up, nil
}

// bootstrapURL returns the configured bootstrap endpoint, honoring
// VETTID_BOOTSTRAP_URL for local testing.
func bootstrapURL() string {
	if v := os.Getenv("VETTID_BOOTSTRAP_URL"); v != "" {
		return v
	}
	return DefaultBootstrapURL
}

// FetchBootstrapCreds calls the public bootstrap Lambda and returns the
// per-pair NATS user keypair the agent will use to read its invite.
//
// `kind` should be PairingKindAgent. The Lambda defaults to "device" for
// backwards-compat with the desktop, so an agent that forgets to set it
// won't fail authentication (same scope is minted either way today) — but
// CloudWatch traces will silently misattribute the request. Always pass it.
func FetchBootstrapCreds(ctx context.Context, code, kind string) (*BootstrapResponse, error) {
	body, err := json.Marshal(map[string]string{
		"code": code,
		"kind": kind,
	})
	if err != nil {
		return nil, fmt.Errorf("encode bootstrap request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, bootstrapURL(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build bootstrap request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: bootstrapHTTPTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("bootstrap request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("read bootstrap response: %w", err)
	}

	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("bootstrap endpoint returned %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var out BootstrapResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("parse bootstrap response: %w", err)
	}
	if out.NATSEndpoint == "" || out.JWT == "" || out.Seed == "" {
		return nil, fmt.Errorf("bootstrap response missing required field (endpoint/jwt/seed)")
	}
	return &out, nil
}

// natsCredsFile formats a JWT + seed as the NATS .creds file shape that
// nats.UserJWTAndSeed / nats.UserCredentials expect.
func natsCredsFile(jwt, seed string) string {
	// Trailing newlines are load-bearing: the credentials parser inside
	// nats.go uses a regex anchored on `\r?\n` after each block's
	// terminator. Mirroring the layout the vault's
	// formatNATSCredentials emits (vault-manager/nats_credentials.go).
	return fmt.Sprintf(
		"-----BEGIN NATS USER JWT-----\n%s\n------END NATS USER JWT------\n\n-----BEGIN USER NKEY SEED-----\n%s\n------END USER NKEY SEED------\n",
		jwt, seed,
	)
}

// connectGuest opens a NATS connection authenticated with the per-pair
// guest creds and torn down after a single JetStream fetch.
//
// The bootstrap Lambda returns endpoints prefixed `tls://`, which nats.go
// interprets as TLS-immediate (the NLB on :443 hangs on the default
// nats://-then-STARTTLS flow). The explicit `nats.Secure()` is belt-and-
// braces — even if the URL is somehow passed without the tls:// prefix,
// the option enforces TLS.
func connectGuest(natsURL, jwt, seed string) (*nats.Conn, error) {
	// Inline credentials via UserJWTAndSeed: nats.go accepts the JWT/seed
	// pair without touching the filesystem. The credential strings here
	// live in the BootstrapResponse object that bound this stack frame
	// and get freed with normal GC once the connection is up — fine for
	// a 60s-TTL token. natsCredsFile() is only invoked by tests that
	// want the .creds-file shape rather than the inline form.
	opts := []nats.Option{
		nats.UserJWTAndSeed(jwt, seed),
		nats.Name("vettid-agent-bootstrap"),
		nats.Timeout(10 * time.Second),
		nats.MaxReconnects(0), // single-shot: don't retry, just fail fast
		nats.Secure(),
		// The VettID NATS endpoint sits behind an NLB that terminates
		// TLS at byte 0 — it never speaks plain NATS, so the library's
		// default STARTTLS dance (read INFO in cleartext, then upgrade)
		// deadlocks against the NLB. TLSHandshakeFirst tells nats.go
		// to do TLS immediately, before reading INFO. Required for
		// any Go client targeting nats.vettid.dev:443.
		nats.TLSHandshakeFirst(),
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
			log.Debug().Err(err).Msg("nats async error during bootstrap")
		}),
	}
	conn, err := nats.Connect(natsURL, opts...)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", natsURL, err)
	}
	return conn, nil
}

// fetchInviteFromStream creates an ephemeral pull consumer on the
// INVITATIONS stream filtered to invite.<code>, fetches the single most
// recent message, parses it as an InvitePayload, and returns it.
//
// DeliverLastPerSubject is what lets us start the consumer AFTER the vault
// published the invite — without it, a pull consumer with DeliverAll would
// race the publish and might miss it.
func fetchInviteFromStream(ctx context.Context, conn *nats.Conn, code string) (*InvitePayload, error) {
	js, err := jetstream.New(conn)
	if err != nil {
		return nil, fmt.Errorf("create jetstream client: %w", err)
	}

	stream, err := js.Stream(ctx, "INVITATIONS")
	if err != nil {
		return nil, fmt.Errorf("look up INVITATIONS stream: %w", err)
	}

	subject := "invite." + code

	// Ephemeral consumer — passing an empty Name + Durable string lets
	// JetStream pick a server-side name. The consumer is deleted as
	// soon as we drop the connection at the end of ResolveInvite.
	cons, err := stream.CreateConsumer(ctx, jetstream.ConsumerConfig{
		FilterSubject: subject,
		DeliverPolicy: jetstream.DeliverLastPerSubjectPolicy,
		AckPolicy:     jetstream.AckExplicitPolicy,
	})
	if err != nil {
		return nil, fmt.Errorf("create invite consumer: %w", err)
	}

	fetchCtx, cancel := context.WithTimeout(ctx, fetchInviteTimeout)
	defer cancel()

	batch, err := cons.Fetch(1, jetstream.FetchMaxWait(fetchInviteTimeout))
	if err != nil {
		return nil, fmt.Errorf("fetch invite: %w", err)
	}

	var inviteMsg jetstream.Msg
	select {
	case msg, ok := <-batch.Messages():
		if !ok {
			if fetchErr := batch.Error(); fetchErr != nil {
				return nil, fmt.Errorf("invite batch error: %w", fetchErr)
			}
			return nil, errors.New("invite not found — code expired or invalid")
		}
		inviteMsg = msg
	case <-fetchCtx.Done():
		return nil, errors.New("timed out waiting for invite — code expired or invalid")
	}

	var payload InvitePayload
	if err := json.Unmarshal(inviteMsg.Data(), &payload); err != nil {
		return nil, fmt.Errorf("parse invite payload: %w", err)
	}
	// Ack so the JetStream consumer drops the message promptly; we
	// won't read it again.
	if err := inviteMsg.Ack(); err != nil {
		log.Debug().Err(err).Msg("invite ack failed (non-fatal)")
	}

	if payload.Type != "vettid_agent" {
		return nil, fmt.Errorf("invite payload type %q is not vettid_agent — wrong invite kind?", payload.Type)
	}
	if payload.ConnectionID == "" || payload.JWT == "" || payload.Seed == "" || payload.OwnerSpace == "" {
		return nil, errors.New("invite payload missing required field (connection_id/jwt/seed/owner_space)")
	}

	return &payload, nil
}

// ResolveInvite runs stage 1 end-to-end: bootstrap → connect → fetch
// invite → tear down. Generates the ephemeral X25519 keypair and the
// 32-byte approval token the agent will reuse in stage 2.
//
// The caller owns the returned PairingRuntime — it MUST call Zero() on
// the runtime once stage 2 completes (or fails) to wipe the ephemeral
// private key.
func ResolveInvite(ctx context.Context, code string) (*InviteSession, *PairingRuntime, error) {
	normCode, err := ValidateInviteCode(code)
	if err != nil {
		return nil, nil, err
	}

	guest, err := FetchBootstrapCreds(ctx, normCode, PairingKindAgent)
	if err != nil {
		return nil, nil, fmt.Errorf("bootstrap: %w", err)
	}
	log.Info().Str("endpoint", guest.NATSEndpoint).Msg("Bootstrap creds minted; connecting to fetch invite")

	conn, err := connectGuest(guest.NATSEndpoint, guest.JWT, guest.Seed)
	if err != nil {
		return nil, nil, fmt.Errorf("guest connect: %w", err)
	}
	defer conn.Close()

	payload, err := fetchInviteFromStream(ctx, conn, normCode)
	if err != nil {
		return nil, nil, fmt.Errorf("invite fetch: %w", err)
	}

	log.Info().
		Str("connection_id", payload.ConnectionID).
		Str("owner_space", payload.OwnerSpace).
		Msg("Invite resolved")

	// Stage-2 ephemeral state — generated now so the caller can publish
	// agent.request-session as soon as it reconnects with the scoped creds.
	kp, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		return nil, nil, fmt.Errorf("generate stage-2 keypair: %w", err)
	}
	approvalRaw, err := crypto.GenerateRandomBytes(32)
	if err != nil {
		kp.Zero()
		return nil, nil, fmt.Errorf("generate approval token: %w", err)
	}

	session := &InviteSession{
		ConnectionID:  payload.ConnectionID,
		OwnerSpace:    payload.OwnerSpace,
		NATSURL:       guest.NATSEndpoint,
		ScopedJWT:     payload.JWT,
		ScopedSeed:    payload.Seed,
		ApprovalToken: hex.EncodeToString(approvalRaw),
	}
	runtime := &PairingRuntime{
		AgentKeyPair:  kp,
		ApprovalToken: approvalRaw,
		ConnectionID:  payload.ConnectionID,
	}
	return session, runtime, nil
}
