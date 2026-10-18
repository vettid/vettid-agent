// Package pairtest is a test double for pairing: an in-process relay
// (the parts of RELAY-PROTOCOL a pairing device uses: register, claim,
// deposit, collect, ack) with the vault's side of a pairing behind it
// (VAULT-MESSAGING §6.7): it answers hs.init with hs.resp, checks hs.fin,
// and then sends device.paired or device.pair.rejected, sealed under the
// handshake's epoch, or nothing (an expiry). The messages are real
// envelopes built with vettid-vault's wire packages, so the connector's
// client handles them as it handles a vault's.
//
// Test use only: it keeps fresh random keys in memory, checks no relay
// signatures, and serves HTTPS on the loopback interface with
// httptest's certificate, which only HTTPClient trusts.
package pairtest

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vettid/vettid-relay/relayauth"
	"github.com/vettid/vettid-relay/relayclient"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/invite"
	"github.com/vettid/vettid-vault/vms/suite"
)

// RelayError is a relay error answer.
type RelayError struct {
	Status int
	Code   string
}

// Decision is what the simulated owner does once hs.fin checks out.
type Decision int

const (
	// Approve sends device.paired.
	Approve Decision = iota
	// Reject sends device.pair.rejected.
	Reject
	// Hold sends nothing until Approve or Reject is called (or never:
	// an expiry).
	Hold
)

// DeviceID and VaultID are what device.paired carries.
const (
	DeviceID = "01JB2Z6V9K3M4N5P6Q7R8S9DEV"
	VaultID  = "01JB2Z6V9K3M4N5P6Q7R8S9VLT"
)

// Vault is the relay and the vault's pairing side.
type Vault struct {
	srv      *httptest.Server
	alt      *httptest.Server
	ik       ed25519.PrivateKey
	kem      *suite.PrivateKey
	relayKey ed25519.PrivateKey

	mu sync.Mutex
	// RegisterError, if set, makes register answer with this status
	// and error code.
	RegisterError *RelayError
	// Decide is called (without the lock held) when hs.fin checks out,
	// with the vault's SAS. Default: Approve.
	Decide   func(sas string) Decision
	claims   map[string][]byte
	queue    []relayclient.Message // the device's mailbox
	nextID   int
	pending  *handshake.Responder
	devPK    ed25519.PublicKey
	devURL   string
	epoch    *handshake.Epoch
	sas      string
	name     string
	inits    int
	acks     int
	requests []string // method and path of every request
	notify   chan struct{}
}

// New starts a Vault; Close stops it.
func New() (*Vault, error) {
	v := &Vault{claims: map[string][]byte{}, notify: make(chan struct{}, 1)}
	var err error
	if _, v.ik, err = ed25519.GenerateKey(rand.Reader); err != nil {
		return nil, err
	}
	if _, v.relayKey, err = ed25519.GenerateKey(rand.Reader); err != nil {
		return nil, err
	}
	if v.kem, err = suite.GeneratePrivateKey(); err != nil {
		return nil, err
	}
	v.srv = httptest.NewTLSServer(http.HandlerFunc(v.serve))
	v.alt = httptest.NewTLSServer(http.HandlerFunc(v.serve))
	return v, nil
}

// Close stops the servers.
func (v *Vault) Close() { v.srv.Close(); v.alt.Close() }

// HTTPClient trusts the servers' certificate.
func (v *Vault) HTTPClient() *http.Client { return v.srv.Client() }

// AltURL is a second relay URL served by the same relay (a relay that
// forwards everything: what an altered code's `r` could name).
func (v *Vault) AltURL() string { return v.alt.URL }

// URL is the relay's base URL.
func (v *Vault) URL() string { return v.srv.URL }

func (v *Vault) relayPK() ed25519.PublicKey { return v.relayKey.Public().(ed25519.PublicKey) }

func (v *Vault) mailbox() string { return handshake.MailboxID(v.relayPK()) }

func (v *Vault) relayClient() *relayclient.Client { return relayclient.New(v.srv.URL, v.relayKey) }

// Code creates a pairing invitation of kind k that expires after ttl
// and returns its bare payload (the code the phone shows).
func (v *Vault) Code(k invite.Kind, ttl time.Duration) (string, error) {
	return v.CodeWithRelay(k, ttl, v.srv.URL)
}

// CodeWithRelay is Code with relay as the QR's `r`; the bundle keeps the
// vault's own relay (an altered code when relay differs).
func (v *Vault) CodeWithRelay(k invite.Kind, ttl time.Duration, relay string) (string, error) {
	now := time.Now().UTC()
	exp := now.Add(ttl).Truncate(time.Second)
	kind, ok := k.BundleKind()
	if !ok {
		return "", errors.New("unknown kind")
	}
	id, err := envelope.NewULID(now)
	if err != nil {
		return "", err
	}
	open, err := v.relayClient().MintOpenToken(v.srv.URL, 10*time.Minute, "")
	if err != nil {
		return "", err
	}
	b := &invite.Bundle{Kind: kind, InviteID: id, Token: open, Exp: exp,
		Vault: handshake.Principal{IK: v.ik.Public().(ed25519.PublicKey), KEM: v.kem.Public(),
			Relay: handshake.RelayAddr{URL: v.srv.URL, Mailbox: v.mailbox(), PK: v.relayPK()}}}
	bj, err := b.Marshal()
	if err != nil {
		return "", err
	}
	blob, kb, h, err := invite.SealBundle(bj)
	if err != nil {
		return "", err
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	claim := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw))[:invite.ClaimIDLen]
	v.mu.Lock()
	v.claims[claim] = blob
	v.mu.Unlock()
	q := &invite.QR{Kind: k, Relay: relay, ClaimID: claim, Hash: h, Key: kb, Exp: exp.Unix()}
	return q.Link()
}

// SAS returns the vault's SAS of the last handshake ("" before hs.fin).
func (v *Vault) SAS() string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.sas
}

// Name returns the name the device's hs.init profile carried.
func (v *Vault) Name() string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.name
}

// Inits returns how many hs.init the vault answered.
func (v *Vault) Inits() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.inits
}

// Requests returns the method and path of every request so far.
func (v *Vault) Requests() []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return append([]string(nil), v.requests...)
}

// Approve sends device.paired for the completed handshake.
func (v *Vault) Approve() error { return v.decide(Approve) }

// Reject sends device.pair.rejected for the completed handshake.
func (v *Vault) Reject() error { return v.decide(Reject) }

func (v *Vault) decide(d Decision) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.epoch == nil {
		return errors.New("pairtest: no completed handshake")
	}
	now := time.Now()
	var typ string
	var body []byte
	switch d {
	case Approve:
		v.epoch.MarkActivated(now)
		tok, err := v.relayClient().MintToken(relayauth.EncodeKey(v.devPK), v.devURL, relayclient.TokenOptions{})
		if err != nil {
			return err
		}
		typ = "device.paired"
		body, _ = json.Marshal(map[string]string{"device_id": DeviceID, "role": "agent", "vault_id": VaultID, "token": tok})
	case Reject:
		typ, body = "device.pair.rejected", []byte(`{}`)
	default:
		return nil
	}
	id, err := envelope.NewULID(now)
	if err != nil {
		return err
	}
	raw, err := v.epoch.Seal(&envelope.Inner{ID: id, Type: typ, TS: now.UTC().Truncate(time.Millisecond), Body: body})
	if err != nil {
		return err
	}
	v.epoch = nil
	v.enqueueLocked(raw)
	return nil
}

func (v *Vault) enqueueLocked(payload []byte) {
	v.nextID++
	v.queue = append(v.queue, relayclient.Message{MsgID: "m" + strconv.Itoa(v.nextID),
		DepositedAt: time.Now().UTC().Format(time.RFC3339), Sender: relayauth.EncodeKey(v.relayPK()), Payload: payload})
	select {
	case v.notify <- struct{}{}:
	default:
	}
}

func writeJSON(w http.ResponseWriter, status int, x any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(x)
}

func relayError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"code": code, "message": code})
}

func (v *Vault) serve(w http.ResponseWriter, r *http.Request) {
	v.mu.Lock()
	v.requests = append(v.requests, r.Method+" "+r.URL.Path)
	v.mu.Unlock()
	p := r.URL.Path
	switch {
	case r.Method == http.MethodPost && p == "/v1/register":
		v.mu.Lock()
		fail := v.RegisterError
		v.mu.Unlock()
		if fail != nil {
			relayError(w, fail.Status, fail.Code)
			return
		}
		var in struct {
			Pubkey string `json:"pubkey"`
		}
		pk, ok := []byte(nil), false
		if json.NewDecoder(r.Body).Decode(&in) == nil {
			pk, ok = relayauth.DecodeKey(in.Pubkey)
		}
		if !ok {
			relayError(w, http.StatusBadRequest, "bad_request")
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"mailbox_id": relayauth.MailboxID(pk), "limits": map[string]any{}})
	case r.Method == http.MethodGet && strings.HasPrefix(p, "/v1/claim/"):
		id := strings.TrimPrefix(p, "/v1/claim/")
		v.mu.Lock()
		blob, ok := v.claims[id]
		delete(v.claims, id)
		v.mu.Unlock()
		if !ok {
			relayError(w, http.StatusNotFound, "not_found")
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(blob)
	case r.Method == http.MethodPost && strings.HasPrefix(p, "/v1/mailbox/"):
		var in struct {
			Payload []byte `json:"payload"`
		}
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			relayError(w, http.StatusBadRequest, "bad_request")
			return
		}
		if strings.TrimPrefix(p, "/v1/mailbox/") == v.mailbox() {
			v.toVault(in.Payload)
		}
		writeJSON(w, http.StatusOK, map[string]string{"msg_id": "d" + strconv.FormatInt(time.Now().UnixNano(), 10)})
	case r.Method == http.MethodGet && p == "/v1/mailbox":
		v.collect(w, r)
	case r.Method == http.MethodDelete && strings.HasPrefix(p, "/v1/mailbox/"):
		id := strings.TrimPrefix(p, "/v1/mailbox/")
		v.mu.Lock()
		for i, m := range v.queue {
			if m.MsgID == id {
				v.queue = append(v.queue[:i:i], v.queue[i+1:]...)
				v.acks++
				break
			}
		}
		v.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	default:
		relayError(w, http.StatusNotFound, "not_found")
	}
}

// collect returns the device's unacknowledged messages, waiting up to
// 100 ms for one.
func (v *Vault) collect(w http.ResponseWriter, r *http.Request) {
	deadline := time.After(100 * time.Millisecond)
	for {
		v.mu.Lock()
		msgs := append([]relayclient.Message(nil), v.queue...)
		v.mu.Unlock()
		if len(msgs) > 0 {
			writeJSON(w, http.StatusOK, map[string]any{"messages": msgs})
			return
		}
		select {
		case <-v.notify:
		case <-deadline:
			writeJSON(w, http.StatusOK, map[string]any{"messages": []relayclient.Message{}})
			return
		case <-r.Context().Done():
			return
		}
	}
}

// toVault handles a deposit to the vault's mailbox: hs.init or hs.fin.
func (v *Vault) toVault(payload []byte) {
	env, err := envelope.Parse(payload)
	if err != nil {
		return
	}
	now := time.Now()
	var decide func(string) Decision
	var sas string
	v.mu.Lock()
	switch env.Mode() {
	case envelope.ModeSealed:
		pi, err := handshake.OpenInit(payload, func(k suite.Kid) *suite.PrivateKey {
			if k.Equal(v.kem.Public().Kid()) {
				return v.kem
			}
			return nil
		}, now)
		if err != nil || pi.Init().Purpose != handshake.PurposeAgent {
			break
		}
		in := pi.Init()
		var prof struct {
			Name string `json:"name"`
		}
		_ = json.Unmarshal(in.Profile, &prof)
		tok, err := v.relayClient().MintToken(relayauth.EncodeKey(in.From.Relay.PK), in.From.Relay.URL, relayclient.TokenOptions{TTL: 10 * time.Minute})
		if err != nil {
			break
		}
		resp, out, err := pi.Respond(handshake.ResponderConfig{Identity: v.ik, Token: tok, Policy: handshake.PolicyVaultToDevice,
			CollectSender: in.From.Relay.PK, Now: now})
		if err != nil {
			break
		}
		v.pending, v.devPK, v.devURL, v.name, v.epoch, v.sas = resp, in.From.Relay.PK, in.From.Relay.URL, prof.Name, nil, ""
		v.inits++
		v.enqueueLocked(out)
	case envelope.ModeSession:
		if v.pending == nil {
			break
		}
		fr, err := v.pending.HandleFin(payload, v.devPK, now)
		if err != nil {
			break
		}
		v.pending, v.epoch, v.sas = nil, fr.Epoch, fr.SAS
		decide, sas = v.Decide, fr.SAS
		if decide == nil {
			decide = func(string) Decision { return Approve }
		}
	}
	v.mu.Unlock()
	if decide != nil {
		_ = v.decide(decide(sas))
	}
}
