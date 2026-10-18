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

	// The paired session (after Approve).
	session   *handshake.Keyring
	devIK     ed25519.PublicKey
	rekey     *handshake.Initiator
	rekeyRsp  int       // hs.resp received for the vault's rekeys
	doneRekey suite.Kid // the ephemeral kid of the last finished rekey
	received  []string  // inner types received from the device in session
	// FailAcks makes every ack fail (the message stays in the mailbox),
	// as if the device stopped between saving and acknowledging.
	FailAcks bool
	// SessionSeconds, if positive, makes the approval grant a first
	// access session of that length (device.paired session_expires_at).
	SessionSeconds int
	// GrantListError, if set, answers leash.grant.list with this error
	// code (for example session_required) instead of an empty list.
	GrantListError string
	// DepositError, if set, answers the device's deposits to the vault's
	// mailbox after pairing with this error (for example 403
	// token_revoked).
	DepositError *RelayError
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
		m := map[string]string{"device_id": DeviceID, "role": "agent", "vault_id": VaultID, "token": tok}
		if v.SessionSeconds > 0 {
			m["session_expires_at"] = envelope.FormatTS(now.Add(time.Duration(v.SessionSeconds) * time.Second))
		}
		body, _ = json.Marshal(m)
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
	if d == Approve {
		v.session = &handshake.Keyring{}
		v.session.Activate(v.epoch, now)
	}
	v.epoch = nil
	v.enqueueLocked(raw)
	return nil
}

func ulidNow() (string, time.Time, error) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	id, err := envelope.NewULID(now)
	return id, now, err
}

// SendEvent sends the paired device an event in the current session
// epoch and returns its inner id.
func (v *Vault) SendEvent(typ string, body []byte) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.sealLocked(&envelope.Inner{Type: typ, Body: body})
}

func (v *Vault) sealLocked(in *envelope.Inner) (string, error) {
	if v.session == nil || v.session.Current() == nil {
		return "", errors.New("pairtest: not paired")
	}
	id, now, err := ulidNow()
	if err != nil {
		return "", err
	}
	in.ID, in.TS = id, now
	raw, err := v.session.Current().Seal(in)
	if err != nil {
		return "", err
	}
	v.enqueueLocked(raw)
	return id, nil
}

// Rekey starts a vault-initiated rekey of the session (VAULT-MESSAGING
// §6.5): hs.init in the current epoch; the device's hs.resp is answered
// with hs.fin and the new epoch becomes current.
func (v *Vault) Rekey() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.session == nil || v.session.Current() == nil {
		return errors.New("pairtest: not paired")
	}
	ini, err := handshake.NewInitiator(handshake.InitiatorConfig{
		Purpose: handshake.PurposeRekey, Identity: v.ik, StaticKEM: v.kem.Public(),
		Relay:       handshake.RelayAddr{URL: v.srv.URL, Mailbox: v.mailbox(), PK: v.relayPK()},
		ResponderIK: v.devIK, ResponderRelayKey: v.devPK, Current: v.session.Current(),
		PinnedSuite: 2, Policy: handshake.PolicyVaultToDevice, Now: time.Now(),
	})
	if err != nil {
		return err
	}
	v.rekey = ini
	v.enqueueLocked(ini.Envelope())
	return nil
}

// Rotate rotates the vault's identity key and sends identity.rotate
// (VAULT-MESSAGING §6.6). It returns the new ik.
func (v *Vault) Rotate() (ed25519.PublicKey, error) {
	_, nk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	nkem, err := suite.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	r, err := handshake.NewRotation(v.ik, nk, nkem.Public())
	if err != nil {
		return nil, err
	}
	body := append(append([]byte(`{"rotation":`), r.Marshal()...), '}')
	if _, err := v.sealLocked(&envelope.Inner{Type: "identity.rotate", Body: body}); err != nil {
		return nil, err
	}
	v.ik, v.kem = nk, nkem
	return nk.Public().(ed25519.PublicKey), nil
}

// SetDepositError sets DepositError while the vault runs.
func (v *Vault) SetDepositError(e *RelayError) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.DepositError = e
}

// RekeyResps returns how many hs.resp the vault's rekeys received
// (a repeated one is counted and ignored).
func (v *Vault) RekeyResps() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.rekeyRsp
}

// RekeyDone reports whether the last rekey completed.
func (v *Vault) RekeyDone() bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.rekey == nil && v.rekeyRsp > 0
}

// Received returns the inner types the device sent in session, in
// order.
func (v *Vault) Received() []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return append([]string(nil), v.received...)
}

// Pending returns how many messages wait unacknowledged in the device's
// mailbox.
func (v *Vault) Pending() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return len(v.queue)
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
			v.mu.Lock()
			fail := v.DepositError
			if v.session == nil {
				fail = nil
			}
			v.mu.Unlock()
			if fail != nil {
				relayError(w, fail.Status, fail.Code)
				return
			}
			v.toVault(in.Payload)
		}
		writeJSON(w, http.StatusOK, map[string]string{"msg_id": "d" + strconv.FormatInt(time.Now().UnixNano(), 10)})
	case r.Method == http.MethodGet && p == "/v1/mailbox":
		v.collect(w, r)
	case r.Method == http.MethodDelete && strings.HasPrefix(p, "/v1/mailbox/"):
		id := strings.TrimPrefix(p, "/v1/mailbox/")
		v.mu.Lock()
		if v.FailAcks {
			v.mu.Unlock()
			relayError(w, http.StatusBadRequest, "test_ack_refused")
			return
		}
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
		if v.rekey != nil && env.RecipientKid().Equal(v.rekey.EphKid()) {
			v.rekeyRsp++
			res, err := v.rekey.HandleResp(payload, v.devPK, now)
			if err != nil {
				break
			}
			v.session.Activate(res.Epoch, now)
			v.doneRekey, v.rekey = v.rekey.EphKid(), nil
			v.enqueueLocked(res.Fin)
			break
		}
		if v.rekeyRsp > 0 && env.RecipientKid().Equal(v.doneRekey) {
			// A repeated hs.resp of a finished rekey: counted, dropped.
			v.rekeyRsp++
			break
		}
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
		v.devIK = in.From.IK
		v.inits++
		v.enqueueLocked(out)
	case envelope.ModeSession:
		if v.session != nil {
			if in, _, err := v.session.Open(env, now); err == nil {
				v.received = append(v.received, in.Type)
				if in.Type == "leash.grant.list" && in.Re == "" {
					resp := &envelope.Inner{Type: in.Type, Re: in.ID, Status: envelope.StatusOK, Body: []byte(`{"grants":[],"suspended":false}`)}
					if v.GrantListError != "" {
						resp.Status, resp.Body = envelope.StatusError, nil
						resp.Error = &envelope.Error{Code: v.GrantListError}
					}
					_, _ = v.sealLocked(resp)
				}
				if in.Type == "vault.status" && in.Re == "" {
					_, _ = v.sealLocked(&envelope.Inner{Type: in.Type, Re: in.ID, Status: envelope.StatusOK,
						Body: []byte(`{"vault_id":"` + VaultID + `","state_seq":1,"header_seq":1,"provisional":false,"devices":[],"connections":[],"owner_check":{"state":"ok"}}`)})
				}
				break
			}
		}
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
