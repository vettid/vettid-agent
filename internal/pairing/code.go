// Package pairing is `vettid-agent pair` (AGENT-PLAN §4.3, §6 A2.1;
// VAULT-MESSAGING §6.7): it reads the pairing code the member's phone
// shows, creates the device with fresh keys through vettid-vault's
// reference client, runs the handshake, shows the SAS, and waits for the
// owner's approval (device.paired), rejection (device.pair.rejected) or
// the end of the 10 minutes after hs.init, saving the state through
// internal/state at each step.
//
// Pairing codes, the keys and the SAS are never logged or put in an
// error. The SAS is shown once, on the operator's terminal.
package pairing

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/vettid/vettid-vault/vms/invite"
)

// Code is a parsed pairing code (VAULT-MESSAGING §6.4).
type Code struct {
	// Link is the bare base64url payload, which the client's Pair takes.
	Link string
	// Relay is the payload's `r`: the vault's relay, which decides where
	// the claim is fetched (the host of a URL form is not trusted).
	Relay string
	// Exp is the code's expiry (`e`).
	Exp time.Time

	claimID string
	key     string // `k` as base64url, only to redact it from errors
}

// secrets returns the parts of the code that must never appear in an
// error or a log.
func (c *Code) secrets() []string {
	return []string{c.Link, c.claimID, c.key}
}

// MaxCodeInput is the most text ParseCode looks at.
const MaxCodeInput = 64 << 10

// minPayloadLen is the shortest run of base64url characters tried as a
// payload: a QR payload of §6.4 is far longer.
const minPayloadLen = 64

var (
	// ErrNoCode: no pairing code was found in the text.
	ErrNoCode = errors.New("no pairing code found: paste the code from Devices & agents on your phone (the code, or the link that contains it)")
	// ErrManyCodes: the text holds more than one different code.
	ErrManyCodes = errors.New("more than one pairing code found: paste only one")
	// ErrNotAgent: the code is a valid invitation of another kind.
	ErrNotAgent = errors.New("this is not an agent pairing code")
	// ErrCodeExpired: the code's `e` has passed.
	ErrCodeExpired = errors.New("the pairing code has expired")
	// ErrRelayNotHTTPS: the code names a relay that is not reached over
	// HTTPS (plain HTTP to a loopback address is allowed only in builds
	// with the devstack tag).
	ErrRelayNotHTTPS = errors.New("the pairing code names a relay that is not reached over HTTPS; this build pairs only through HTTPS relays")
	// ErrCodeTooLong: the text is longer than MaxCodeInput.
	ErrCodeTooLong = errors.New("the pasted text is too long to hold a pairing code")
)

// ParseCode finds the pairing code in text and checks it (AGENT-PLAN
// §4.3 step 2; VAULT-MESSAGING §6.4). It accepts the bare payload, the
// URL form `<r>/connect#<payload>` on any host, the `vettid://connect#`
// form, and any of them inside surrounding text: every maximal run of
// base64url characters is tried as a payload, and the payload alone is
// authoritative. It then checks that the code is for an agent (`t` =
// "a") and has not expired at now. The bundle hash is checked by the
// client when it fetches the claim (invite.OpenBundle).
//
// Errors never contain the code or a part of it.
func ParseCode(text string, now time.Time) (*Code, error) {
	link, found, err := findPayload(text)
	if err != nil {
		return nil, err
	}
	if found.Kind != invite.KindAgent {
		return nil, fmt.Errorf("%w: %s; on your phone, open Devices & agents and choose Pair an agent", ErrNotAgent, kindName(found.Kind))
	}
	if !relaySchemeAllowed(found.Relay) {
		return nil, ErrRelayNotHTTPS
	}
	exp := time.Unix(found.Exp, 0).UTC()
	if !now.Before(exp) {
		return nil, ErrCodeExpired
	}
	return &Code{Link: link, Relay: found.Relay, Exp: exp, claimID: found.ClaimID,
		key: base64.RawURLEncoding.EncodeToString(found.Key)}, nil
}

// allowHTTPRelay allows a plain-HTTP relay on a loopback address (which
// VAULT-MESSAGING §6.2 allows for development); set only by the
// devstack build tag (relay_devstack.go, AGENT-PLAN §4.8).
var allowHTTPRelay = false

// relaySchemeAllowed reports whether the code's relay URL may be used:
// https, or (devstack builds only) http, which the invite package
// accepts only for loopback hosts.
func relaySchemeAllowed(relay string) bool {
	u, err := url.Parse(relay)
	if err != nil {
		return false
	}
	return u.Scheme == "https" || (allowHTTPRelay && u.Scheme == "http")
}

// findPayload returns the one payload in text and its parsed QR.
func findPayload(text string) (string, *invite.QR, error) {
	if len(text) > MaxCodeInput {
		return "", nil, ErrCodeTooLong
	}
	var found *invite.QR
	var link string
	for _, run := range base64URLRuns(text) {
		if len(run) < minPayloadLen {
			continue
		}
		q, err := invite.ParseLink(run)
		if err != nil {
			continue
		}
		if found != nil && run != link {
			return "", nil, ErrManyCodes
		}
		found, link = q, run
	}
	if found == nil {
		return "", nil, ErrNoCode
	}
	return link, found, nil
}

// kindName names an invitation kind for the operator.
func kindName(k invite.Kind) string {
	switch k {
	case invite.KindConnection:
		return "it is an invitation to connect with someone"
	case invite.KindApp:
		return "it moves the VettID app to a new phone"
	case invite.KindDesktop:
		return "it pairs a desktop"
	default:
		return "it is of an unknown kind"
	}
}

func isBase64URL(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_'
}

// base64URLRuns returns the maximal runs of base64url characters in s.
func base64URLRuns(s string) []string {
	var runs []string
	start := -1
	for i := 0; i <= len(s); i++ {
		if i < len(s) && isBase64URL(s[i]) {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 {
			runs = append(runs, s[start:i])
			start = -1
		}
	}
	return runs
}

// redact replaces every non-empty secret in s with "[redacted]".
func redact(s string, secrets ...string) string {
	for _, x := range secrets {
		if x != "" {
			s = strings.ReplaceAll(s, x, "[redacted]")
		}
	}
	return s
}
