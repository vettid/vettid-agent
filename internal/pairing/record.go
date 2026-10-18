package pairing

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

// Record is the plaintext the connector keeps in its state file
// (internal/state encrypts it; docs/STATE-FILE.md "What the state holds"):
// the vault client's saved state, and how far pairing got.
//
//	{"v":1,"phase":"started"|"waiting"|"paired","deadline":"<RFC 3339>","device":{…},
//	 "access":{"state":"none"|"active","session_id":"…","expires_at":"<RFC 3339>"}}
//
// deadline is present exactly while pairing is unfinished (started or
// waiting): the end of the 10 minutes after hs.init (VAULT-MESSAGING
// §6.7). device is the client's Save output (secret: keys, tokens, the
// session keyring). Neither the pairing code nor the SAS is ever stored
// (AGENT-PLAN §4.7).
//
// access (paired records only, optional) is the connector's access
// session (VAULT-MESSAGING §6.8) as of the save: none, or active with
// session_id and expires_at (from device.session.granted), with
// expires_at only (the first session, from device.paired, which carries
// no session id), or with neither (a session found by a check whose end
// is not known). It is first written by internal/pairing from
// device.paired, then by internal/vaultconn from device.session.granted
// and .ended in the same save as the batch that carried them, and from
// what internal/access learns by a check. A record without it (paired by
// a build before the first session was recorded) reads as unknown;
// "unknown" is never written.
type Record struct {
	Phase    Phase
	Deadline time.Time // zero once paired
	Device   json.RawMessage
	Access   Access // paired only; the zero value is AccessUnknown
}

// Access is the access session as the connector last knew it.
type Access struct {
	State     AccessState
	SessionID string    // active only
	ExpiresAt time.Time // active only; zero when the expiry is not known
}

// AccessState is the kind of access the connector knows of.
type AccessState string

const (
	// AccessUnknown: not known (a record without the member, paired by
	// a build that did not record the first session). The zero value.
	AccessUnknown AccessState = ""
	// AccessNone: no access session.
	AccessNone AccessState = "none"
	// AccessActive: a session, until ExpiresAt (if known).
	AccessActive AccessState = "active"
)

// maxSessionID bounds a session id (chosen; the vault's are short ids).
const maxSessionID = 128

// Valid reports whether a has a consistent form.
func (a Access) Valid() bool {
	switch a.State {
	case AccessUnknown, AccessNone:
		return a.SessionID == "" && a.ExpiresAt.IsZero()
	case AccessActive:
		return len(a.SessionID) <= maxSessionID
	}
	return false
}

type accessJSON struct {
	State     string     `json:"state"`
	SessionID string     `json:"session_id,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// Phase is how far pairing got.
type Phase string

const (
	// PhaseStarted: fresh keys exist and the mailbox is registered; the
	// SAS has not been shown. Not resumable: the next `pair` discards it.
	PhaseStarted Phase = "started"
	// PhaseWaiting: the handshake completed and the SAS was shown; the
	// connector waits for the owner's decision until Deadline. Resumable
	// until then.
	PhaseWaiting Phase = "waiting"
	// PhasePaired: device.paired arrived; the device record is complete.
	PhasePaired Phase = "paired"
)

const recordVersion = 1

// maxRecord bounds the record decoded (the state file's own limit is
// larger; a device state is a few KiB).
const maxRecord = 4 << 20

type recordJSON struct {
	V        int             `json:"v"`
	Phase    Phase           `json:"phase"`
	Deadline *time.Time      `json:"deadline,omitempty"`
	Device   json.RawMessage `json:"device"`
	Access   *accessJSON     `json:"access,omitempty"`
}

// ErrRecord: the state file's plaintext is not a valid record.
var ErrRecord = errors.New("the state file's contents are not a valid connector record")

// Encode returns the record's JSON.
func (r *Record) Encode() ([]byte, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	j := recordJSON{V: recordVersion, Phase: r.Phase, Device: r.Device}
	if r.Phase != PhasePaired {
		d := r.Deadline.UTC()
		j.Deadline = &d
	} else if r.Access.State != AccessUnknown {
		a := &accessJSON{State: string(r.Access.State), SessionID: r.Access.SessionID}
		if !r.Access.ExpiresAt.IsZero() {
			e := r.Access.ExpiresAt.UTC()
			a.ExpiresAt = &e
		}
		j.Access = a
	}
	return json.Marshal(j)
}

// DecodeRecord parses a record strictly: version 1, a known phase, a
// deadline exactly when unfinished, a JSON object as device, no unknown
// members and nothing after.
func DecodeRecord(b []byte) (*Record, error) {
	if len(b) > maxRecord {
		return nil, fmt.Errorf("%w: too large", ErrRecord)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var j recordJSON
	if err := dec.Decode(&j); err != nil {
		return nil, fmt.Errorf("%w: not the expected JSON", ErrRecord)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: data after the record", ErrRecord)
	}
	if j.V != recordVersion {
		return nil, fmt.Errorf("%w: unknown version", ErrRecord)
	}
	r := &Record{Phase: j.Phase, Device: j.Device}
	if j.Access != nil {
		if r.Phase != PhasePaired {
			return nil, fmt.Errorf("%w: access on an unfinished pairing", ErrRecord)
		}
		st := AccessState(j.Access.State)
		if st == AccessUnknown {
			return nil, fmt.Errorf("%w: invalid access", ErrRecord)
		}
		r.Access = Access{State: st, SessionID: j.Access.SessionID}
		if j.Access.ExpiresAt != nil {
			r.Access.ExpiresAt = *j.Access.ExpiresAt
		}
	}
	if j.Deadline != nil {
		r.Deadline = *j.Deadline
		if r.Phase == PhasePaired {
			return nil, fmt.Errorf("%w: a deadline on a completed pairing", ErrRecord)
		}
	} else if r.Phase != PhasePaired {
		return nil, fmt.Errorf("%w: an unfinished pairing without a deadline", ErrRecord)
	}
	if err := r.check(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *Record) check() error {
	switch r.Phase {
	case PhaseStarted, PhaseWaiting:
		if r.Deadline.IsZero() {
			return fmt.Errorf("%w: an unfinished pairing without a deadline", ErrRecord)
		}
		if r.Access.State != AccessUnknown {
			return fmt.Errorf("%w: access on an unfinished pairing", ErrRecord)
		}
	case PhasePaired:
		if !r.Access.Valid() {
			return fmt.Errorf("%w: invalid access", ErrRecord)
		}
	default:
		return fmt.Errorf("%w: unknown phase", ErrRecord)
	}
	d := bytes.TrimSpace(r.Device)
	if len(d) < 2 || d[0] != '{' || !json.Valid(d) {
		return fmt.Errorf("%w: no device state", ErrRecord)
	}
	return nil
}
