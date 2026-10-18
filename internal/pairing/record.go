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
//	{"v":1,"phase":"started"|"waiting"|"paired","deadline":"<RFC 3339>","device":{…}}
//
// deadline is present exactly while pairing is unfinished (started or
// waiting): the end of the 10 minutes after hs.init (VAULT-MESSAGING
// §6.7). device is the client's Save output (secret: keys, tokens, the
// session keyring). Neither the pairing code nor the SAS is ever stored
// (AGENT-PLAN §4.7).
type Record struct {
	Phase    Phase
	Deadline time.Time // zero once paired
	Device   json.RawMessage
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
	case PhasePaired:
	default:
		return fmt.Errorf("%w: unknown phase", ErrRecord)
	}
	d := bytes.TrimSpace(r.Device)
	if len(d) < 2 || d[0] != '{' || !json.Valid(d) {
		return fmt.Errorf("%w: no device state", ErrRecord)
	}
	return nil
}
