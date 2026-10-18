package pairing

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// TestRecordLeash: the `leash` member (internal/leash's grants) is kept
// as given on a paired record, absent when nil, and refused when it is
// not a JSON object or the pairing is unfinished.
func TestRecordLeash(t *testing.T) {
	member := json.RawMessage(`{"v":1,"grants":[]}`)
	b, err := (&Record{Phase: PhasePaired, Device: json.RawMessage(`{}`), Leash: member}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	r, err := DecodeRecord(b)
	if err != nil || !bytes.Equal(r.Leash, member) {
		t.Fatalf("got %s, %v (%s)", r.Leash, err, b)
	}
	b, _ = (&Record{Phase: PhasePaired, Device: json.RawMessage(`{}`)}).Encode()
	if bytes.Contains(b, []byte("leash")) {
		t.Errorf("nil member written: %s", b)
	}
	if r, err := DecodeRecord(b); err != nil || r.Leash != nil {
		t.Errorf("absent member: %s %v", r.Leash, err)
	}
	for _, bad := range []string{
		`{"v":1,"phase":"paired","device":{},"leash":null}`,
		`{"v":1,"phase":"paired","device":{},"leash":[]}`,
		`{"v":1,"phase":"paired","device":{},"leash":"x"}`,
		`{"v":1,"phase":"waiting","deadline":"2026-10-01T12:00:00Z","device":{},"leash":{}}`,
	} {
		if _, err := DecodeRecord([]byte(bad)); !errors.Is(err, ErrRecord) {
			t.Errorf("%s: %v", bad, err)
		}
	}
	if _, err := (&Record{Phase: PhaseWaiting, Deadline: time.Now(), Device: json.RawMessage(`{}`), Leash: member}).Encode(); err == nil {
		t.Error("encoded leash on an unfinished pairing")
	}
}
