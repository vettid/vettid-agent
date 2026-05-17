package nats

import (
	"testing"
	"time"
)

func mkEnv(seq uint64, ts time.Time) *Envelope {
	return &Envelope{
		Type:      MsgSecretResponse,
		KeyID:     "test",
		Payload:   []byte("x"),
		Sequence:  seq,
		Timestamp: ts,
	}
}

func TestEnvelopeValidator_AcceptsMonotonic(t *testing.T) {
	v := NewEnvelopeValidator()
	now := time.Now()
	v.now = func() time.Time { return now }

	if err := v.Validate(mkEnv(1, now)); err != nil {
		t.Fatalf("seq 1: %v", err)
	}
	if err := v.Validate(mkEnv(2, now)); err != nil {
		t.Fatalf("seq 2: %v", err)
	}
	if err := v.Validate(mkEnv(100, now)); err != nil {
		t.Fatalf("seq 100 (jump): %v", err)
	}
}

func TestEnvelopeValidator_RejectsReplay(t *testing.T) {
	v := NewEnvelopeValidator()
	now := time.Now()
	v.now = func() time.Time { return now }

	if err := v.Validate(mkEnv(5, now)); err != nil {
		t.Fatalf("seq 5: %v", err)
	}
	// Replay of seq 5
	if err := v.Validate(mkEnv(5, now)); err == nil {
		t.Errorf("validator accepted replay of seq 5")
	}
	// Older seq
	if err := v.Validate(mkEnv(4, now)); err == nil {
		t.Errorf("validator accepted older seq 4")
	}
	// Zero seq is invalid
	if err := v.Validate(mkEnv(0, now)); err == nil {
		t.Errorf("validator accepted seq 0")
	}
}

func TestEnvelopeValidator_RejectsStaleTimestamp(t *testing.T) {
	v := NewEnvelopeValidator()
	now := time.Now()
	v.now = func() time.Time { return now }

	old := now.Add(-(maxInboundSkew + time.Minute))
	if err := v.Validate(mkEnv(1, old)); err == nil {
		t.Errorf("validator accepted stale timestamp %s past skew", old)
	}
}

func TestEnvelopeValidator_RejectsFutureTimestamp(t *testing.T) {
	v := NewEnvelopeValidator()
	now := time.Now()
	v.now = func() time.Time { return now }

	future := now.Add(maxFutureSkew + time.Minute)
	if err := v.Validate(mkEnv(1, future)); err == nil {
		t.Errorf("validator accepted future timestamp %s past skew", future)
	}
}

func TestEnvelopeValidator_RejectMissingTimestamp(t *testing.T) {
	v := NewEnvelopeValidator()
	if err := v.Validate(mkEnv(1, time.Time{})); err == nil {
		t.Errorf("validator accepted zero timestamp")
	}
}

// Rejected envelopes must not advance lastSeqSeen — otherwise a
// hostile replay could permanently lock out the next legitimate
// sequence.
func TestEnvelopeValidator_RejectsDoNotAdvanceCounter(t *testing.T) {
	v := NewEnvelopeValidator()
	now := time.Now()
	v.now = func() time.Time { return now }

	if err := v.Validate(mkEnv(1, now)); err != nil {
		t.Fatalf("seq 1: %v", err)
	}
	// Stale timestamp — should be rejected without bumping counter
	old := now.Add(-(maxInboundSkew + time.Minute))
	_ = v.Validate(mkEnv(50, old))
	// Now a legitimate seq 2 should still be accepted
	if err := v.Validate(mkEnv(2, now)); err != nil {
		t.Errorf("seq 2 after rejected seq 50: %v", err)
	}
}
