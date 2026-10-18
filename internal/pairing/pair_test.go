package pairing

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/vms/invite"

	"github.com/vettid/vettid-agent/internal/pairing/pairtest"
	"github.com/vettid/vettid-agent/internal/state"
)

// testProtector wraps under a fixed in-memory key (tests only).
type testProtector struct {
	name   string
	key    [32]byte
	broken bool // Unwrap always fails
	wipes  int
}

func (p *testProtector) Name() string { return p.name }
func (p *testProtector) Wrap(k []byte) ([]byte, error) {
	a, _ := chacha20poly1305.NewX(p.key[:])
	n := make([]byte, a.NonceSize())
	return a.Seal(n, n, k, nil), nil
}
func (p *testProtector) Unwrap(w []byte) ([]byte, error) {
	a, _ := chacha20poly1305.NewX(p.key[:])
	if p.broken || len(w) < a.NonceSize() {
		return nil, errors.New("test protector refuses")
	}
	return a.Open(nil, w[:a.NonceSize()], w[a.NonceSize():], nil)
}
func (p *testProtector) Wipe() error { p.wipes++; return nil }

// syncBuffer is the operator's terminal; onLine runs for every line
// written.
type syncBuffer struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	onLine func(string)
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	n, err := b.buf.Write(p)
	f := b.onLine
	b.mu.Unlock()
	if f != nil {
		for _, l := range strings.Split(strings.TrimRight(string(p), "\n"), "\n") {
			f(l)
		}
	}
	return n, err
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type env struct {
	t     *testing.T
	v     *pairtest.Vault
	dir   string
	prot  *testProtector
	out   *syncBuffer
	codes int // Code calls
}

func newEnv(t *testing.T) *env {
	t.Helper()
	v, err := pairtest.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(v.Close)
	old := Window
	t.Cleanup(func() { Window = old })
	return &env{t: t, v: v, dir: filepath.Join(t.TempDir(), "state"), prot: &testProtector{name: "test-key", key: [32]byte{1, 2, 3}}, out: &syncBuffer{}}
}

// options returns Options over an opened store, with code as the text.
func (e *env) options(s *state.Store, code string) Options {
	return Options{
		Store:         s,
		Resolve:       func(n string) state.Protector { return map[string]state.Protector{e.prot.name: e.prot}[n] },
		AllProtectors: []state.Protector{e.prot},
		Protector:     func() (state.Protector, string, error) { return e.prot, "", nil },
		Code:          func() (string, error) { e.codes++; return code, nil },
		Name:          "Agent on test-host",
		Out:           e.out,
		HTTP:          e.v.HTTPClient(),
		PollWait:      10 * time.Millisecond,
	}
}

func (e *env) open() *state.Store {
	e.t.Helper()
	s, err := state.Open(e.dir)
	if err != nil {
		e.t.Fatal(err)
	}
	return s
}

func (e *env) code(k invite.Kind, ttl time.Duration) string {
	e.t.Helper()
	c, err := e.v.Code(k, ttl)
	if err != nil {
		e.t.Fatal(err)
	}
	return c
}

// pair runs Pair with opts adjusted by adjust.
func (e *env) pair(ctx context.Context, code string, adjust func(*Options)) error {
	s := e.open()
	defer s.Close()
	o := e.options(s, code)
	if adjust != nil {
		adjust(&o)
	}
	return Pair(ctx, o)
}

// record loads the state file's record (nil if there is none).
func (e *env) record() (*Record, *client.State) {
	e.t.Helper()
	s := e.open()
	defer s.Close()
	ok, err := s.Exists()
	if err != nil {
		e.t.Fatal(err)
	}
	if !ok {
		return nil, nil
	}
	raw, err := s.Load(func(string) state.Protector { return e.prot })
	if err != nil {
		e.t.Fatal(err)
	}
	r, err := DecodeRecord(raw)
	if err != nil {
		e.t.Fatal(err)
	}
	var st client.State
	if err := json.Unmarshal(r.Device, &st); err != nil {
		e.t.Fatal(err)
	}
	return r, &st
}

// checkNoSecrets: the operator output never holds the code or any part
// of it, and holds the SAS only in the one SAS line.
func (e *env) checkNoSecrets(code string) {
	e.t.Helper()
	out := e.out.String()
	c, err := ParseCode(code, time.Now())
	if err == nil {
		for _, s := range c.secrets() {
			if strings.Contains(out, s) {
				e.t.Errorf("the output holds a part of the code")
			}
		}
	}
	if strings.Contains(out, code) {
		e.t.Errorf("the output holds the code")
	}
	if sas := e.v.SAS(); sas != "" {
		if strings.Contains(out, sas) {
			e.t.Errorf("the output holds the SAS unformatted")
		}
		shown, _ := FormatSAS(sas)
		if n := strings.Count(out, shown); n > 1 {
			e.t.Errorf("the SAS is shown %d times", n)
		}
	}
}

func TestPairApproved(t *testing.T) {
	e := newEnv(t)
	code := e.code(invite.KindAgent, 10*time.Minute)
	if err := e.pair(context.Background(), code, nil); err != nil {
		t.Fatalf("Pair: %v\n%s", err, e.out)
	}
	out := e.out.String()
	shown, _ := FormatSAS(e.v.SAS())
	wantOrder := []string{textContacting, "Check that your phone shows the same code: " + shown + ". Approve on your phone only if it matches.", TextWaiting, TextPaired}
	at := 0
	for _, w := range wantOrder {
		i := strings.Index(out[at:], w)
		if i < 0 {
			t.Fatalf("output lacks %q in order:\n%s", w, out)
		}
		at += i + len(w)
	}
	e.checkNoSecrets(code)
	if e.v.Name() != "Agent on test-host" {
		t.Errorf("name sent %q", e.v.Name())
	}
	r, st := e.record()
	if r == nil || r.Phase != PhasePaired || !r.Deadline.IsZero() {
		t.Fatalf("record %+v", r)
	}
	if st.Role != "agent" || st.DeviceID != pairtest.DeviceID || st.VaultID != pairtest.VaultID || st.Vault == nil || st.Vault.Token == "" {
		t.Errorf("device state: role %q device %q vault %q", st.Role, st.DeviceID, st.VaultID)
	}
	// A second pair refuses: the directory holds a completed pairing.
	if err := e.pair(context.Background(), e.code(invite.KindAgent, time.Minute), nil); !errors.Is(err, ErrAlreadyPaired) {
		t.Errorf("second pair: %v", err)
	}
	if r2, _ := e.record(); r2 == nil || r2.Phase != PhasePaired {
		t.Error("the completed pairing was changed")
	}
}

func TestPairRejected(t *testing.T) {
	e := newEnv(t)
	e.v.Decide = func(string) pairtest.Decision { return pairtest.Reject }
	code := e.code(invite.KindAgent, 10*time.Minute)
	err := e.pair(context.Background(), code, nil)
	if !errors.Is(err, ErrRejected) || err.Error() != TextRejected {
		t.Fatalf("got %v", err)
	}
	if !strings.Contains(e.out.String(), TextWaiting) {
		t.Errorf("no waiting text:\n%s", e.out)
	}
	e.checkNoSecrets(code)
	if r, _ := e.record(); r != nil {
		t.Errorf("state kept after a rejection: %+v", r.Phase)
	}
	if e.prot.wipes == 0 {
		t.Error("the protector's key was not wiped")
	}
}

func TestPairExpired(t *testing.T) {
	e := newEnv(t)
	Window = 1500 * time.Millisecond
	e.v.Decide = func(string) pairtest.Decision { return pairtest.Hold }
	code := e.code(invite.KindAgent, 10*time.Minute)
	start := time.Now()
	err := e.pair(context.Background(), code, nil)
	if !errors.Is(err, ErrExpired) || err.Error() != TextExpired {
		t.Fatalf("got %v", err)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("waited %v", d)
	}
	if r, _ := e.record(); r != nil {
		t.Errorf("state kept after the timeout")
	}
	// A late approval finds nothing to complete.
	if err := e.v.Approve(); err != nil {
		t.Fatal(err)
	}
}

// TestPairInterruptedAndResumed: interrupted after the SAS was shown,
// the state is kept (phase waiting); `pair` again without a code
// resumes with the saved keys and completes on the approval.
func TestPairInterruptedAndResumed(t *testing.T) {
	e := newEnv(t)
	e.v.Decide = func(string) pairtest.Decision { return pairtest.Hold }
	code := e.code(invite.KindAgent, 10*time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e.out.onLine = func(l string) {
		if l == TextWaiting {
			cancel()
		}
	}
	err := e.pair(ctx, code, nil)
	if !errors.Is(err, ErrInterrupted) || !strings.Contains(err.Error(), "run `vettid-agent pair` again (without a code)") {
		t.Fatalf("got %v", err)
	}
	r, st := e.record()
	if r == nil || r.Phase != PhaseWaiting || r.Deadline.IsZero() || st.DeviceID != "" || st.Vault == nil {
		t.Fatalf("record after the interruption: %+v", r)
	}
	ik := ed25519.NewKeyFromSeed(st.IKSeed).Public()

	e.out.onLine = nil
	if err := e.v.Approve(); err != nil {
		t.Fatal(err)
	}
	e.codes = 0
	if err := e.pair(context.Background(), "", func(o *Options) { o.CodeOnStdin, o.PassphraseChosen = true, true }); err != nil {
		t.Fatalf("resume: %v\n%s", err, e.out)
	}
	for _, w := range []string{textResumeStdin, textResumePassphrase, "If you are not sure a code was shown here"} {
		if !strings.Contains(e.out.String(), w) {
			t.Errorf("resume output lacks %q", w)
		}
	}
	if e.codes != 0 {
		t.Error("the resume asked for a code")
	}
	if !strings.Contains(e.out.String(), "Resuming the pairing") || !strings.HasSuffix(e.out.String(), TextPaired+"\n") {
		t.Errorf("output:\n%s", e.out)
	}
	e.checkNoSecrets(code)
	r, st = e.record()
	if r.Phase != PhasePaired || st.DeviceID != pairtest.DeviceID {
		t.Fatalf("after the resume: %+v", r)
	}
	if !ed25519.NewKeyFromSeed(st.IKSeed).Public().(ed25519.PublicKey).Equal(ik) {
		t.Error("the resume changed the keys")
	}
	if e.v.Inits() != 1 {
		t.Errorf("%d hs.init, want 1", e.v.Inits())
	}
}

// TestPairInterruptedBeforeSAS: an interruption before the SAS is
// shown keeps nothing.
func TestPairInterruptedBeforeSAS(t *testing.T) {
	e := newEnv(t)
	code := e.code(invite.KindAgent, 10*time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e.out.onLine = func(l string) {
		if l == textContacting {
			cancel()
		}
	}
	err := e.pair(ctx, code, nil)
	if !errors.Is(err, ErrInterrupted) || err.Error() != textInterruptedEarly {
		t.Fatalf("got %v", err)
	}
	if r, _ := e.record(); r != nil {
		t.Error("state kept")
	}
}

// writeRecord puts a record with a fresh (unregistered) device state in
// the state directory, as an interrupted earlier run would have left.
func (e *env) writeRecord(phase Phase, deadline time.Time) *client.State {
	e.t.Helper()
	d, err := client.Generate(client.Config{Role: "agent", Name: "old", RelayURL: e.v.URL()})
	if err != nil {
		e.t.Fatal(err)
	}
	dev, err := d.Save()
	if err != nil {
		e.t.Fatal(err)
	}
	if phase != PhaseStarted {
		// A completed handshake has a vault record (enough for the
		// resume checks here).
		var st map[string]any
		_ = json.Unmarshal(dev, &st)
		st["vault"] = map[string]any{"ik": []byte{1}, "kem": []byte{1}, "relay_url": e.v.URL(), "mailbox": "m", "relay_pk": []byte{1}, "sessions": map[string]any{}, "suite": 2}
		if phase == PhasePaired {
			st["device_id"] = "old-device"
		}
		dev, _ = json.Marshal(st)
	}
	b, err := (&Record{Phase: phase, Deadline: deadline, Device: dev}).Encode()
	if err != nil {
		e.t.Fatal(err)
	}
	s := e.open()
	defer s.Close()
	if err := s.Create(e.prot, b); err != nil {
		e.t.Fatal(err)
	}
	var st client.State
	_ = json.Unmarshal(dev, &st)
	return &st
}

// TestPairDiscardsUnfinished: a run that crashed before its SAS was
// shown left phase started; the next `pair` discards it (new keys) and
// pairs.
func TestPairDiscardsUnfinished(t *testing.T) {
	e := newEnv(t)
	old := e.writeRecord(PhaseStarted, time.Now().Add(5*time.Minute))
	code := e.code(invite.KindAgent, 10*time.Minute)
	if err := e.pair(context.Background(), code, nil); err != nil {
		t.Fatalf("%v\n%s", err, e.out)
	}
	if !strings.HasPrefix(e.out.String(), textContacting+"\n"+textDiscarded+"\n") {
		t.Errorf("output:\n%s", e.out)
	}
	r, st := e.record()
	if r.Phase != PhasePaired || bytes.Equal(st.IKSeed, old.IKSeed) {
		t.Error("not paired with new keys")
	}
}

// TestPairCodeGivenDiscardsWaiting: a code on the command line starts a
// new pairing over a resumable one.
func TestPairCodeGivenDiscardsWaiting(t *testing.T) {
	e := newEnv(t)
	old := e.writeRecord(PhaseWaiting, time.Now().Add(5*time.Minute))
	code := e.code(invite.KindAgent, 10*time.Minute)
	if err := e.pair(context.Background(), code, func(o *Options) { o.CodeGiven = true }); err != nil {
		t.Fatalf("%v\n%s", err, e.out)
	}
	r, st := e.record()
	if r.Phase != PhasePaired || bytes.Equal(st.IKSeed, old.IKSeed) || !strings.Contains(e.out.String(), textDiscarded) {
		t.Error("the waiting pairing was not replaced")
	}
}

// TestPairWaitEndedWhileStopped: a waiting record whose deadline passed
// is wiped and reported as expired.
func TestPairWaitEndedWhileStopped(t *testing.T) {
	e := newEnv(t)
	e.writeRecord(PhaseWaiting, time.Now().Add(-time.Second))
	if err := e.pair(context.Background(), "", nil); !errors.Is(err, ErrExpired) {
		t.Fatalf("got %v", err)
	}
	if e.codes != 0 {
		t.Error("asked for a code")
	}
	if r, _ := e.record(); r != nil {
		t.Error("state kept")
	}
}

// TestPairRestart: --restart replaces a completed pairing, and a state
// file that does not open (refused without it).
func TestPairRestart(t *testing.T) {
	e := newEnv(t)
	e.writeRecord(PhasePaired, time.Time{})
	if err := e.pair(context.Background(), e.code(invite.KindAgent, time.Minute), func(o *Options) { o.Restart = true }); err != nil {
		t.Fatalf("%v\n%s", err, e.out)
	}
	if !strings.Contains(e.out.String(), textReplaced) {
		t.Errorf("output:\n%s", e.out)
	}
	if r, st := e.record(); r.Phase != PhasePaired || st.DeviceID != pairtest.DeviceID {
		t.Error("not replaced")
	}

	e2 := newEnv(t)
	e2.writeRecord(PhaseStarted, time.Now().Add(time.Minute))
	e2.prot.broken = true
	err := e2.pair(context.Background(), e2.code(invite.KindAgent, time.Minute), nil)
	if err == nil || !strings.Contains(err.Error(), "--restart") {
		t.Fatalf("unopenable without --restart: %v", err)
	}
	if len(e2.v.Requests()) != 0 {
		t.Error("contacted the relay")
	}
	if err := e2.pair(context.Background(), e2.code(invite.KindAgent, time.Minute), func(o *Options) { o.Restart = true }); err != nil {
		t.Fatalf("with --restart: %v", err)
	}
	e2.prot.broken = false
	if r, _ := e2.record(); r.Phase != PhasePaired {
		t.Error("not paired")
	}
}

// TestPairRefusesBeforeContact: a code of another kind, an expired code
// and a protector that refuses (a TPM present but not working) stop
// before the relay is contacted, and nothing is written.
func TestPairRefusesBeforeContact(t *testing.T) {
	e := newEnv(t)
	cases := map[string]struct {
		code   string
		adjust func(*Options)
		want   error
	}{
		"connection code": {code: e.code(invite.KindConnection, time.Minute), want: ErrNotAgent},
		"desktop code":    {code: e.code(invite.KindDesktop, time.Minute), want: ErrNotAgent},
		"expired code":    {code: e.code(invite.KindAgent, -time.Second), want: ErrExpired},
		"no code":         {code: "hello", want: ErrNoCode},
		"protector": {code: e.code(invite.KindAgent, time.Minute), want: errTestTPM,
			adjust: func(o *Options) {
				o.Protector = func() (state.Protector, string, error) { return nil, "", errTestTPM }
			}},
	}
	for name, tc := range cases {
		err := e.pair(context.Background(), tc.code, tc.adjust)
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: got %v", name, err)
		}
		if err != nil && strings.Contains(err.Error(), tc.code) {
			t.Errorf("%s: the error holds the code", name)
		}
	}
	if n := len(e.v.Requests()); n != 0 {
		t.Errorf("%d relay requests", n)
	}
	if r, _ := e.record(); r != nil {
		t.Error("state written")
	}
}

var errTestTPM = errors.New("TPM: /dev/tpmrm0 cannot be opened by this user (permission denied): add your user to the tss group")

// TestPairCodeUsed: a code whose claim is gone (used) is refused with
// a plain text, and nothing is kept.
func TestPairCodeUsed(t *testing.T) {
	e := newEnv(t)
	code := e.code(invite.KindAgent, 10*time.Minute)
	if err := e.pair(context.Background(), code, nil); err != nil {
		t.Fatal(err)
	}
	e2 := newEnv(t)
	e2.v = e.v
	e2.out = &syncBuffer{}
	err := e2.pair(context.Background(), code, nil)
	if err == nil || !strings.Contains(err.Error(), "already used or has expired") {
		t.Fatalf("got %v", err)
	}
	if r, _ := e2.record(); r != nil {
		t.Error("state kept")
	}
}

func TestRedact(t *testing.T) {
	got := redact(`Get "https://relay.example/v1/claim/abcdef": EOF`, "abcdef", "")
	if strings.Contains(got, "abcdef") || !strings.Contains(got, "[redacted]") {
		t.Errorf("got %q", got)
	}
}

func TestCheckName(t *testing.T) {
	for _, ok := range []string{"Agent on host", "Agent é", strings.Repeat("a", MaxNameBytes)} {
		if err := CheckName(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", " lead", "trail ", "a\nb", "a\x00b", "\xff", strings.Repeat("a", MaxNameBytes+1),
		"evil\u202etxt.exe", "a\u200bb", "\u2066x\u2069", "a\ufeffb"} {
		if CheckName(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if n := DefaultName(); CheckName(n) != nil || !strings.HasPrefix(n, "Agent") {
		t.Errorf("default %q", n)
	}
	if got := truncateUTF8(strings.Repeat("é", 100), MaxNameBytes); len(got) > MaxNameBytes || CheckName(got) != nil {
		t.Errorf("truncated %q", got)
	}
}

func TestRecordStrict(t *testing.T) {
	good, err := (&Record{Phase: PhaseWaiting, Deadline: time.Unix(1790856600, 0), Device: json.RawMessage(`{"role":"agent"}`)}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	if r, err := DecodeRecord(good); err != nil || r.Phase != PhaseWaiting {
		t.Fatalf("%v", err)
	}
	for _, bad := range []string{
		`{"v":2,"phase":"paired","device":{}}`,
		`{"v":1,"phase":"other","device":{}}`,
		`{"v":1,"phase":"paired","deadline":"2026-10-01T12:00:00Z","device":{}}`,
		`{"v":1,"phase":"waiting","device":{}}`,
		`{"v":1,"phase":"paired","device":[]}`,
		`{"v":1,"phase":"paired"}`,
		`{"v":1,"phase":"paired","device":{},"x":1}`,
		`{"v":1,"phase":"paired","device":{}} {}`,
	} {
		if _, err := DecodeRecord([]byte(bad)); !errors.Is(err, ErrRecord) {
			t.Errorf("%s: %v", bad, err)
		}
	}
	if _, err := (&Record{Phase: PhaseStarted, Device: json.RawMessage(`{}`)}).Encode(); err == nil {
		t.Error("encoded an unfinished record without a deadline")
	}
}

var _ io.Writer = (*syncBuffer)(nil)

// TestPairRelayMismatch: a code whose `r` was altered to another relay
// (which forwards everything, so the handshake and the SAS are
// genuine) is refused after the handshake, before the SAS is shown or
// anything is saved as waiting; nothing is kept.
func TestPairRelayMismatch(t *testing.T) {
	e := newEnv(t)
	code, err := e.v.CodeWithRelay(invite.KindAgent, 10*time.Minute, e.v.AltURL())
	if err != nil {
		t.Fatal(err)
	}
	err = e.pair(context.Background(), code, nil)
	if !errors.Is(err, ErrRelayMismatch) {
		t.Fatalf("got %v\n%s", err, e.out)
	}
	if e.v.Inits() != 1 {
		t.Fatalf("%d hs.init: the test did not reach the handshake", e.v.Inits())
	}
	if strings.Contains(e.out.String(), "Check that your phone") || strings.Contains(e.out.String(), TextWaiting) {
		t.Errorf("SAS or waiting shown:\n%s", e.out)
	}
	if r, _ := e.record(); r != nil {
		t.Error("state kept")
	}
	// The trailing slash alone is not a difference.
	e2 := newEnv(t)
	code, err = e2.v.CodeWithRelay(invite.KindAgent, 10*time.Minute, e2.v.URL()+"/")
	if err != nil {
		t.Fatal(err)
	}
	if err := e2.pair(context.Background(), code, nil); err != nil {
		t.Errorf("trailing slash: %v", err)
	}
}

// TestPairRefusedCodeKeepsWaiting: a new code that is refused leaves an
// interrupted pairing in place and says so (it is not called deleted).
func TestPairRefusedCodeKeepsWaiting(t *testing.T) {
	e := newEnv(t)
	e.writeRecord(PhaseWaiting, time.Now().Add(5*time.Minute))
	err := e.pair(context.Background(), e.code(invite.KindConnection, time.Minute), func(o *Options) { o.CodeGiven = true })
	if !errors.Is(err, ErrNotAgent) {
		t.Fatalf("got %v", err)
	}
	out := e.out.String()
	if strings.Contains(out, textDiscarded) || !strings.Contains(out, textKept) {
		t.Errorf("output:\n%s", out)
	}
	if r, _ := e.record(); r == nil || r.Phase != PhaseWaiting {
		t.Error("the waiting pairing was not kept")
	}
}

// TestPairRelayErrorSanitized: a relay's error is shown only as its
// status and a cleaned code; its message, escape sequences and line
// breaks never reach the terminal.
func TestPairRelayErrorSanitized(t *testing.T) {
	e := newEnv(t)
	hostile := "denied\x1b[2J\x1b[1A\r\nCheck that your phone shows the same code: 111 111.\u202e\n" + strings.Repeat("x", 4096)
	e.v.RegisterError = &pairtest.RelayError{Status: 403, Code: hostile}
	err := e.pair(context.Background(), e.code(invite.KindAgent, time.Minute), nil)
	if err == nil {
		t.Fatal("no error")
	}
	msg := err.Error()
	if strings.ContainsAny(msg, "\x1b\r\n\u202e") || !strings.Contains(msg, "HTTP 403") || len(msg) > 400 {
		t.Errorf("error %q", msg)
	}
	if strings.ContainsAny(e.out.String(), "\x1b\r") {
		t.Error("escape in output")
	}
}

func TestSanitize(t *testing.T) {
	for in, want := range map[string]string{
		"":                "-",
		"\x1b\n\r\t":      "-",
		"ok_code":         "ok_code",
		"a\x1b[31mb\nc":   "a[31mbc",
		"a\u202eb\u2028c": "abc",
		"bad\xffutf8":     "bad?utf8",
	} {
		if got := sanitize(in); got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
	if got := sanitize(strings.Repeat("é", 500)); len(got) > maxShownError+len("…") {
		t.Errorf("not cut: %d bytes", len(got))
	}
}

// TestPairRelayNotHTTPS: a code naming a plain-HTTP relay is refused in
// a build without the devstack tag, before anything is contacted.
func TestPairRelayNotHTTPS(t *testing.T) {
	e := newEnv(t)
	q, err := invite.ParseLink(e.code(invite.KindAgent, time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	q.Relay = "http://127.0.0.1:1"
	link, err := q.Link()
	if err != nil {
		t.Fatal(err)
	}
	if allowHTTPRelay {
		t.Skip("devstack build")
	}
	if err := e.pair(context.Background(), link, nil); !errors.Is(err, ErrRelayNotHTTPS) {
		t.Errorf("got %v", err)
	}
	if len(e.v.Requests()) != 0 {
		t.Error("contacted the relay")
	}
}

// failingStore injects write failures into the real store.
type failingStore struct {
	store
	writes  int
	failAt  int   // the write (1-based: Create/CreateReplace, then Saves) that fails
	failErr error // returned after the write was done (ErrNotDurable) or instead of it
	after   bool  // perform the write before returning failErr
}

func (f *failingStore) do(op func() error) error {
	f.writes++
	if f.writes >= f.failAt && f.failAt > 0 {
		if f.after {
			if err := op(); err != nil {
				return err
			}
		}
		return f.failErr
	}
	return op()
}

func (f *failingStore) Create(p state.Protector, b []byte) error {
	return f.do(func() error { return f.store.Create(p, b) })
}
func (f *failingStore) CreateReplace(p state.Protector, b []byte, r state.Resolver) error {
	return f.do(func() error { return f.store.CreateReplace(p, b, r) })
}
func (f *failingStore) Save(b []byte) error { return f.do(func() error { return f.store.Save(b) }) }

func withFailingStore(t *testing.T, f *failingStore) {
	old := wrapStore
	wrapStore = func(s store) store { f.store = s; return f }
	t.Cleanup(func() { wrapStore = old })
}

// TestPairStartedNotDurable: a first save that is in place but not
// durable (also on its retry) wipes the file and stops.
func TestPairStartedNotDurable(t *testing.T) {
	e := newEnv(t)
	withFailingStore(t, &failingStore{failAt: 1, failErr: state.ErrNotDurable, after: true})
	err := e.pair(context.Background(), e.code(invite.KindAgent, time.Minute), nil)
	if !errors.Is(err, state.ErrNotDurable) {
		t.Fatalf("got %v", err)
	}
	wrapStore = func(s store) store { return s }
	if r, _ := e.record(); r != nil {
		t.Error("state kept")
	}
	if e.v.Inits() != 0 {
		t.Error("the handshake ran")
	}
}

// TestPairFinalSaveFails: device.paired arrived but the paired state
// cannot be saved: the waiting file is deleted (a resume would wait for
// an approval that already came) and the operator is told to unlink the
// agent.
func TestPairFinalSaveFails(t *testing.T) {
	e := newEnv(t)
	// Writes: 1 started (Create), 2 the hs.resp batch (Persist), 3
	// waiting (Save), 4 the device.paired batch (Persist, fails: the
	// batch stays unacknowledged), 5 paired (Save, fails).
	withFailingStore(t, &failingStore{failAt: 4, failErr: errors.New("disk full")})
	err := e.pair(context.Background(), e.code(invite.KindAgent, time.Minute), nil)
	if err == nil || !strings.Contains(err.Error(), "Unlink the agent on your phone") || !strings.Contains(err.Error(), "disk full") {
		t.Fatalf("got %v", err)
	}
	if strings.Contains(e.out.String(), TextPaired) {
		t.Error("said paired")
	}
	wrapStore = func(s store) store { return s }
	if r, _ := e.record(); r != nil {
		t.Errorf("state kept: %v", r.Phase)
	}
}

// phaseSpy records the phase of every record written, and whether the
// vault's mailbox still held unacknowledged messages at that moment.
type phaseSpy struct {
	store
	v      *pairtest.Vault
	mu     sync.Mutex
	writes []string
}

func (p *phaseSpy) note(b []byte) {
	r, err := DecodeRecord(b)
	if err != nil {
		return
	}
	p.mu.Lock()
	p.writes = append(p.writes, string(r.Phase)+":"+strconv.Itoa(p.v.Pending()))
	p.mu.Unlock()
}

func (p *phaseSpy) Create(pr state.Protector, b []byte) error {
	p.note(b)
	return p.store.Create(pr, b)
}
func (p *phaseSpy) Save(b []byte) error { p.note(b); return p.store.Save(b) }

// TestPairPairedSavedBeforeAck: device.paired is saved (as paired)
// while it is still unacknowledged at the relay, so a crash after the
// relay dropped it cannot lose the pairing (the client's Config.Persist).
func TestPairPairedSavedBeforeAck(t *testing.T) {
	e := newEnv(t)
	sp := &phaseSpy{v: e.v}
	old := wrapStore
	wrapStore = func(s store) store { sp.store = s; return sp }
	t.Cleanup(func() { wrapStore = old })
	if err := e.pair(context.Background(), e.code(invite.KindAgent, time.Minute), nil); err != nil {
		t.Fatal(err)
	}
	sp.mu.Lock()
	defer sp.mu.Unlock()
	found := false
	for _, w := range sp.writes {
		if strings.HasPrefix(w, "paired:") {
			found = true
			if w == "paired:0" {
				t.Errorf("paired saved after the acknowledgement: %v", sp.writes)
			}
			break
		}
	}
	if !found {
		t.Errorf("no paired write: %v", sp.writes)
	}
	if n := strings.Count(strings.Join(sp.writes, " "), "paired:"); n != 1 {
		t.Errorf("paired written %d times: %v", n, sp.writes)
	}
}

// TestRecordAccess: the access member round-trips on a paired record; a
// record without it (older, or right after pairing) reads as unknown;
// malformed or misplaced access is refused.
func TestRecordAccess(t *testing.T) {
	exp := time.Unix(1790856600, 0).UTC()
	for _, a := range []Access{
		{},
		{State: AccessNone},
		{State: AccessActive},
		{State: AccessActive, SessionID: "s1", ExpiresAt: exp},
	} {
		b, err := (&Record{Phase: PhasePaired, Device: json.RawMessage(`{}`), Access: a}).Encode()
		if err != nil {
			t.Fatalf("%+v: %v", a, err)
		}
		r, err := DecodeRecord(b)
		if err != nil || r.Access != a {
			t.Errorf("%+v: got %+v, %v (%s)", a, r.Access, err, b)
		}
	}
	old := `{"v":1,"phase":"paired","device":{}}`
	if r, err := DecodeRecord([]byte(old)); err != nil || r.Access.State != AccessUnknown {
		t.Errorf("old record: %+v %v", r, err)
	}
	for _, bad := range []string{
		`{"v":1,"phase":"paired","device":{},"access":{"state":""}}`,
		`{"v":1,"phase":"paired","device":{},"access":{"state":"maybe"}}`,
		`{"v":1,"phase":"paired","device":{},"access":{"state":"none","session_id":"x"}}`,
		`{"v":1,"phase":"paired","device":{},"access":{"state":"active","expires_at":"2026-10-01T12:00:00Z"}}`,
		`{"v":1,"phase":"paired","device":{},"access":{"state":"active","x":1}}`,
		`{"v":1,"phase":"waiting","deadline":"2026-10-01T12:00:00Z","device":{},"access":{"state":"none"}}`,
	} {
		if _, err := DecodeRecord([]byte(bad)); !errors.Is(err, ErrRecord) {
			t.Errorf("%s: %v", bad, err)
		}
	}
	if _, err := (&Record{Phase: PhaseWaiting, Deadline: exp, Device: json.RawMessage(`{}`), Access: Access{State: AccessNone}}).Encode(); err == nil {
		t.Error("encoded access on an unfinished pairing")
	}
}
