package vaultconn

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/vms/invite"

	"github.com/vettid/vettid-agent/internal/pairing"
	"github.com/vettid/vettid-agent/internal/pairing/pairtest"
	"github.com/vettid/vettid-agent/internal/state"
)

// testProtector wraps under a fixed key and records its wipes in out.
type testProtector struct {
	key   [32]byte
	mu    sync.Mutex
	wipes int
	out   *syncBuf
}

func (p *testProtector) Name() string { return "test-key" }
func (p *testProtector) Wrap(k []byte) ([]byte, error) {
	a, _ := chacha20poly1305.NewX(p.key[:])
	n := make([]byte, a.NonceSize())
	return a.Seal(n, n, k, nil), nil
}
func (p *testProtector) Unwrap(w []byte) ([]byte, error) {
	a, _ := chacha20poly1305.NewX(p.key[:])
	if len(w) < a.NonceSize() {
		return nil, errors.New("short")
	}
	return a.Open(nil, w[:a.NonceSize()], w[a.NonceSize():], nil)
}
func (p *testProtector) Wipe() error {
	p.mu.Lock()
	p.wipes++
	p.mu.Unlock()
	if p.out != nil {
		p.out.Write([]byte("[protector wiped]\n"))
	}
	return nil
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func TestMain(m *testing.M) {
	retryBase, retryMax, statusRetryMax = 20*time.Millisecond, 100*time.Millisecond, 100*time.Millisecond
	os.Exit(m.Run())
}

type env struct {
	log  *syncBuf
	t    *testing.T
	v    *pairtest.Vault
	dir  string
	prot *testProtector
	out  *syncBuf
}

// newPaired pairs a connector with a pairtest vault through
// internal/pairing and returns the environment.
func newPaired(t *testing.T) *env {
	t.Helper()
	v, err := pairtest.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(v.Close)
	e := &env{t: t, v: v, dir: filepath.Join(t.TempDir(), "state"), out: &syncBuf{}, log: &syncBuf{}}
	e.prot = &testProtector{key: [32]byte{9}, out: e.out}
	code, err := v.Code(invite.KindAgent, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	s, err := state.Open(e.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	err = pairing.Pair(context.Background(), pairing.Options{
		Store:     s,
		Resolve:   e.resolve,
		Protector: func() (state.Protector, string, error) { return e.prot, "", nil },
		Code:      func() (string, error) { return code, nil },
		Name:      "test agent",
		Out:       &bytes.Buffer{},
		HTTP:      v.HTTPClient(),
		PollWait:  10 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *env) resolve(string) state.Protector { return e.prot }

// opened is a Conn over the state directory, as `vettid-agent mcp`
// builds it.
type opened struct {
	store *state.Store
	conn  *Conn
	rec   *pairing.Record
	evs   chan Event
}

func (e *env) open(wrap func(Store) Store) *opened {
	e.t.Helper()
	s, err := state.Open(e.dir)
	if err != nil {
		e.t.Fatal(err)
	}
	raw, err := s.Load(e.resolve)
	if err != nil {
		s.Close()
		e.t.Fatal(err)
	}
	rec, err := pairing.DecodeRecord(raw)
	if err != nil {
		s.Close()
		e.t.Fatal(err)
	}
	var st Store = s
	if wrap != nil {
		st = wrap(s)
	}
	o := &opened{store: s, rec: rec, evs: make(chan Event, 100)}
	o.conn, err = New(Options{Store: st, Resolve: e.resolve, Record: rec, Out: e.out, HTTP: e.v.HTTPClient(),
		Log:      slog.New(slog.NewTextHandler(e.log, nil)),
		PollWait: 10 * time.Millisecond, OnEvent: func(ev Event) { o.evs <- ev }})
	if err != nil {
		s.Close()
		e.t.Fatal(err)
	}
	return o
}

// run starts Run; stop cancels it and returns its error; the store is
// closed (the lock released) as a process exit would.
func (o *opened) run() (stop func() error) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- o.conn.Run(ctx) }()
	var once sync.Once
	var err error
	return func() error {
		once.Do(func() {
			cancel()
			err = <-done
			o.store.Close()
		})
		return err
	}
}

// runUntilEnd runs until Run returns by itself (within 10 s).
func (o *opened) runUntilEnd(t *testing.T) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := o.conn.Run(ctx)
	o.store.Close()
	if errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("Run did not end")
	}
	return err
}

func eventually(t *testing.T, what string, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !f() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// saved returns the saved device state (nil if there is no state file).
func (e *env) saved() (*pairing.Record, *client.State) {
	e.t.Helper()
	s, err := state.Open(e.dir)
	if err != nil {
		e.t.Fatal(err)
	}
	defer s.Close()
	if ok, _ := s.Exists(); !ok {
		return nil, nil
	}
	raw, err := s.Load(e.resolve)
	if err != nil {
		e.t.Fatal(err)
	}
	rec, err := pairing.DecodeRecord(raw)
	if err != nil {
		e.t.Fatal(err)
	}
	var st client.State
	if err := json.Unmarshal(rec.Device, &st); err != nil {
		e.t.Fatal(err)
	}
	return rec, &st
}

// spyStore keeps a copy of the last record saved (the store's lock is
// held by the running Conn, so the file cannot be opened meanwhile).
type spyStore struct {
	Store
	mu   sync.Mutex
	last []byte
}

func (s *spyStore) Save(b []byte) error {
	err := s.Store.Save(b)
	if err == nil {
		s.mu.Lock()
		s.last = bytes.Clone(b)
		s.mu.Unlock()
	}
	return err
}

// state returns the device state of the last record saved, or nil.
func (s *spyStore) state(t *testing.T) *client.State {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.last == nil {
		return nil
	}
	rec, err := pairing.DecodeRecord(s.last)
	if err != nil {
		t.Fatal(err)
	}
	var st client.State
	if err := json.Unmarshal(rec.Device, &st); err != nil {
		t.Fatal(err)
	}
	return &st
}

func spy(sp *spyStore) func(Store) Store {
	return func(s Store) Store { sp.Store = s; return sp }
}

func count(xs []string, x string) int {
	n := 0
	for _, y := range xs {
		if y == x {
			n++
		}
	}
	return n
}

func nextEvent(t *testing.T, o *opened, typ string) Event {
	t.Helper()
	timeout := time.After(10 * time.Second)
	for {
		select {
		case ev := <-o.evs:
			if ev.Type == typ {
				return ev
			}
		case <-timeout:
			t.Fatalf("no %s event", typ)
		}
	}
}

func noEvent(t *testing.T, o *opened, typ string) {
	t.Helper()
	for {
		select {
		case ev := <-o.evs:
			if ev.Type == typ {
				t.Fatalf("%s dispatched again", typ)
			}
		default:
			return
		}
	}
}

// TestRunStatusAndRequests: Run sends vault.status at start; Requests
// from several goroutines each get their own response (dispatch by
// `re`); every collected message is acknowledged after the save.
func TestRunStatusAndRequests(t *testing.T) {
	e := newPaired(t)
	o := e.open(nil)
	stop := o.run()
	defer stop()
	eventually(t, "vault.status at start", func() bool { return count(e.v.Received(), "vault.status") >= 1 })
	var wg sync.WaitGroup
	errs := make(chan error, 3)
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			r, err := o.conn.Request(ctx, "vault.status", json.RawMessage(`{}`))
			if err == nil && (!r.OK || !strings.Contains(string(r.Body), pairtest.VaultID)) {
				err = errors.New("unexpected response")
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
	if _, err := e.v.SendEvent("test.ping", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	nextEvent(t, o, "test.ping")
	eventually(t, "the mailbox to drain", func() bool { return e.v.Pending() == 0 })
	if err := stop(); !errors.Is(err, context.Canceled) {
		t.Errorf("Run: %v", err)
	}
	if _, err := o.conn.Request(context.Background(), "vault.status", nil); !errors.Is(err, ErrStopped) {
		t.Errorf("Request after Run: %v", err)
	}
}

// TestCrashAfterSaveBeforeAck: a batch (a rekey, its hs.fin, an event)
// is saved but never acknowledged, as if the process died between the
// save and the acks. The next process replays it without harm: the
// messages are recognised as handled (not dispatched again), the rekey
// is complete, a repeated hs.resp from the saved outbox is ignored by
// the vault, and the new epoch works.
func TestCrashAfterSaveBeforeAck(t *testing.T) {
	e := newPaired(t)
	e.v.FailAcks = true
	if _, err := e.v.SendEvent("test.before", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := e.v.Rekey(); err != nil {
		t.Fatal(err)
	}
	sp := &spyStore{}
	o := e.open(spy(sp))
	stop := o.run()
	nextEvent(t, o, "test.before")
	eventually(t, "the rekey to complete at the vault", e.v.RekeyDone)
	eventually(t, "the device to save the new epoch", func() bool {
		st := sp.state(t)
		return st != nil && len(st.Awaiting) == 0 && e.v.Pending() >= 3
	})
	stop() // the crash: nothing was acknowledged
	if e.v.Pending() < 3 {
		t.Fatalf("%d messages pending; the test needs the unacknowledged batch", e.v.Pending())
	}

	e.v.FailAcks = false
	o2 := e.open(nil)
	stop2 := o2.run()
	defer stop2()
	eventually(t, "the replayed batch to be acknowledged", func() bool { return e.v.Pending() == 0 })
	if _, err := e.v.SendEvent("test.after", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	nextEvent(t, o2, "test.after") // sealed in the new epoch
	noEvent(t, o2, "test.before")
	if n := e.v.RekeyResps(); n < 1 {
		t.Errorf("%d hs.resp", n)
	}
}

// failingStore fails every Save while fail is set.
type failingStore struct {
	Store
	mu    sync.Mutex
	fail  bool
	fails int
}

func (f *failingStore) Save(b []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		f.fails++
		return errors.New("disk full")
	}
	return f.Store.Save(b)
}

func (f *failingStore) failures() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.fails
}

// TestCrashBeforeSaveKeepsRekey: the save of the batch carrying the
// vault's rekey fails and the process dies. Nothing of the batch was
// acknowledged and the hs.resp never left (it waits in the unsaved
// outbox), so the next process collects the rekey again, answers it,
// and the new epoch works.
func TestCrashBeforeSaveKeepsRekey(t *testing.T) {
	e := newPaired(t)
	if err := e.v.Rekey(); err != nil {
		t.Fatal(err)
	}
	fs := &failingStore{fail: true}
	o := e.open(func(s Store) Store { fs.Store = s; return fs })
	stop := o.run()
	eventually(t, "a failed save", func() bool { return fs.failures() >= 1 })
	stop() // the crash
	if n := e.v.RekeyResps(); n != 0 {
		t.Fatalf("an hs.resp left before its batch was saved (%d)", n)
	}
	if e.v.Pending() == 0 {
		t.Fatal("the rekey was acknowledged without being saved")
	}
	if _, st := e.saved(); len(st.Awaiting) != 0 {
		t.Fatal("the failed save reached the file")
	}

	o2 := e.open(nil)
	stop2 := o2.run()
	defer stop2()
	eventually(t, "the rekey to complete", e.v.RekeyDone)
	if _, err := e.v.SendEvent("test.after", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	nextEvent(t, o2, "test.after")
	eventually(t, "the mailbox to drain", func() bool { return e.v.Pending() == 0 })
}

// TestSaveFailureBounded: while saves keep failing, the batch stays
// unacknowledged and is retried with a growing pause; no vault.status is
// sent beyond the one at start (each would add a response to the
// unacknowledged mailbox), and only the first failure and the recovery
// are logged. Once saving works the batch is acknowledged.
func TestSaveFailureBounded(t *testing.T) {
	e := newPaired(t)
	fs := &failingStore{}
	o := e.open(func(s Store) Store { fs.Store = s; return fs })
	stop := o.run()
	defer stop()
	eventually(t, "vault.status at start", func() bool { return count(e.v.Received(), "vault.status") == 1 })
	eventually(t, "the status response to be saved", func() bool { return e.v.Pending() == 0 })
	fs.mu.Lock()
	fs.fail = true
	fs.mu.Unlock()
	if _, err := e.v.SendEvent("test.ping", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	eventually(t, "several failed saves", func() bool { return fs.failures() >= 4 })
	time.Sleep(300 * time.Millisecond)
	if n := count(e.v.Received(), "vault.status"); n != 1 {
		t.Errorf("%d vault.status during the failure, want only the one at start", n)
	}
	if e.v.Pending() == 0 {
		t.Error("acknowledged without a save")
	}
	fs.mu.Lock()
	fs.fail = false
	fs.mu.Unlock()
	eventually(t, "the batch to be acknowledged", func() bool { return e.v.Pending() == 0 })
	nextEvent(t, o, "test.ping")
	noEvent(t, o, "test.ping") // delivered once although collected several times
	logs := e.log.String()
	if n := strings.Count(logs, "state not saved"); n != 1 {
		t.Errorf("failure logged %d times:\n%s", n, logs)
	}
	if n := strings.Count(logs, "state saved again"); n != 1 {
		t.Errorf("recovery logged %d times:\n%s", n, logs)
	}
	if b := backoff(time.Second, 30*time.Second, 1); b != time.Second {
		t.Errorf("backoff 1: %v", b)
	}
	if b := backoff(time.Second, 30*time.Second, 10); b != 30*time.Second {
		t.Errorf("backoff 10: %v", b)
	}
}

// TestStatusRetriedAtStart: a vault.status at start that cannot be sent
// is retried after a short pause, not after StatusEvery.
func TestStatusRetriedAtStart(t *testing.T) {
	e := newPaired(t)
	e.v.DepositError = &pairtest.RelayError{Status: 400, Code: "bad_request"}
	o := e.open(nil)
	stop := o.run()
	defer stop()
	time.Sleep(150 * time.Millisecond)
	if n := count(e.v.Received(), "vault.status"); n != 0 {
		t.Fatalf("%d vault.status got through", n)
	}
	e.v.SetDepositError(nil)
	eventually(t, "vault.status after the retry", func() bool { return count(e.v.Received(), "vault.status") == 1 })
}

// wipeFailStore fails Wipe while fail is set.
type wipeFailStore struct {
	Store
	fail bool
}

func (w *wipeFailStore) Wipe(r state.Resolver) error {
	if w.fail {
		return errors.New("read-only file system")
	}
	return w.Store.Wipe(r)
}

// TestUnlinkedWipeFails: the wipe fails: Run returns once with advice
// that is accurate for this build, the batch stays unacknowledged and
// the state file stays; the next process collects device.unlinked again
// and wipes.
func TestUnlinkedWipeFails(t *testing.T) {
	e := newPaired(t)
	if _, err := e.v.SendEvent("device.unlinked", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	o := e.open(func(s Store) Store { return &wipeFailStore{Store: s, fail: true} })
	err := o.runUntilEnd(t)
	var wf *wipeFailed
	if !errors.As(err, &wf) || errors.Is(err, ErrUnlinked) {
		t.Fatalf("Run: %v", err)
	}
	if !strings.Contains(err.Error(), "Run `vettid-agent mcp` again to retry, or delete the state directory") {
		t.Errorf("advice: %v", err)
	}
	if strings.Contains(e.out.String(), TextUnlinked) {
		t.Error("said the keys were deleted")
	}
	if e.v.Pending() == 0 {
		t.Fatal("device.unlinked was acknowledged although the wipe failed")
	}
	if rec, _ := e.saved(); rec == nil {
		t.Fatal("the state file is gone although the wipe failed")
	}
	o2 := e.open(nil)
	if err := o2.runUntilEnd(t); !errors.Is(err, ErrUnlinked) {
		t.Fatalf("second run: %v", err)
	}
	if rec, _ := e.saved(); rec != nil {
		t.Fatal("not wiped on the second run")
	}
}

// TestRefusedDrainBounded: refused, and the saves keep failing, so the
// same batch comes back on every collect: the drain still ends after a
// bounded number of collects with the refused text.
func TestRefusedDrainBounded(t *testing.T) {
	e := newPaired(t)
	e.v.DepositError = &pairtest.RelayError{Status: 403, Code: "token_revoked"}
	if _, err := e.v.SendEvent("test.ping", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	fs := &failingStore{fail: true}
	o := e.open(func(s Store) Store { fs.Store = s; return fs })
	if err := o.runUntilEnd(t); !errors.Is(err, ErrRefused) {
		t.Fatalf("Run: %v", err)
	}
	if n := fs.failures(); n < 1 || n > drainMaxCollect {
		t.Errorf("%d collects with a failed save", n)
	}
	if !strings.Contains(e.out.String(), TextRefused) {
		t.Error("no refused text")
	}
}

// TestUnlinkedWipes: device.unlinked wipes the state file and the
// protector's key before the operator is told; Run ends with
// ErrUnlinked.
func TestUnlinkedWipes(t *testing.T) {
	e := newPaired(t)
	if _, err := e.v.SendEvent("device.unlinked", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	o := e.open(nil)
	if err := o.runUntilEnd(t); !errors.Is(err, ErrUnlinked) {
		t.Fatalf("Run: %v", err)
	}
	if rec, _ := e.saved(); rec != nil {
		t.Fatal("the state file is still there")
	}
	out := e.out.String()
	w, u := strings.Index(out, "[protector wiped]"), strings.Index(out, TextUnlinked)
	if w < 0 || u < 0 || w > u {
		t.Errorf("wipe and notice out of order:\n%s", out)
	}
	if e.v.Pending() != 0 {
		t.Error("device.unlinked was not acknowledged")
	}
}

// TestTokenRevokedStops: the relay answers the agent's deposits
// token_revoked and no device.unlinked comes: Run stops with the AG12
// text and nothing is wiped.
func TestTokenRevokedStops(t *testing.T) {
	e := newPaired(t)
	e.v.DepositError = &pairtest.RelayError{Status: 403, Code: "token_revoked"}
	o := e.open(nil)
	if err := o.runUntilEnd(t); !errors.Is(err, ErrRefused) {
		t.Fatalf("Run: %v", err)
	}
	if !strings.Contains(e.out.String(), TextRefused) {
		t.Errorf("output:\n%s", e.out)
	}
	if strings.Contains(e.out.String(), "[protector wiped]") {
		t.Error("the protector was wiped")
	}
	rec, st := e.saved()
	if rec == nil || rec.Phase != pairing.PhasePaired || st.DeviceID != pairtest.DeviceID {
		t.Fatal("the state was changed")
	}
}

// TestTokenRevokedThenUnlinked: refused, but device.unlinked waits in
// the mailbox: the connector keeps collecting, finds it and wipes.
func TestTokenRevokedThenUnlinked(t *testing.T) {
	e := newPaired(t)
	e.v.DepositError = &pairtest.RelayError{Status: 403, Code: "token_revoked"}
	if _, err := e.v.SendEvent("device.unlinked", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	o := e.open(nil)
	if err := o.runUntilEnd(t); !errors.Is(err, ErrUnlinked) {
		t.Fatalf("Run: %v", err)
	}
	if rec, _ := e.saved(); rec != nil {
		t.Fatal("not wiped")
	}
}

// TestRequestRefused: a Request whose deposit is refused token_revoked
// gets ErrRefused.
func TestRequestRefused(t *testing.T) {
	e := newPaired(t)
	o := e.open(nil)
	stop := o.run()
	defer stop()
	eventually(t, "vault.status at start", func() bool { return count(e.v.Received(), "vault.status") >= 1 })
	e.v.SetDepositError(&pairtest.RelayError{Status: 403, Code: "token_revoked"})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := o.conn.Request(ctx, "vault.status", json.RawMessage(`{}`)); !errors.Is(err, ErrRefused) {
		t.Errorf("got %v", err)
	}
}

// TestIdentityRotationSaved: identity.rotate is followed and the vault's
// new ik is saved with the batch.
func TestIdentityRotationSaved(t *testing.T) {
	e := newPaired(t)
	nik, err := e.v.Rotate()
	if err != nil {
		t.Fatal(err)
	}
	sp := &spyStore{}
	o := e.open(spy(sp))
	stop := o.run()
	defer stop()
	eventually(t, "the new ik to be saved", func() bool {
		st := sp.state(t)
		return st != nil && ed25519.PublicKey(st.Vault.IK).Equal(nik)
	})
}

// TestTokenRefreshAnswered: the vault's relay.token.refresh request is
// answered with a new standing token, deposited from the saved outbox
// after the batch was saved.
func TestTokenRefreshAnswered(t *testing.T) {
	e := newPaired(t)
	if _, err := e.v.SendEvent("relay.token.refresh", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	sp := &spyStore{}
	o := e.open(spy(sp))
	stop := o.run()
	defer stop()
	eventually(t, "the refresh answer", func() bool { return count(e.v.Received(), "relay.token.refresh") == 1 })
	st := sp.state(t)
	if st.IssuedExp.Before(time.Now().Add(29 * 24 * time.Hour)) {
		t.Errorf("issued token expiry %v not saved", st.IssuedExp)
	}
}

func TestNewRefusesUnpaired(t *testing.T) {
	for _, rec := range []*pairing.Record{nil,
		{Phase: pairing.PhaseWaiting, Deadline: time.Now(), Device: json.RawMessage(`{}`)},
		{Phase: pairing.PhasePaired, Device: json.RawMessage(`{"role":"agent"}`)}} {
		if _, err := New(Options{Record: rec}); !errors.Is(err, ErrNotPaired) {
			t.Errorf("%v: got %v", rec, err)
		}
	}
}

func TestErrCode(t *testing.T) {
	if got := sanitizeCode("tok\x1b[2J\nen_revoked"); got != "tok2Jen_revoked" {
		t.Errorf("got %q", got)
	}
	if got := errCode(errors.New("Get https://relay/v1/claim/secret: EOF")); got != "transport error" {
		t.Errorf("got %q", got)
	}
}

// accessSpy notes the access saved with each record and how many
// messages were still unacknowledged at that moment.
type accessSpy struct {
	Store
	v     *pairtest.Vault
	mu    sync.Mutex
	saves []string
}

func (a *accessSpy) Save(b []byte) error {
	if r, err := pairing.DecodeRecord(b); err == nil {
		a.mu.Lock()
		a.saves = append(a.saves, fmt.Sprintf("%s/%s/%d", r.Access.State, r.Access.SessionID, a.v.Pending()))
		a.mu.Unlock()
	}
	return a.Store.Save(b)
}

func (a *accessSpy) has(prefix string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, s := range a.saves {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}
	return false
}

func (a *accessSpy) first(prefix string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, s := range a.saves {
		if strings.HasPrefix(s, prefix) {
			return s
		}
	}
	return ""
}

func granted(id string, exp time.Time) []byte {
	return []byte(`{"session_id":"` + id + `","expires_at":"` + exp.UTC().Format(time.RFC3339) + `"}`)
}

// TestAccessSavedWithBatch: device.session.granted is applied to the
// access session and saved in the save of its batch, while it is still
// unacknowledged; device.session.ended makes it none the same way.
func TestAccessSavedWithBatch(t *testing.T) {
	e := newPaired(t)
	exp := time.Now().Add(time.Hour).Truncate(time.Second)
	if _, err := e.v.SendEvent("device.session.granted", granted("sess-1", exp)); err != nil {
		t.Fatal(err)
	}
	sp := &accessSpy{v: e.v}
	o := e.open(func(s Store) Store { sp.Store = s; return sp })
	if a := o.conn.Access(); a.State != pairing.AccessUnknown {
		t.Fatalf("after pairing without a first session time: %+v", a)
	}
	stop := o.run()
	nextEvent(t, o, "device.session.granted")
	eventually(t, "the grant saved", func() bool { return sp.has("active/sess-1/") })
	if first := sp.first("active/sess-1/"); strings.HasSuffix(first, "/0") {
		t.Errorf("the grant was first saved with nothing unacknowledged (%s)", first)
	}
	if a := o.conn.Access(); a.SessionID != "sess-1" || !a.ExpiresAt.Equal(exp) {
		t.Errorf("access %+v", a)
	}
	if _, err := e.v.SendEvent("device.session.ended", []byte(`{"reason":"ended"}`)); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the end saved", func() bool { return sp.has("none//") })
	stop()
	if rec, _ := e.saved(); rec.Access.State != pairing.AccessNone {
		t.Errorf("file: %+v", rec.Access)
	}
}

// TestAccessReplayAfterCrash: the grant's batch is saved but never
// acknowledged (a crash before the acks); the next process starts with
// the saved session, and the replayed batch changes nothing.
func TestAccessReplayAfterCrash(t *testing.T) {
	e := newPaired(t)
	exp := time.Now().Add(time.Hour).Truncate(time.Second)
	e.v.FailAcks = true
	if _, err := e.v.SendEvent("device.session.granted", granted("sess-2", exp)); err != nil {
		t.Fatal(err)
	}
	sp := &accessSpy{v: e.v}
	o := e.open(func(s Store) Store { sp.Store = s; return sp })
	stop := o.run()
	eventually(t, "the grant saved", func() bool { return sp.has("active/sess-2/") })
	stop()
	e.v.FailAcks = false
	o2 := e.open(nil)
	if a := o2.conn.Access(); a.SessionID != "sess-2" || !a.ExpiresAt.Equal(exp) {
		t.Fatalf("restart: %+v", a)
	}
	stop2 := o2.run()
	defer stop2()
	eventually(t, "the replay acknowledged", func() bool { return e.v.Pending() == 0 })
	if a := o2.conn.Access(); a.SessionID != "sess-2" {
		t.Errorf("after replay: %+v", a)
	}
}

// TestAccessCrashBeforeSave: the grant's save fails and the process
// dies: the next process collects the grant again and saves it.
func TestAccessCrashBeforeSave(t *testing.T) {
	e := newPaired(t)
	if _, err := e.v.SendEvent("device.session.granted", granted("sess-3", time.Now().Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	fs := &failingStore{fail: true}
	o := e.open(func(s Store) Store { fs.Store = s; return fs })
	stop := o.run()
	eventually(t, "a failed save", func() bool { return fs.failures() >= 1 })
	stop()
	if rec, _ := e.saved(); rec.Access.State != pairing.AccessUnknown {
		t.Fatal("the failed save reached the file")
	}
	sp := &accessSpy{v: e.v}
	o2 := e.open(func(s Store) Store { sp.Store = s; return sp })
	stop2 := o2.run()
	defer stop2()
	eventually(t, "the grant saved on the second run", func() bool { return sp.has("active/sess-3/") })
}

// TestCompareAndSetAccessSaved: what internal/access learns from a
// probe is saved with the next batch.
func TestCompareAndSetAccessSaved(t *testing.T) {
	e := newPaired(t)
	sp := &accessSpy{v: e.v}
	o := e.open(func(s Store) Store { sp.Store = s; return sp })
	cur := o.conn.Access() // unknown: paired without a first session time
	probed := pairing.Access{State: pairing.AccessActive}
	if o.conn.CompareAndSetAccess(pairing.Access{State: pairing.AccessActive, SessionID: "x"}, probed) {
		t.Fatal("set although the session was not the one compared")
	}
	if o.conn.CompareAndSetAccess(cur, pairing.Access{State: "bogus"}) {
		t.Fatal("set an invalid value")
	}
	if !o.conn.CompareAndSetAccess(cur, probed) {
		t.Fatal("not set")
	}
	stop := o.run()
	defer stop()
	eventually(t, "saved", func() bool { return sp.has("active//") })
}

func TestParseGranted(t *testing.T) {
	if a, ok := ParseGranted(granted("x", time.Unix(1790856600, 0))); !ok || a.SessionID != "x" || a.ExpiresAt.Unix() != 1790856600 {
		t.Errorf("%+v %v", a, ok)
	}
	for _, b := range []string{`{}`, `{"session_id":"x"}`, `{"session_id":"","expires_at":"2026-10-01T12:00:00Z"}`, `{"session_id":"x","expires_at":"soon"}`, `[]`} {
		if _, ok := ParseGranted(json.RawMessage(b)); ok {
			t.Errorf("%s accepted", b)
		}
	}
}

// TestOnStatus: each vault.status's owner check reaches OnStatus.
func TestOnStatus(t *testing.T) {
	e := newPaired(t)
	got := make(chan string, 4)
	s, err := state.Open(e.dir)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := s.Load(e.resolve)
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := pairing.DecodeRecord(raw)
	c, err := New(Options{Store: s, Resolve: e.resolve, Record: rec, HTTP: e.v.HTTPClient(), PollWait: 10 * time.Millisecond,
		OnStatus: func(oc string) { got <- oc }})
	if err != nil {
		t.Fatal(err)
	}
	o := &opened{store: s, conn: c, rec: rec}
	stop := o.run()
	defer stop()
	select {
	case oc := <-got:
		if oc != "ok" {
			t.Errorf("owner check %q", oc)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no OnStatus")
	}
}

// TestGrantedThenEndedOneBatch: a grant and the end of that session in
// one batch save none, and the grant is never saved on its own.
func TestGrantedThenEndedOneBatch(t *testing.T) {
	e := newPaired(t)
	if _, err := e.v.SendEvent("device.session.granted", granted("sess-4", time.Now().Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	if _, err := e.v.SendEvent("device.session.ended", []byte(`{"reason":"ended"}`)); err != nil {
		t.Fatal(err)
	}
	sp := &accessSpy{v: e.v}
	o := e.open(func(s Store) Store { sp.Store = s; return sp })
	stop := o.run()
	nextEvent(t, o, "device.session.ended")
	eventually(t, "the batch acknowledged", func() bool { return e.v.Pending() == 0 })
	stop()
	if sp.has("active/sess-4/") {
		t.Errorf("the grant was saved on its own: %v", sp.saves)
	}
	if rec, _ := e.saved(); rec.Access.State != pairing.AccessNone {
		t.Errorf("saved %+v", rec.Access)
	}
}
