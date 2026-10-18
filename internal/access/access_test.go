package access

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/vettid/vettid-agent/internal/pairing"
	"github.com/vettid/vettid-agent/internal/vaultconn"
)

// fakeConn answers requests from a table and records them.
type fakeConn struct {
	mu      sync.Mutex
	access  pairing.Access
	answers map[string]func() (*vaultconn.Response, error)
	sent    []string
	block   chan struct{} // if set, Request waits on it
}

func (f *fakeConn) Request(ctx context.Context, typ string, body json.RawMessage) (*vaultconn.Response, error) {
	f.mu.Lock()
	f.sent = append(f.sent, typ)
	ans := f.answers[typ]
	block := f.block
	f.mu.Unlock()
	if block != nil {
		<-block
	}
	if ans == nil {
		return nil, errors.New("no answer")
	}
	return ans()
}

func (f *fakeConn) Access() pairing.Access {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.access
}

func (f *fakeConn) SetAccess(a pairing.Access) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.access = a
}

func (f *fakeConn) CompareAndSetAccess(old, a pairing.Access) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.access != old {
		return false
	}
	f.access = a
	return true
}

func (f *fakeConn) count(typ string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, s := range f.sent {
		if s == typ {
			n++
		}
	}
	return n
}

func (f *fakeConn) answer(typ string, fn func() (*vaultconn.Response, error)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.answers[typ] = fn
}

func ok(body string) func() (*vaultconn.Response, error) {
	return func() (*vaultconn.Response, error) {
		return &vaultconn.Response{OK: true, Body: json.RawMessage(body)}, nil
	}
}

func fail(code, body string) func() (*vaultconn.Response, error) {
	return func() (*vaultconn.Response, error) {
		return &vaultconn.Response{ErrorCode: code, Body: json.RawMessage(body)}, nil
	}
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

var t0 = time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)

// setup: no session; device.session.request answers with exp in 10
// minutes of the current clock.
func setup(a pairing.Access) (*fakeConn, *clock, *Manager) {
	c := &clock{t: t0}
	f := &fakeConn{access: a, answers: map[string]func() (*vaultconn.Response, error){}}
	f.answer("device.session.request", func() (*vaultconn.Response, error) {
		return &vaultconn.Response{OK: true, Body: json.RawMessage(`{"request_id":"r1","exp":"` + c.now().Add(10*time.Minute).Format(time.RFC3339) + `"}`)}, nil
	})
	return f, c, New(f, 0, c.now)
}

var none = pairing.Access{State: pairing.AccessNone}

func ensure(t *testing.T, m *Manager) error {
	t.Helper()
	return m.Ensure(context.Background())
}

func TestActiveSessionNoRequest(t *testing.T) {
	f, _, m := setup(pairing.Access{State: pairing.AccessActive, SessionID: "s", ExpiresAt: t0.Add(time.Hour)})
	if err := ensure(t, m); err != nil {
		t.Fatal(err)
	}
	f2, _, m2 := setup(pairing.Access{State: pairing.AccessActive}) // unknown expiry
	if err := ensure(t, m2); err != nil {
		t.Fatal(err)
	}
	if f.count("device.session.request")+f2.count("device.session.request") != 0 {
		t.Error("requested while a session exists")
	}
}

// TestOneOutstanding: a request is sent on the first Ensure without a
// session (expired here); while it is outstanding no other is sent.
func TestOneOutstanding(t *testing.T) {
	f, c, m := setup(pairing.Access{State: pairing.AccessActive, SessionID: "s", ExpiresAt: t0.Add(-time.Second)})
	if err := ensure(t, m); !errors.Is(err, ErrAccessRequested) {
		t.Fatalf("got %v", err)
	}
	for i := 0; i < 5; i++ {
		c.add(time.Minute)
		if err := ensure(t, m); !errors.Is(err, ErrAccessRequested) {
			t.Fatalf("got %v", err)
		}
	}
	if n := f.count("device.session.request"); n != 1 {
		t.Fatalf("%d requests, want 1", n)
	}
	// Granted: the session is used, nothing more is sent.
	f.SetAccess(pairing.Access{State: pairing.AccessActive, SessionID: "s2", ExpiresAt: c.now().Add(time.Hour)})
	m.OnEvent(vaultconn.Event{Type: "device.session.granted"})
	if err := ensure(t, m); err != nil || f.count("device.session.request") != 1 {
		t.Fatalf("after grant: %v", err)
	}
}

// TestOneOutstandingConcurrent: concurrent Ensures send one request.
func TestOneOutstandingConcurrent(t *testing.T) {
	f, _, m := setup(none)
	f.block = make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = m.Ensure(context.Background()) }()
	}
	time.Sleep(50 * time.Millisecond)
	close(f.block)
	wg.Wait()
	if n := f.count("device.session.request"); n != 1 {
		t.Fatalf("%d requests, want 1", n)
	}
}

// TestQuietAfterDenial: after a denial no automatic request for 10
// minutes (ErrAccessDenied with Until); then one is sent.
func TestQuietAfterDenial(t *testing.T) {
	f, c, m := setup(none)
	_ = ensure(t, m)
	c.add(2 * time.Minute)
	m.OnEvent(vaultconn.Event{Type: "device.session.ended", Body: json.RawMessage(`{"reason":"denied"}`)})
	deniedAt := c.now()
	for _, d := range []time.Duration{0, 5 * time.Minute, 10*time.Minute - time.Second} {
		c.t = deniedAt.Add(d)
		err := ensure(t, m)
		var e *Error
		if !errors.As(err, &e) || !errors.Is(err, ErrAccessDenied) || !e.Until.Equal(deniedAt.Add(10*time.Minute)) {
			t.Fatalf("at +%v: %v", d, err)
		}
	}
	if n := f.count("device.session.request"); n != 1 {
		t.Fatalf("%d requests during the quiet period", n)
	}
	c.t = deniedAt.Add(10 * time.Minute)
	if err := ensure(t, m); !errors.Is(err, ErrAccessRequested) || f.count("device.session.request") != 2 {
		t.Fatalf("after the quiet period: %v", err)
	}
}

// TestQuietAfterUnanswered: a request that expires unanswered starts a
// 10-minute quiet period from its expiry.
func TestQuietAfterUnanswered(t *testing.T) {
	f, c, m := setup(none)
	_ = ensure(t, m) // exp = t0+10m
	c.t = t0.Add(10 * time.Minute)
	err := ensure(t, m)
	var e *Error
	if !errors.As(err, &e) || !errors.Is(err, ErrAccessRequested) || !e.Until.Equal(t0.Add(20*time.Minute)) {
		t.Fatalf("got %v", err)
	}
	c.t = t0.Add(20*time.Minute - time.Second)
	_ = ensure(t, m)
	if f.count("device.session.request") != 1 {
		t.Fatal("sent during the quiet period")
	}
	c.t = t0.Add(20 * time.Minute)
	_ = ensure(t, m)
	if f.count("device.session.request") != 2 {
		t.Fatal("not sent after the quiet period")
	}
}

// TestSixAnHour: at most 6 automatic requests in any hour.
func TestSixAnHour(t *testing.T) {
	f, c, m := setup(none)
	for i := 0; i < 6; i++ {
		if err := ensure(t, m); !errors.Is(err, ErrAccessRequested) {
			t.Fatalf("request %d: %v", i+1, err)
		}
		// Granted for one minute, then expired.
		f.SetAccess(pairing.Access{State: pairing.AccessActive, SessionID: "s", ExpiresAt: c.now().Add(time.Minute)})
		m.OnEvent(vaultconn.Event{Type: "device.session.granted"})
		c.add(2 * time.Minute)
	}
	if n := f.count("device.session.request"); n != 6 {
		t.Fatalf("%d requests", n)
	}
	err := ensure(t, m)
	var e *Error
	if !errors.As(err, &e) || !e.Until.Equal(t0.Add(time.Hour)) {
		t.Fatalf("7th: %v", err)
	}
	c.t = t0.Add(time.Hour - time.Second)
	_ = ensure(t, m)
	if f.count("device.session.request") != 6 {
		t.Fatal("7th sent within the hour")
	}
	c.t = t0.Add(time.Hour)
	_ = ensure(t, m)
	if f.count("device.session.request") != 7 {
		t.Fatal("not sent once the first left the hour")
	}
}

// TestTooSoon: the vault's too_soon is waited out until allowed_after;
// never retried sooner.
func TestTooSoon(t *testing.T) {
	f, c, m := setup(none)
	after := t0.Add(7 * time.Minute)
	f.answer("device.session.request", fail("too_soon", `{"allowed_after":"`+after.Format(time.RFC3339)+`"}`))
	err := ensure(t, m)
	var e *Error
	if !errors.As(err, &e) || !e.Until.Equal(after) {
		t.Fatalf("got %v", err)
	}
	for _, d := range []time.Duration{time.Minute, 7*time.Minute - time.Second} {
		c.t = t0.Add(d)
		_ = ensure(t, m)
	}
	if n := f.count("device.session.request"); n != 1 {
		t.Fatalf("%d requests before allowed_after", n)
	}
	f.answer("device.session.request", ok(`{"request_id":"r2","exp":"`+t0.Add(20*time.Minute).Format(time.RFC3339)+`"}`))
	c.t = after
	if err := ensure(t, m); !errors.Is(err, ErrAccessRequested) || f.count("device.session.request") != 2 {
		t.Fatalf("at allowed_after: %v", err)
	}

	// Without a readable allowed_after: the whole 10 minutes.
	f2, c2, m2 := setup(none)
	f2.answer("device.session.request", fail("too_soon", `{}`))
	_ = ensure(t, m2)
	c2.t = t0.Add(10*time.Minute - time.Second)
	_ = ensure(t, m2)
	if f2.count("device.session.request") != 1 {
		t.Fatal("retried before 10 minutes")
	}
}

// TestOwnerCheck: owner_check_required stops requests until a
// vault.status says the hold ended, or a grant update arrives.
func TestOwnerCheck(t *testing.T) {
	f, _, m := setup(none)
	f.answer("device.session.request", fail("owner_check_required", `{}`))
	if err := ensure(t, m); !errors.Is(err, ErrOwnerCheck) {
		t.Fatalf("got %v", err)
	}
	f.answer("device.session.request", ok(`{"request_id":"r","exp":"`+t0.Add(10*time.Minute).Format(time.RFC3339)+`"}`))
	if err := ensure(t, m); !errors.Is(err, ErrOwnerCheck) || f.count("device.session.request") != 1 {
		t.Fatalf("while held: %v", err)
	}
	m.OnStatus("held")
	if err := ensure(t, m); !errors.Is(err, ErrOwnerCheck) {
		t.Fatal("status held")
	}
	m.OnStatus("ok")
	if err := ensure(t, m); !errors.Is(err, ErrAccessRequested) {
		t.Fatalf("after the hold: %v", err)
	}
	m.OnAnswer("owner_check_required", m.Snapshot())
	if err := ensure(t, m); !errors.Is(err, ErrOwnerCheck) {
		t.Fatal("answer owner_check_required")
	}
	m.OnEvent(vaultconn.Event{Type: "leash.grant.updated"})
	if err := ensure(t, m); errors.Is(err, ErrOwnerCheck) {
		t.Fatal("grant update did not end the hold")
	}
}

// TestUnknownProbed: after pairing the session is unknown; the first
// Ensure checks it with leash.grant.list before any request.
func TestUnknownProbed(t *testing.T) {
	// A session exists (granted at pairing): used with unknown expiry.
	f, _, m := setup(pairing.Access{})
	f.answer("leash.grant.list", ok(`{"grants":[],"suspended":false}`))
	if err := ensure(t, m); err != nil {
		t.Fatal(err)
	}
	if a := f.Access(); a.State != pairing.AccessActive || !a.ExpiresAt.IsZero() {
		t.Errorf("access %+v", a)
	}
	if f.count("device.session.request") != 0 {
		t.Error("requested")
	}
	// Until the vault answers session_required.
	m.OnAnswer("session_required", m.Snapshot())
	if f.Access().State != pairing.AccessNone {
		t.Error("session_required did not end it")
	}
	if err := ensure(t, m); !errors.Is(err, ErrAccessRequested) || f.count("device.session.request") != 1 {
		t.Errorf("after session_required: %v", err)
	}

	// No session: the probe says so, then the request is sent.
	f2, _, m2 := setup(pairing.Access{})
	f2.answer("leash.grant.list", fail("session_required", `{}`))
	if err := ensure(t, m2); !errors.Is(err, ErrAccessRequested) {
		t.Fatalf("got %v", err)
	}
	if f2.count("leash.grant.list") != 1 || f2.count("device.session.request") != 1 || f2.Access().State != pairing.AccessNone {
		t.Error("probe then request")
	}

	// Held: no request.
	f3, _, m3 := setup(pairing.Access{})
	f3.answer("leash.grant.list", fail("owner_check_required", `{}`))
	if err := ensure(t, m3); !errors.Is(err, ErrOwnerCheck) || f3.count("device.session.request") != 0 {
		t.Errorf("held: %v", err)
	}
	// Unreachable: no request, unknown kept.
	f4, _, m4 := setup(pairing.Access{})
	if err := ensure(t, m4); !errors.Is(err, ErrUnreachable) || f4.count("device.session.request") != 0 || f4.Access().State != pairing.AccessUnknown {
		t.Errorf("unreachable: %v", err)
	}
}

// TestStart: a saved session that has not expired is checked at start
// with one leash.grant.list; session_required makes it none. An expired
// or absent saved session is not checked.
func TestStart(t *testing.T) {
	f, _, m := setup(pairing.Access{State: pairing.AccessActive, SessionID: "s", ExpiresAt: t0.Add(time.Hour)})
	f.answer("leash.grant.list", fail("session_required", `{}`))
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.count("leash.grant.list") != 1 || f.Access().State != pairing.AccessNone {
		t.Errorf("ended session: %+v", f.Access())
	}

	saved := pairing.Access{State: pairing.AccessActive, SessionID: "s", ExpiresAt: t0.Add(time.Hour)}
	f2, _, m2 := setup(saved)
	f2.answer("leash.grant.list", ok(`{}`))
	if err := m2.Start(context.Background()); err != nil || f2.Access() != saved {
		t.Errorf("live session changed: %v %+v", err, f2.Access())
	}

	for _, a := range []pairing.Access{none, {}, {State: pairing.AccessActive, SessionID: "s", ExpiresAt: t0.Add(-time.Minute)}} {
		f3, _, m3 := setup(a)
		if err := m3.Start(context.Background()); err != nil || f3.count("leash.grant.list") != 0 {
			t.Errorf("%+v: probed", a)
		}
	}
}

// TestRequestFailureCountsAndRetries: an unreachable vault gives
// ErrUnreachable; the attempt counts toward the hourly bound and the
// next Ensure may try again.
func TestRequestFailure(t *testing.T) {
	f, _, m := setup(none)
	f.answer("device.session.request", func() (*vaultconn.Response, error) { return nil, errors.New("down") })
	if err := ensure(t, m); !errors.Is(err, ErrUnreachable) {
		t.Fatalf("got %v", err)
	}
	if err := ensure(t, m); !errors.Is(err, ErrUnreachable) || f.count("device.session.request") != 2 {
		t.Fatalf("retry: %v", err)
	}
	f.answer("device.session.request", func() (*vaultconn.Response, error) { return nil, vaultconn.ErrRefused })
	if err := ensure(t, m); !errors.Is(err, vaultconn.ErrRefused) {
		t.Fatalf("refused: %v", err)
	}
}

func TestDenialWithoutOutstanding(t *testing.T) {
	f, _, m := setup(none)
	m.OnEvent(vaultconn.Event{Type: "device.session.ended", Body: json.RawMessage(`{"reason":"denied"}`)})
	if err := ensure(t, m); !errors.Is(err, ErrAccessDenied) || f.count("device.session.request") != 0 {
		t.Fatalf("got %v", err)
	}
	// An app ending the session starts no quiet period (AG8 names only
	// denials and unanswered requests).
	f2, _, m2 := setup(none)
	m2.OnEvent(vaultconn.Event{Type: "device.session.ended", Body: json.RawMessage(`{"reason":"ended"}`)})
	if err := ensure(t, m2); !errors.Is(err, ErrAccessRequested) || f2.count("device.session.request") != 1 {
		t.Fatalf("ended: %v", err)
	}
}

// TestProbeDoesNotOverwriteBatch: a grant applied by a batch while the
// probe is in flight is not overwritten by the probe's session_required
// (an atomic compare-and-set against the session before the probe).
func TestProbeDoesNotOverwriteBatch(t *testing.T) {
	f, _, m := setup(pairing.Access{})
	grant := pairing.Access{State: pairing.AccessActive, SessionID: "g", ExpiresAt: t0.Add(time.Hour)}
	f.answer("leash.grant.list", func() (*vaultconn.Response, error) {
		f.SetAccess(grant) // the batch lands while the answer is on its way
		return &vaultconn.Response{ErrorCode: "session_required"}, nil
	})
	if err := ensure(t, m); err != nil {
		t.Fatalf("got %v", err)
	}
	if f.Access() != grant || f.count("device.session.request") != 0 {
		t.Errorf("the grant was overwritten: %+v", f.Access())
	}
	// Likewise an end applied in between is not revived by a probe
	// that found a session.
	f2, _, m2 := setup(pairing.Access{})
	f2.answer("leash.grant.list", func() (*vaultconn.Response, error) {
		f2.SetAccess(pairing.Access{State: pairing.AccessNone})
		return &vaultconn.Response{OK: true, Body: json.RawMessage(`{}`)}, nil
	})
	_ = ensure(t, m2)
	if f2.Access().State != pairing.AccessNone {
		t.Errorf("an ended session was revived: %+v", f2.Access())
	}
	// OnAnswer with the session the request was sent with: a grant that
	// came after it stays.
	f3, _, m3 := setup(pairing.Access{State: pairing.AccessActive, SessionID: "old", ExpiresAt: t0.Add(time.Hour)})
	sent := m3.Snapshot()
	f3.SetAccess(grant)
	m3.OnAnswer("session_required", sent)
	if f3.Access() != grant {
		t.Errorf("OnAnswer overwrote a later grant: %+v", f3.Access())
	}
	m3.OnAnswer("session_required", m3.Snapshot())
	if f3.Access().State != pairing.AccessNone {
		t.Error("OnAnswer did not end the current session")
	}
}

// TestCallersDuringProbe: callers that arrive while the probe runs wait
// for it and get its outcome; none is told a request was sent when none
// was.
func TestCallersDuringProbe(t *testing.T) {
	for _, tc := range []struct {
		name   string
		answer func() (*vaultconn.Response, error)
		want   error
	}{
		{"session found", ok(`{}`), nil},
		{"unreachable", func() (*vaultconn.Response, error) { return nil, errors.New("down") }, ErrUnreachable},
		{"held", fail("owner_check_required", `{}`), ErrOwnerCheck},
	} {
		f, _, m := setup(pairing.Access{})
		release := make(chan struct{})
		f.answer("leash.grant.list", func() (*vaultconn.Response, error) { <-release; return tc.answer() })
		errs := make(chan error, 4)
		for i := 0; i < 4; i++ {
			go func() { errs <- m.Ensure(context.Background()) }()
		}
		time.Sleep(50 * time.Millisecond)
		close(release)
		for i := 0; i < 4; i++ {
			if err := <-errs; !errors.Is(err, tc.want) || (tc.want == nil && err != nil) {
				t.Errorf("%s: got %v, want %v", tc.name, err, tc.want)
			}
		}
		if f.count("leash.grant.list") != 1 || f.count("device.session.request") != 0 {
			t.Errorf("%s: %d probes, %d requests", tc.name, f.count("leash.grant.list"), f.count("device.session.request"))
		}
	}
}

// TestEnsureBounded: Ensure returns when its context ends although the
// vault has not answered (a tool call's 20 s budget); the request goes
// on, later callers are told access was requested, nothing more is sent,
// and the answer is recorded when it comes. A context that has already
// ended sends nothing.
func TestEnsureBounded(t *testing.T) {
	f, _, m := setup(none)
	release := make(chan struct{})
	f.mu.Lock()
	f.block = release
	f.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := m.Ensure(ctx); !errors.Is(err, ErrUnreachable) {
		t.Fatalf("got %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("Ensure did not return at its deadline")
	}
	if err := ensure(t, m); !errors.Is(err, ErrAccessRequested) {
		t.Fatalf("while the request is on its way: %v", err)
	}
	close(release)
	deadline := time.Now().Add(5 * time.Second)
	for {
		m.mu.Lock()
		out := m.outstanding
		m.mu.Unlock()
		if out {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the answer was not recorded")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := ensure(t, m); !errors.Is(err, ErrAccessRequested) || f.count("device.session.request") != 1 {
		t.Fatalf("after the answer: %v, %d requests", err, f.count("device.session.request"))
	}

	// The probe of an unknown session is bounded the same way.
	f2, _, m2 := setup(pairing.Access{})
	release2 := make(chan struct{})
	f2.mu.Lock()
	f2.block = release2
	f2.mu.Unlock()
	f2.answer("leash.grant.list", ok(`{}`))
	ctx2, cancel2 := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel2()
	if err := m2.Ensure(ctx2); !errors.Is(err, ErrUnreachable) {
		t.Fatalf("probe: %v", err)
	}
	close(release2)
	deadline = time.Now().Add(5 * time.Second)
	for f2.Access().State != pairing.AccessActive {
		if time.Now().After(deadline) {
			t.Fatal("the probe's answer was not recorded")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Already ended: nothing is sent.
	f3, _, m3 := setup(none)
	done, cancel3 := context.WithCancel(context.Background())
	cancel3()
	if err := m3.Ensure(done); err == nil || f3.count("device.session.request") != 0 {
		t.Fatalf("ended context: %v, %d requests", err, f3.count("device.session.request"))
	}
}

// TestCheckHold: while held, CheckHold sends vault.status at most once
// per HoldRecheck; an answer that is not held ends the hold and reaches
// the hook.
func TestCheckHold(t *testing.T) {
	f, c, m := setup(none)
	var mu sync.Mutex
	var hooked []string
	m.SetStatusHook(func(s string) { mu.Lock(); hooked = append(hooked, s); mu.Unlock() })
	f.answer("vault.status", ok(`{"owner_check":{"state":"held"}}`))
	m.OnStatus("held")
	if !m.Held() {
		t.Fatal("not held")
	}
	waitSent := func(n int) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			m.mu.Lock()
			busy := m.checking
			m.mu.Unlock()
			if f.count("vault.status") == n && !busy {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("%d vault.status, want %d", f.count("vault.status"), n)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	m.CheckHold()
	waitSent(1)
	m.CheckHold()
	c.add(30 * time.Second)
	m.CheckHold()
	waitSent(1)
	if !m.Held() {
		t.Error("held answer ended the hold")
	}
	f.answer("vault.status", ok(`{"owner_check":{"state":"ok"}}`))
	c.add(31 * time.Second)
	m.CheckHold()
	waitSent(2)
	if m.Held() {
		t.Error("ok answer did not end the hold")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(hooked) != 2 || hooked[0] != "held" || hooked[1] != "ok" {
		t.Errorf("hook got %v", hooked)
	}
}
