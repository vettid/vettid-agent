package access

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/vettid/vettid-agent/internal/pairing"
	"github.com/vettid/vettid-agent/internal/vaultconn"
)

// A session live on this computer's clock is not used after Suspect until
// a vault.status answers; the session it names decides, with the vault's
// own expiry; nothing is sent to the phone for it.
func TestSuspectVerifiedByStatus(t *testing.T) {
	live := pairing.Access{State: pairing.AccessActive, SessionID: "s1", ExpiresAt: t0.Add(time.Hour)}
	f, _, m := setup(live)
	f.answer("vault.status", ok(`{"vault_id":"v","owner_check":{"state":"ok"},"session":{"session_id":"s1","expires_at":"`+t0.Add(30*time.Minute).Format(time.RFC3339)+`"}}`))
	m.Suspect()
	if !m.Suspected() {
		t.Fatal("not suspect after Suspect")
	}
	if err := ensure(t, m); err != nil {
		t.Fatal(err)
	}
	if f.count("vault.status") != 1 || f.count("device.session.request") != 0 || f.count("leash.grant.list") != 0 {
		t.Fatalf("sent %v", f.sent)
	}
	if got := f.Access(); got.SessionID != "s1" || !got.ExpiresAt.Equal(t0.Add(30*time.Minute)) {
		t.Fatalf("session %+v, want the vault's", got)
	}
	if m.Suspected() {
		t.Fatal("still suspect after the vault answered")
	}
	// Then it is used as usual: no more vault.status.
	if err := ensure(t, m); err != nil || f.count("vault.status") != 1 {
		t.Fatalf("%v, %v", err, f.sent)
	}
}

// The vault says the session ended (null) while the computer slept: it is
// none, and only then does the usual request go out.
func TestSuspectSessionEnded(t *testing.T) {
	live := pairing.Access{State: pairing.AccessActive, SessionID: "s1", ExpiresAt: t0.Add(time.Hour)}
	f, _, m := setup(live)
	f.answer("vault.status", ok(`{"owner_check":{"state":"ok"},"session":null}`))
	m.Suspect()
	if err := ensure(t, m); !errors.Is(err, ErrAccessRequested) {
		t.Fatalf("Ensure = %v, want access_requested", err)
	}
	if f.Access().State != pairing.AccessNone {
		t.Fatalf("session %+v, want none", f.Access())
	}
	if f.count("vault.status") != 1 || f.count("device.session.request") != 1 {
		t.Fatalf("sent %v", f.sent)
	}
}

// While the vault doesn't answer, the session stays suspect and is not
// used: each Ensure says the vault did not answer and tries again.
func TestSuspectUnreachable(t *testing.T) {
	live := pairing.Access{State: pairing.AccessActive, SessionID: "s1", ExpiresAt: t0.Add(time.Hour)}
	f, _, m := setup(live)
	m.Suspect()
	for i := 0; i < 2; i++ {
		if err := ensure(t, m); !errors.Is(err, ErrUnreachable) {
			t.Fatalf("Ensure %d = %v, want vault_unreachable", i, err)
		}
	}
	if !m.Suspected() || f.count("vault.status") != 2 || f.count("device.session.request") != 0 {
		t.Fatalf("suspect %v, sent %v", m.Suspected(), f.sent)
	}
	// A status that names no session (a vault before VAULT-MESSAGING
	// 0.41.0) teaches nothing: still suspect.
	f.answer("vault.status", ok(`{"owner_check":{"state":"ok"}}`))
	if err := ensure(t, m); err == nil || !m.Suspected() {
		t.Fatalf("a status without session: %v, suspect %v", err, m.Suspected())
	}
}

// Tool calls that arrive during the check wait for it and take its
// outcome: one vault.status for all of them.
func TestCallersDuringVerify(t *testing.T) {
	live := pairing.Access{State: pairing.AccessActive, SessionID: "s1", ExpiresAt: t0.Add(time.Hour)}
	f, _, m := setup(live)
	f.answer("vault.status", ok(`{"owner_check":{"state":"ok"},"session":{"session_id":"s1","expires_at":"`+t0.Add(time.Hour).Format(time.RFC3339)+`"}}`))
	block := make(chan struct{})
	f.mu.Lock()
	f.block = block
	f.mu.Unlock()
	m.Suspect()
	var wg sync.WaitGroup
	errs := make([]error, 5)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = m.Ensure(context.Background())
		}()
	}
	time.Sleep(100 * time.Millisecond)
	close(block)
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("caller %d: %v", i, err)
		}
	}
	if n := f.count("vault.status"); n != 1 {
		t.Fatalf("%d vault.status for 5 callers", n)
	}
}

// A suspicion that comes while a check is on its way is not cleared by
// that check's answer: the caller checks again, after it.
func TestSuspectAgainDuringVerify(t *testing.T) {
	live := pairing.Access{State: pairing.AccessActive, SessionID: "s1", ExpiresAt: t0.Add(time.Hour)}
	f, _, m := setup(live)
	block := make(chan struct{})
	f.answer("vault.status", func() (*vaultconn.Response, error) {
		<-block
		return ok(`{"owner_check":{"state":"ok"},"session":{"session_id":"s1","expires_at":"` + t0.Add(time.Hour).Format(time.RFC3339) + `"}}`)()
	})
	m.Suspect()
	done := make(chan error, 1)
	go func() { done <- m.Ensure(context.Background()) }()
	for f.count("vault.status") == 0 {
		time.Sleep(time.Millisecond)
	}
	m.Suspect() // a second resume while the first check waits
	close(block)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if n := f.count("vault.status"); n != 2 {
		t.Fatalf("%d vault.status: the later suspicion was cleared by the check sent before it", n)
	}
	if m.Suspected() {
		t.Fatal("still suspect after a check sent after the last suspicion")
	}
}

// The vault's owner check in the same answer is taken too, with the
// status hook (the grants' hold).
func TestVerifyTakesOwnerCheck(t *testing.T) {
	f, _, m := setup(none)
	f.answer("vault.status", ok(`{"owner_check":{"state":"held"},"session":null}`))
	var hooked string
	m.SetStatusHook(func(s string) { hooked = s })
	m.Suspect()
	if err := ensure(t, m); !errors.Is(err, ErrOwnerCheck) {
		t.Fatalf("Ensure = %v, want owner_check_required", err)
	}
	if !m.Held() || hooked != "held" {
		t.Fatalf("held %v, hook %q", m.Held(), hooked)
	}
}

func TestJumped(t *testing.T) {
	for _, c := range []struct {
		wall, mono time.Duration
		want       bool
	}{
		{15 * time.Second, 15 * time.Second, false},
		{15*time.Second + ClockJump, 15 * time.Second, false},
		{15*time.Second + ClockJump + time.Millisecond, 15 * time.Second, true}, // set forward, or slept
		{15*time.Second - ClockJump - time.Millisecond, 15 * time.Second, true}, // set back
		{2 * time.Hour, 15 * time.Second, true},                                 // slept two hours
	} {
		if got := jumped(c.wall, c.mono); got != c.want {
			t.Errorf("jumped(%v, %v) = %v", c.wall, c.mono, got)
		}
	}
}

// WatchClock marks the session suspect when the wall clock moves apart
// from the monotonic one, and not otherwise.
func TestWatchClock(t *testing.T) {
	_, _, m := setup(none)
	var mu sync.Mutex
	wall, mono := t0, time.Duration(0)
	m.clock = func() (time.Time, time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		return wall, mono
	}
	m.clockEvery = 10 * time.Millisecond
	step := func(w, mo time.Duration) {
		mu.Lock()
		wall, mono = wall.Add(w), mono+mo
		mu.Unlock()
		time.Sleep(50 * time.Millisecond)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); m.WatchClock(ctx) }()
	defer func() { cancel(); <-done }()
	time.Sleep(20 * time.Millisecond)
	step(time.Second, time.Second)
	if m.Suspected() {
		t.Fatal("suspect with the clocks together")
	}
	step(3*time.Hour, time.Second) // a sleep, or the clock set forward
	if !m.Suspected() {
		t.Fatal("not suspect after the wall clock jumped")
	}
}
