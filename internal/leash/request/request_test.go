package request

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"

	"github.com/vettid/vettid-agent/internal/access"
	"github.com/vettid/vettid-agent/internal/pairing"
	"github.com/vettid/vettid-agent/internal/vaultconn"
)

const (
	itemID = "01JB2Z6V9K3M4N5P6Q7R8S9XYZ"
	secret = "s3cr3t-Value-0123"
)

// sent is one copy of a request as the fake connection saw it.
type sent struct {
	id   string
	body string
}

// fakeConn hands each copy of a request to answer, which returns the
// response (nil: no answer, wait until the context ends) or an error.
type fakeConn struct {
	mu     sync.Mutex
	sent   []sent
	answer func(n int, id string) (*vaultconn.Response, error)
	bodies []json.RawMessage // response bodies handed out
}

func (f *fakeConn) NewID() (string, error) { return envelope.NewULID(time.Now()) }

func (f *fakeConn) RequestWithID(ctx context.Context, id, typ string, body json.RawMessage) (*vaultconn.Response, error) {
	if typ != "agent.request" {
		return nil, errors.New("unexpected type " + typ)
	}
	f.mu.Lock()
	f.sent = append(f.sent, sent{id: id, body: string(body)})
	n := len(f.sent)
	ans := f.answer
	f.mu.Unlock()
	r, err := ans(n, id)
	if err != nil {
		return nil, err
	}
	if r == nil {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	f.mu.Lock()
	f.bodies = append(f.bodies, r.Body)
	f.mu.Unlock()
	return r, nil
}

func (f *fakeConn) copies() []sent {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]sent(nil), f.sent...)
}

// fakeAccess records Ensure calls and OnAnswer codes.
type fakeAccess struct {
	mu       sync.Mutex
	ensure   error
	ensures  int
	answers  []string
	sentWith []pairing.Access
	snap     pairing.Access
}

func (a *fakeAccess) Ensure(context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.ensures++
	return a.ensure
}
func (a *fakeAccess) Snapshot() pairing.Access {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.snap
}
func (a *fakeAccess) OnAnswer(code string, sentWith pairing.Access) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.answers = append(a.answers, code)
	a.sentWith = append(a.sentWith, sentWith)
}
func (a *fakeAccess) set(err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.ensure = err
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

var session = pairing.Access{State: pairing.AccessActive, SessionID: "s1"}

type env struct {
	conn *fakeConn
	acc  *fakeAccess
	c    *Client
	log  *syncBuf
}

// short timings: a tool call waits 100 ms; an attempt 300 ms.
func newEnv(t *testing.T, answer func(n int, id string) (*vaultconn.Response, error), mod func(*Options)) *env {
	t.Helper()
	e := &env{conn: &fakeConn{answer: answer}, acc: &fakeAccess{snap: session}, log: &syncBuf{}}
	o := Options{Log: slog.New(slog.NewTextHandler(e.log, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Wait: 100 * time.Millisecond, Attempt: 300 * time.Millisecond, Grace: 100 * time.Millisecond,
		Unanswered: 200 * time.Millisecond, Keep: time.Second, RetryPause: 10 * time.Millisecond}
	if mod != nil {
		mod(&o)
	}
	e.c = New(e.conn, e.acc, o)
	t.Cleanup(e.c.Close)
	return e
}

func ok(body string) *vaultconn.Response {
	return &vaultconn.Response{Type: "agent.request", OK: true, Body: json.RawMessage(body)}
}

func refused(code string) *vaultconn.Response {
	return &vaultconn.Response{Type: "agent.request", ErrorCode: code}
}

const itemBody = `{"item_id":"` + itemID + `","name":"Bank","category":"login","fields":[{"field_id":"pw","label":"Password","kind":"password","value":"` + secret + `"},{"field_id":"addr","label":"Address","kind":"address","value":{"city":"Paris"}}],"notes":"note ` + secret + `"}`

func waiting(e *env, id string, exp time.Time) {
	e.c.OnEvent(vaultconn.Event{ID: "ev", Type: "approval.waiting",
		Body: json.RawMessage(`{"approval_id":"ap1","request_id":"` + id + `","exp":"` + exp.UTC().Format(time.RFC3339Nano) + `"}`)})
}

func eventually(t *testing.T, what string, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !f() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out: %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// status polls Status until the request is no longer pending.
func status(t *testing.T, e *env, id string) (*Outcome, error) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		out, err := e.c.Status(context.Background(), id)
		var re *Error
		inFlight := errors.As(err, &re) && re.RequestID != ""
		if !(err == nil && out.Pending) && !inFlight {
			return out, err
		}
		if time.Now().After(deadline) {
			t.Fatal("still pending")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func noSecretIn(t *testing.T, what, s string) {
	t.Helper()
	if strings.Contains(s, secret) || strings.Contains(s, "Paris") || strings.Contains(s, "Bank") {
		t.Errorf("%s holds an item value or name: %q", what, s)
	}
}

// TestAllow: an allowed item.get is answered within the tool call's
// wait; the result holds the values; nothing is kept; the response body
// is zeroed; the log holds no value; Wipe zeroes the values.
func TestAllow(t *testing.T) {
	e := newEnv(t, func(int, string) (*vaultconn.Response, error) { return ok(itemBody), nil }, nil)
	out, err := e.c.Get(context.Background(), itemID, nil)
	if err != nil || out.Pending || out.Result == nil || out.Result.Item == nil {
		t.Fatalf("Get: %+v, %v", out, err)
	}
	it := out.Result.Item
	if it.Name != "Bank" || len(it.Fields) != 2 || string(it.Fields[0].Value) != `"`+secret+`"` ||
		string(it.Fields[1].Value) != `{"city":"Paris"}` || string(it.Notes) != `"note `+secret+`"` {
		t.Fatalf("item: %+v", it)
	}
	c := e.conn.copies()
	if len(c) != 1 || c[0].body != `{"item_id":"`+itemID+`","op":"item.get"}` {
		t.Fatalf("sent: %+v", c)
	}
	for _, b := range e.conn.bodies {
		if len(bytes.Trim(b, "\x00")) != 0 {
			t.Error("the response body was not zeroed")
		}
	}
	e.c.mu.Lock()
	n := len(e.c.entries)
	e.c.mu.Unlock()
	if n != 0 {
		t.Errorf("%d entries kept after a direct answer", n)
	}
	if _, err := e.c.Status(context.Background(), c[0].id); !errors.Is(err, ErrExpired) {
		t.Errorf("Status of a returned request: %v", err)
	}
	noSecretIn(t, "the log", e.log.String())
	vals := [][]byte{it.Fields[0].Value, it.Fields[1].Value, it.Notes}
	out.Result.Wipe()
	for _, v := range vals {
		if len(bytes.Trim(v, "\x00")) != 0 {
			t.Error("Wipe left a value")
		}
	}
}

// TestCatalogAndUse: the other two ops, their bodies and answers.
func TestCatalogAndUse(t *testing.T) {
	cat := `{"items":[{"item_id":"` + itemID + `","name":"Bank","category":"login","labels":[{"field_id":"pw","label":"Password","kind":"password"}]}]}`
	use := `{"item_id":"` + itemID + `","field_id":"pw","action":"hmac-sha256","result":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="}`
	var next string
	e := newEnv(t, func(int, string) (*vaultconn.Response, error) { return ok(next), nil }, nil)
	next = cat
	out, err := e.c.Catalog(context.Background())
	if err != nil || len(out.Result.Catalog) != 1 || out.Result.Catalog[0].Labels[0].FieldID != "pw" {
		t.Fatalf("Catalog: %+v, %v", out, err)
	}
	next = `{"items":[]}`
	if out, err := e.c.Catalog(context.Background()); err != nil || out.Result.Catalog == nil || len(out.Result.Catalog) != 0 {
		t.Fatalf("empty Catalog: %+v, %v", out, err)
	}
	next = use
	out, err = e.c.Use(context.Background(), itemID, "pw", []byte("hello"))
	if err != nil || len(out.Result.Use.Result) != 32 || out.Result.Use.Result[31] != 31 {
		t.Fatalf("Use: %+v, %v", out, err)
	}
	c := e.conn.copies()
	if c[0].body != `{"op":"catalog"}` || c[2].body != `{"action":"hmac-sha256","data":"aGVsbG8=","field_id":"pw","item_id":"`+itemID+`","op":"item.use"}` {
		t.Errorf("bodies: %+v", c)
	}
	// An answer about another field, or a short HMAC, is not accepted.
	next = strings.Replace(use, `"pw"`, `"other"`, 1)
	if _, err := e.c.Use(context.Background(), itemID, "pw", []byte("x")); !errors.Is(err, ErrProtocol) {
		t.Errorf("another field: %v", err)
	}
	next = `{"item_id":"` + itemID + `","field_id":"pw","action":"hmac-sha256","result":"AAEC"}`
	if _, err := e.c.Use(context.Background(), itemID, "pw", []byte("x")); !errors.Is(err, ErrProtocol) {
		t.Errorf("short HMAC: %v", err)
	}
}

// TestGetChecksAnswer: an answer about another item, or with a field
// not asked for, is refused (and zeroed); notes sent with fields asked
// for are dropped.
func TestGetChecksAnswer(t *testing.T) {
	var next string
	e := newEnv(t, func(int, string) (*vaultconn.Response, error) { return ok(next), nil }, nil)
	next = strings.Replace(itemBody, itemID, "01JB2Z6V9K3M4N5P6Q7R8S9ABC", 1)
	if _, err := e.c.Get(context.Background(), itemID, nil); !errors.Is(err, ErrProtocol) {
		t.Errorf("another item: %v", err)
	}
	next = itemBody
	if _, err := e.c.Get(context.Background(), itemID, []string{"pw"}); !errors.Is(err, ErrProtocol) {
		t.Errorf("a field not asked for: %v", err)
	}
	next = `{"item_id":"` + itemID + `","name":"Bank","category":"login","fields":[{"field_id":"pw","label":"P","kind":"password","value":"` + secret + `"}],"notes":"n"}`
	out, err := e.c.Get(context.Background(), itemID, []string{"pw"})
	if err != nil || out.Result.Item.Notes != nil || len(out.Result.Item.Fields) != 1 {
		t.Fatalf("fields: %+v, %v", out, err)
	}
	if string(e.conn.copies()[2].body) != `{"fields":["pw"],"item_id":"`+itemID+`","op":"item.get"}` {
		t.Errorf("body: %s", e.conn.copies()[2].body)
	}
	for _, b := range e.conn.bodies {
		if len(bytes.Trim(b, "\x00")) != 0 {
			t.Error("a response body was not zeroed")
		}
	}
}

// TestReferThenApprove: the vault holds the request (approval.waiting);
// the tool call returns pending with the waiting text; the attempt waits
// past Options.Attempt until the approval's exp; the approval's answer
// arrives; Status returns it once, then ErrExpired. One copy was sent.
func TestReferThenApprove(t *testing.T) {
	approve := make(chan struct{})
	var e *env
	e = newEnv(t, func(n int, id string) (*vaultconn.Response, error) {
		waiting(e, id, time.Now().Add(2*time.Second))
		<-approve
		return ok(itemBody), nil
	}, nil)
	out, err := e.c.Get(context.Background(), itemID, nil)
	if err != nil || !out.Pending || !out.Waiting || out.Text != TextWaiting || out.RequestID == "" {
		t.Fatalf("Get: %+v, %v", out, err)
	}
	time.Sleep(450 * time.Millisecond) // past Options.Attempt and Unanswered
	if o, err := e.c.Status(context.Background(), out.RequestID); err != nil || !o.Pending || !o.Waiting {
		t.Fatalf("Status while held: %+v, %v", o, err)
	}
	close(approve)
	res, err := status(t, e, out.RequestID)
	if err != nil || res.Result == nil || string(res.Result.Item.Fields[0].Value) != `"`+secret+`"` {
		t.Fatalf("Status: %+v, %v", res, err)
	}
	if _, err := e.c.Status(context.Background(), out.RequestID); !errors.Is(err, ErrExpired) {
		t.Errorf("second Status: %v", err)
	}
	if n := len(e.conn.copies()); n != 1 {
		t.Errorf("%d copies sent", n)
	}
	noSecretIn(t, "the log", e.log.String())
}

// TestReferThenDeny: held, then denied: final, Status keeps answering
// denied, nothing is sent again.
func TestReferThenDeny(t *testing.T) {
	var e *env
	e = newEnv(t, func(n int, id string) (*vaultconn.Response, error) {
		waiting(e, id, time.Now().Add(2*time.Second))
		time.Sleep(400 * time.Millisecond)
		return refused("denied"), nil
	}, nil)
	out, err := e.c.Get(context.Background(), itemID, nil)
	if err != nil || !out.Waiting {
		t.Fatalf("Get: %+v, %v", out, err)
	}
	for i := 0; i < 2; i++ {
		if _, err := status(t, e, out.RequestID); !errors.Is(err, ErrDenied) || err.Error() != TextDenied {
			t.Fatalf("Status %d: %v", i, err)
		}
	}
	time.Sleep(700 * time.Millisecond)
	if n := len(e.conn.copies()); n != 1 {
		t.Errorf("%d copies sent after a denial", n)
	}
}

// TestApprovalTimeout: held with a short exp, and the vault's answer is
// lost; after exp + Grace the request is sent again under the same
// inner id and the vault answers it from its dedupe with
// approval_timeout, which is final.
func TestApprovalTimeout(t *testing.T) {
	var e *env
	e = newEnv(t, func(n int, id string) (*vaultconn.Response, error) {
		if n == 1 {
			waiting(e, id, time.Now().Add(500*time.Millisecond))
			return nil, nil // the answer never arrives
		}
		return refused("approval_timeout"), nil
	}, nil)
	out, err := e.c.Get(context.Background(), itemID, nil)
	if err != nil || !out.Waiting {
		t.Fatalf("Get: %+v, %v", out, err)
	}
	start := time.Now()
	if _, err := status(t, e, out.RequestID); !errors.Is(err, ErrTimeout) {
		t.Fatalf("Status: %v", err)
	}
	if d := time.Since(start); d < 350*time.Millisecond {
		t.Errorf("sent again after %v, before exp + Grace", d)
	}
	time.Sleep(600 * time.Millisecond)
	c := e.conn.copies()
	if len(c) != 2 || c[0].id != c[1].id || c[0].body != c[1].body {
		t.Errorf("copies: %+v", c)
	}
	if _, err := e.c.Status(context.Background(), out.RequestID); !errors.Is(err, ErrTimeout) {
		t.Errorf("Status again: %v", err)
	}
}

// TestForbidden: forbidden is final and never sent again; with the
// agent suspended it is reported as the suspension, and while suspended
// nothing is sent.
func TestForbidden(t *testing.T) {
	susp := false
	var mu sync.Mutex
	e := newEnv(t, func(int, string) (*vaultconn.Response, error) { return refused("forbidden"), nil }, func(o *Options) {
		o.Suspended = func() bool { mu.Lock(); defer mu.Unlock(); return susp }
	})
	if _, err := e.c.Get(context.Background(), itemID, nil); !errors.Is(err, ErrForbidden) || err.Error() != TextForbidden {
		t.Fatalf("Get: %v", err)
	}
	time.Sleep(700 * time.Millisecond) // past Attempt: no retransmission
	if n := len(e.conn.copies()); n != 1 {
		t.Fatalf("%d copies after forbidden", n)
	}
	// Answered forbidden in the background: Status keeps saying so.
	e2 := newEnv(t, func(int, string) (*vaultconn.Response, error) {
		time.Sleep(400 * time.Millisecond)
		return refused("forbidden"), nil
	}, nil)
	out, err := e2.c.Catalog(context.Background())
	if err != nil || !out.Pending || out.Waiting || out.Text != TextInFlight {
		t.Fatalf("Catalog: %+v, %v", out, err)
	}
	if _, err := status(t, e2, out.RequestID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("Status: %v", err)
	}
	time.Sleep(700 * time.Millisecond)
	if n := len(e2.conn.copies()); n != 1 {
		t.Errorf("%d copies after forbidden in the background", n)
	}
	// Suspended at the answer: reported as the suspension.
	e.conn.mu.Lock()
	e.conn.answer = func(int, string) (*vaultconn.Response, error) {
		mu.Lock()
		susp = true
		mu.Unlock()
		return refused("forbidden"), nil
	}
	e.conn.mu.Unlock()
	if _, err := e.c.Get(context.Background(), itemID, nil); !errors.Is(err, ErrSuspended) || err.Error() != TextSuspended {
		t.Fatalf("Get while being suspended: %v", err)
	}
	if _, err := e.c.Catalog(context.Background()); !errors.Is(err, ErrSuspended) {
		t.Fatalf("Catalog while suspended: %v", err)
	}
	if n := len(e.conn.copies()); n != 2 {
		t.Errorf("%d copies: something was sent while suspended", n)
	}
}

// TestOwnerCheckRequired: the vault held (known to internal/access):
// nothing is sent and the §11 text is given; answered
// owner_check_required: the access manager is told, with the session
// the request was sent with, and the §11 text is given; not retried.
func TestOwnerCheckRequired(t *testing.T) {
	e := newEnv(t, func(int, string) (*vaultconn.Response, error) { return refused("owner_check_required"), nil }, nil)
	e.acc.set(access.ErrOwnerCheck)
	_, err := e.c.Get(context.Background(), itemID, nil)
	if !errors.Is(err, ErrOwnerCheck) || err.Error() != "Your vault is waiting for your daily check. Open VettID on your phone." {
		t.Fatalf("held: %v", err)
	}
	if n := len(e.conn.copies()); n != 0 {
		t.Fatalf("%d copies sent while held", n)
	}
	e.acc.set(nil)
	_, err = e.c.Use(context.Background(), itemID, "pw", []byte("x"))
	if !errors.Is(err, ErrOwnerCheck) || err.Error() != access.ErrOwnerCheck.Text {
		t.Fatalf("answered: %v", err)
	}
	time.Sleep(700 * time.Millisecond)
	e.acc.mu.Lock()
	defer e.acc.mu.Unlock()
	if len(e.acc.answers) != 1 || e.acc.answers[0] != "owner_check_required" || e.acc.sentWith[0] != session {
		t.Errorf("OnAnswer: %v %v", e.acc.answers, e.acc.sentWith)
	}
	if n := len(e.conn.copies()); n != 1 {
		t.Errorf("%d copies sent", n)
	}
}

// TestLockedVault: a locked vault keeps the request in its mailbox and
// answers nothing. The tool call returns pending after Options.Wait;
// after Options.Unanswered Status gives the §11 text with the request
// still in flight; the request is sent again under the same inner id at
// most twice; then the answer is vault_unreachable, final.
func TestLockedVault(t *testing.T) {
	e := newEnv(t, func(int, string) (*vaultconn.Response, error) { return nil, nil }, nil)
	out, err := e.c.Get(context.Background(), itemID, nil)
	if err != nil || !out.Pending || out.Waiting || out.Text != TextInFlight {
		t.Fatalf("Get: %+v, %v", out, err)
	}
	time.Sleep(150 * time.Millisecond) // past Unanswered, before the second copy
	_, err = e.c.Status(context.Background(), out.RequestID)
	var re *Error
	if !errors.As(err, &re) || re.Code != "vault_unreachable" || re.RequestID != out.RequestID ||
		re.Text != "Your vault did not answer. It may be locked; unlock it on your phone." {
		t.Fatalf("Status in flight: %#v", err)
	}
	eventually(t, "the final answer", func() bool {
		_, err := e.c.Status(context.Background(), out.RequestID)
		return errors.As(err, &re) && re.RequestID == ""
	})
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("final: %v", err)
	}
	c := e.conn.copies()
	if len(c) != 1+Retransmissions {
		t.Fatalf("%d copies", len(c))
	}
	for _, s := range c {
		if s.id != out.RequestID {
			t.Errorf("a copy under another id: %s", s.id)
		}
	}
	time.Sleep(600 * time.Millisecond)
	if n := len(e.conn.copies()); n != 1+Retransmissions {
		t.Errorf("%d copies after the final answer", n)
	}
}

// TestUnlockedLate: the vault unlocks while the second copy waits and
// answers it (from its dedupe if it had run the first): the result is
// delivered, no third copy is sent.
func TestUnlockedLate(t *testing.T) {
	e := newEnv(t, func(n int, id string) (*vaultconn.Response, error) {
		if n == 1 {
			return nil, nil
		}
		return ok(itemBody), nil
	}, nil)
	out, err := e.c.Get(context.Background(), itemID, nil)
	if err != nil || !out.Pending {
		t.Fatalf("Get: %+v, %v", out, err)
	}
	res, err := status(t, e, out.RequestID)
	if err != nil || res.Result.Item == nil {
		t.Fatalf("Status: %+v, %v", res, err)
	}
	time.Sleep(600 * time.Millisecond)
	if n := len(e.conn.copies()); n != 2 {
		t.Errorf("%d copies", n)
	}
}

// TestSendFailureRetried: a deposit that fails is sent again under the
// same id after a pause.
func TestSendFailureRetried(t *testing.T) {
	e := newEnv(t, func(n int, id string) (*vaultconn.Response, error) {
		if n == 1 {
			return nil, errors.New("could not send agent.request to the vault: transport error")
		}
		return ok(itemBody), nil
	}, nil)
	out, err := e.c.Get(context.Background(), itemID, nil)
	if err != nil || out.Result == nil {
		t.Fatalf("Get: %+v, %v", out, err)
	}
	if c := e.conn.copies(); len(c) != 2 || c[0].id != c[1].id {
		t.Errorf("copies: %+v", c)
	}
	out.Result.Wipe()
}

// TestRefusedOrStopped: the relay refusing this agent, or the
// connection stopping, ends the request at once, without retries.
func TestRefusedOrStopped(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want *Error
	}{{vaultconn.ErrRefused, ErrRefused}, {vaultconn.ErrStopped, ErrStopped}} {
		e := newEnv(t, func(int, string) (*vaultconn.Response, error) { return nil, tc.err }, nil)
		if _, err := e.c.Get(context.Background(), itemID, nil); !errors.Is(err, tc.want) {
			t.Errorf("%v: %v", tc.err, err)
		}
		if n := len(e.conn.copies()); n != 1 {
			t.Errorf("%v: %d copies", tc.err, n)
		}
	}
}

// TestSessionRequired: the session ended before the vault ran the
// request: the access manager is told (with the session the request
// was sent with) and asked for access in this tool call; its answer is
// the tool's.
func TestSessionRequired(t *testing.T) {
	e := newEnv(t, func(int, string) (*vaultconn.Response, error) { return refused("session_required"), nil }, nil)
	var calls int
	// First Ensure (before sending) passes; the second (at the answer)
	// asks for access.
	e.c.acc = &seqAccess{fakeAccess: e.acc, errs: []error{nil, access.ErrAccessRequested}, calls: &calls}
	_, err := e.c.Get(context.Background(), itemID, nil)
	if !errors.Is(err, &Error{Code: access.ErrAccessRequested.Code}) || err.Error() != access.ErrAccessRequested.Text {
		t.Fatalf("Get: %v", err)
	}
	if len(e.acc.answers) != 1 || e.acc.answers[0] != "session_required" || e.acc.sentWith[0] != session {
		t.Errorf("OnAnswer: %v", e.acc.answers)
	}
	// A session exists again: ErrSession.
	e.c.acc = &seqAccess{fakeAccess: e.acc, errs: []error{nil, nil}, calls: &calls}
	if _, err := e.c.Get(context.Background(), itemID, nil); !errors.Is(err, ErrSession) {
		t.Fatalf("Get with a session again: %v", err)
	}
}

type seqAccess struct {
	*fakeAccess
	errs  []error
	calls *int
	i     int
}

func (s *seqAccess) Ensure(context.Context) error {
	*s.calls++
	err := s.errs[s.i]
	s.i++
	return err
}

// TestAccessFirst: without a session the access manager's answer is
// returned and nothing is sent.
func TestAccessFirst(t *testing.T) {
	e := newEnv(t, func(int, string) (*vaultconn.Response, error) { return ok(itemBody), nil }, nil)
	until := time.Now().Add(time.Minute)
	e.acc.set(&access.Error{Code: "access_denied", Text: access.ErrAccessDenied.Text, Until: until})
	_, err := e.c.Get(context.Background(), itemID, nil)
	var re *Error
	if !errors.As(err, &re) || re.Code != "access_denied" || !re.Until.Equal(until) {
		t.Fatalf("Get: %v", err)
	}
	if n := len(e.conn.copies()); n != 0 {
		t.Errorf("%d copies", n)
	}
}

// TestApprovalWaitingTolerated: approval.waiting repeated, in reverse
// order, after the answer, or for an unknown request changes nothing it
// should not: an older exp never shortens the wait.
func TestApprovalWaitingTolerated(t *testing.T) {
	answer := make(chan struct{})
	var e *env
	e = newEnv(t, func(n int, id string) (*vaultconn.Response, error) {
		waiting(e, id, time.Now().Add(2*time.Second))
		waiting(e, id, time.Now().Add(2*time.Second))
		waiting(e, id, time.Now().Add(10*time.Millisecond)) // older, reordered
		<-answer
		return ok(itemBody), nil
	}, nil)
	waiting(e, "01JB2Z6V9K3M4N5P6Q7R8S9DEF", time.Now().Add(time.Second))
	e.c.OnEvent(vaultconn.Event{Type: "approval.waiting", Body: json.RawMessage(`not json`)})
	out, err := e.c.Get(context.Background(), itemID, nil)
	if err != nil || !out.Waiting {
		t.Fatalf("Get: %+v, %v", out, err)
	}
	time.Sleep(600 * time.Millisecond) // past Attempt and the short exp + Grace
	if n := len(e.conn.copies()); n != 1 {
		t.Fatalf("an older approval.waiting shortened the wait: %d copies", n)
	}
	close(answer)
	if res, err := status(t, e, out.RequestID); err != nil || res.Result == nil {
		t.Fatalf("Status: %+v %v", res, err)
	}
	waiting(e, out.RequestID, time.Now().Add(time.Second)) // after the answer
	if _, err := e.c.Status(context.Background(), out.RequestID); !errors.Is(err, ErrExpired) {
		t.Errorf("after a late approval.waiting: %v", err)
	}
}

// TestKeptTenMinutes: an uncollected result is zeroed and dropped
// Options.Keep after the answer; an error likewise.
func TestKeptTenMinutes(t *testing.T) {
	release := make(chan struct{})
	e := newEnv(t, func(int, string) (*vaultconn.Response, error) {
		<-release
		return ok(itemBody), nil
	}, func(o *Options) { o.Keep = 100 * time.Millisecond })
	out, err := e.c.Get(context.Background(), itemID, nil)
	if err != nil || !out.Pending {
		t.Fatalf("Get: %+v, %v", out, err)
	}
	close(release)
	var res *Result
	eventually(t, "the answer", func() bool {
		e.c.mu.Lock()
		defer e.c.mu.Unlock()
		if en := e.c.entries[out.RequestID]; en != nil && en.done {
			res = en.res
			return true
		}
		return false
	})
	val := res.Item.Fields[0].Value
	eventually(t, "the drop", func() bool {
		e.c.mu.Lock()
		defer e.c.mu.Unlock()
		return e.c.entries[out.RequestID] == nil
	})
	if len(bytes.Trim(val, "\x00")) != 0 {
		t.Error("a dropped result was not zeroed")
	}
	if _, err := e.c.Status(context.Background(), out.RequestID); !errors.Is(err, ErrExpired) {
		t.Errorf("Status after the drop: %v", err)
	}
}

// TestAbandoned: a tool call cancelled before it got the request id
// leaves nobody to collect the result: it is zeroed and dropped on
// arrival.
func TestAbandoned(t *testing.T) {
	release := make(chan struct{})
	e := newEnv(t, func(int, string) (*vaultconn.Response, error) {
		<-release
		return ok(itemBody), nil
	}, func(o *Options) { o.Wait = 5 * time.Second })
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(20 * time.Millisecond); cancel() }()
	if _, err := e.c.Get(ctx, itemID, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("Get: %v", err)
	}
	close(release)
	eventually(t, "the drop", func() bool {
		e.c.mu.Lock()
		defer e.c.mu.Unlock()
		return len(e.c.entries) == 0
	})
}

// TestClose: Close stops the waits and zeroes kept results; later
// requests are refused.
func TestClose(t *testing.T) {
	release := make(chan struct{})
	e := newEnv(t, func(n int, id string) (*vaultconn.Response, error) {
		if n == 1 {
			<-release
			return ok(itemBody), nil
		}
		return nil, nil
	}, nil)
	a, _ := e.c.Get(context.Background(), itemID, nil)
	close(release)
	var res *Result
	eventually(t, "the answer", func() bool {
		e.c.mu.Lock()
		defer e.c.mu.Unlock()
		if en := e.c.entries[a.RequestID]; en != nil && en.done {
			res = en.res
			return true
		}
		return false
	})
	b, _ := e.c.Get(context.Background(), itemID, nil)
	if !b.Pending {
		t.Fatal("second request not pending")
	}
	e.c.Close()
	if len(bytes.Trim(res.Item.Fields[0].Value, "\x00")) != 0 {
		t.Error("Close left a value")
	}
	if _, err := e.c.Catalog(context.Background()); !errors.Is(err, ErrStopped) {
		t.Errorf("after Close: %v", err)
	}
}

// TestMaxPending: requests in flight or kept are bounded.
func TestMaxPending(t *testing.T) {
	e := newEnv(t, func(int, string) (*vaultconn.Response, error) { return nil, nil }, func(o *Options) {
		o.MaxPending, o.Wait = 2, time.Millisecond
	})
	for i := 0; i < 2; i++ {
		if out, err := e.c.Catalog(context.Background()); err != nil || !out.Pending {
			t.Fatalf("%d: %+v %v", i, out, err)
		}
	}
	if _, err := e.c.Catalog(context.Background()); !errors.Is(err, ErrTooMany) {
		t.Errorf("third: %v", err)
	}
}

// TestBadInput: requests the vault would refuse as bad_request are not
// sent.
func TestBadInput(t *testing.T) {
	e := newEnv(t, func(int, string) (*vaultconn.Response, error) { return ok(itemBody), nil }, nil)
	bad := &Error{Code: "bad_request"}
	for name, f := range map[string]func() error{
		"item id":     func() error { _, err := e.c.Get(context.Background(), "x", nil); return err },
		"no fields":   func() error { _, err := e.c.Get(context.Background(), itemID, []string{}); return err },
		"dup field":   func() error { _, err := e.c.Get(context.Background(), itemID, []string{"a", "a"}); return err },
		"field shape": func() error { _, err := e.c.Get(context.Background(), itemID, []string{"a b"}); return err },
		"use field":   func() error { _, err := e.c.Use(context.Background(), itemID, "", []byte("x")); return err },
		"no data":     func() error { _, err := e.c.Use(context.Background(), itemID, "pw", nil); return err },
		"big data": func() error {
			_, err := e.c.Use(context.Background(), itemID, "pw", make([]byte, MaxUseData+1))
			return err
		},
	} {
		if err := f(); !errors.Is(err, bad) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if n := len(e.conn.copies()); n != 0 {
		t.Errorf("%d copies", n)
	}
}

// TestOtherCodes: the vault's other codes are final, with a plain text;
// an odd code is filtered.
func TestOtherCodes(t *testing.T) {
	var code string
	e := newEnv(t, func(int, string) (*vaultconn.Response, error) { return refused(code), nil }, nil)
	for c, want := range map[string]*Error{"not_found": ErrNotFound, "limit": ErrLimit, "bad_request": {Code: "bad_request"},
		"x\n<y>": {Code: "xy"}} {
		code = c
		_, err := e.c.Get(context.Background(), itemID, nil)
		if !errors.Is(err, want) || strings.ContainsAny(err.Error(), "\n<>") {
			t.Errorf("%q: %v", c, err)
		}
	}
}

// TestRedacted: a result, item, field or use printed with any verb, or
// logged, shows no value, note or HMAC.
func TestRedacted(t *testing.T) {
	e := newEnv(t, func(int, string) (*vaultconn.Response, error) { return ok(itemBody), nil }, nil)
	out, err := e.c.Get(context.Background(), itemID, nil)
	if err != nil || out.Result == nil {
		t.Fatalf("Get: %+v, %v", out, err)
	}
	defer out.Result.Wipe()
	res := out.Result
	mac := []byte("0123456789abcdef0123456789abcdef")
	use := &Use{ItemID: itemID, FieldID: "pw", Action: "hmac-sha256", Result: mac}
	var logged syncBuf
	l := slog.New(slog.NewTextHandler(&logged, nil))
	l.Info("r", "result", res, "item", res.Item, "field", res.Item.Fields[0], "use", use)
	l.Info("r", "result", *res, "item", *res.Item, "use", *use)
	slog.New(slog.NewJSONHandler(&logged, nil)).Info("r", "result", res, "use", use)
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%x", "%q", "%d"} {
		for _, v := range []any{res, *res, res.Item, *res.Item, res.Item.Fields, res.Item.Fields[0], use, *use, out} {
			s := fmt.Sprintf(verb, v)
			noSecretIn(t, verb, s)
			if strings.Contains(s, string(mac)) || strings.Contains(s, fmt.Sprintf("%x", mac)) {
				t.Errorf("%s shows the HMAC: %s", verb, s)
			}
		}
	}
	noSecretIn(t, "log", logged.String())
	if strings.Contains(logged.String(), string(mac)) {
		t.Error("the log shows the HMAC")
	}
	if !strings.Contains(fmt.Sprint(res), "redacted") {
		t.Errorf("summary: %v", res)
	}
}

// TestNothingSentWhenEnded: a call whose context has ended, or one after
// Close, neither asks for access nor sends anything.
func TestNothingSentWhenEnded(t *testing.T) {
	e := newEnv(t, func(int, string) (*vaultconn.Response, error) { return ok(itemBody), nil }, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.c.Get(ctx, itemID, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled: %v", err)
	}
	e.c.Close()
	if _, err := e.c.Catalog(context.Background()); !errors.Is(err, ErrStopped) {
		t.Fatalf("closed: %v", err)
	}
	e.acc.mu.Lock()
	n := e.acc.ensures
	e.acc.mu.Unlock()
	if n != 0 || len(e.conn.copies()) != 0 {
		t.Errorf("%d access checks, %d copies", n, len(e.conn.copies()))
	}
}

// slowAccess blocks Ensure until its context ends, as internal/access
// does while its request waits for the vault.
type slowAccess struct{ *fakeAccess }

func (s slowAccess) Ensure(ctx context.Context) error {
	<-ctx.Done()
	return access.ErrUnreachable
}

// TestAccessWithinBudget: the access check is bounded by the tool
// call's wait (AG9): the call returns vault_unreachable at the end of
// the budget, not after the access manager's own 90 s.
func TestAccessWithinBudget(t *testing.T) {
	conn := &fakeConn{answer: func(int, string) (*vaultconn.Response, error) { return ok(itemBody), nil }}
	c := New(conn, slowAccess{&fakeAccess{snap: session}}, Options{Wait: 100 * time.Millisecond})
	defer c.Close()
	start := time.Now()
	_, err := c.Get(context.Background(), itemID, nil)
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("Get: %v", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("returned after %v", d)
	}
	if len(conn.copies()) != 0 {
		t.Error("sent without access")
	}
}
