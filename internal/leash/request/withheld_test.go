package request

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vettid/vettid-agent/internal/access"
	"github.com/vettid/vettid-agent/internal/vaultconn"
)

// stale is a value in a marked copy: never used (VAULT-MESSAGING §8.2:
// "whatever else it carries").
const stale = "st4le-Value-9876"

// The vault's cached copies of an item.get answer (VAULT-MESSAGING 0.92.0
// §8.2, §10.11; owner decision a, GC #15273): marked "withheld": true,
// fields without `value`, no notes; and a marked answer that carries
// values all the same.
var copies = map[string]string{
	"marked, with values": strings.Replace(strings.TrimSuffix(itemBody, "}"), secret, stale, -1) + `,"withheld":true}`,
	"marked": `{"item_id":"` + itemID + `","name":"Bank","category":"login","fields":[{"field_id":"pw","label":"Password","kind":"password"},` +
		`{"field_id":"addr","label":"Address","kind":"address"}],"withheld":true}`,
	"field without value only": `{"item_id":"` + itemID + `","name":"Bank","category":"login","fields":[{"field_id":"pw","label":"Password","kind":"password","value":"` + secret + `"},` +
		`{"field_id":"addr","label":"Address","kind":"address"}]}`,
	"notes-only item": `{"item_id":"` + itemID + `","name":"Bank","category":"login","fields":[],"withheld":true}`,
	"backstop":        `{"withheld":true}`,
}

// A retransmission answered by the cached copy: the request is asked
// again once, as a new request under a new inner id, and the agent gets
// the value from that one's answer, under the id the tool call returned.
// The copy is never a result.
func TestWithheldAskedAgain(t *testing.T) {
	for name, cp := range copies {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, func(n int, id string) (*vaultconn.Response, error) {
				switch n {
				case 1:
					return nil, nil // the answer is lost: retransmitted
				case 2:
					return ok(cp), nil
				}
				return ok(itemBody), nil
			}, nil)
			out, err := e.c.Get(context.Background(), itemID, nil)
			if err != nil || !out.Pending {
				t.Fatalf("Get: %+v, %v", out, err)
			}
			res, err := status(t, e, out.RequestID)
			if err != nil || res.Result == nil || len(res.Result.Item.Fields) != 2 ||
				string(res.Result.Item.Fields[0].Value) != `"`+secret+`"` {
				t.Fatalf("Status: %+v, %v", res, err)
			}
			for _, f := range res.Result.Item.Fields {
				if strings.Contains(string(f.Value), stale) {
					t.Error("a value of the copy reached the result")
				}
			}
			if strings.Contains(string(res.Result.Item.Notes), stale) || strings.Contains(e.log.String(), stale) {
				t.Error("a value of the copy reached the result or the log")
			}
			res.Result.Wipe()
			c := e.conn.copies()
			if len(c) != 3 || c[0].id != out.RequestID || c[1].id != c[0].id || c[2].id == c[0].id || c[2].body != c[0].body {
				t.Fatalf("copies: %+v", c)
			}
			if !strings.Contains(e.log.String(), "asked again") {
				t.Error("not logged")
			}
			noSecretIn(t, "the log", e.log.String())
		})
	}
}

// The new request refused: that refusal is the outcome, never an empty
// item.
func TestWithheldThenRefused(t *testing.T) {
	e := newEnv(t, func(n int, id string) (*vaultconn.Response, error) {
		if n == 1 {
			return ok(copies["marked"]), nil
		}
		return refused("denied"), nil
	}, nil)
	out, err := e.c.Get(context.Background(), itemID, nil)
	if !errors.Is(err, ErrDenied) || out != nil {
		t.Fatalf("Get: %+v, %v", out, err)
	}
	if c := e.conn.copies(); len(c) != 2 || c[0].id == c[1].id {
		t.Errorf("copies: %+v", c)
	}
}

// The new request answered by a copy too: ErrWithheld, and no third
// request.
func TestWithheldTwice(t *testing.T) {
	e := newEnv(t, func(n int, id string) (*vaultconn.Response, error) {
		return ok(copies["marked"]), nil
	}, nil)
	out, err := e.c.Get(context.Background(), itemID, nil)
	if !errors.Is(err, ErrWithheld) || out != nil {
		t.Fatalf("Get: %+v, %v", out, err)
	}
	if c := e.conn.copies(); len(c) != 1+AskAgain || c[0].id == c[1].id {
		t.Errorf("copies: %+v", c)
	}
}

// The new request is held for the member's approval: approval.waiting
// names its new inner id and is honoured; one naming the old inner id is
// stale and ignored.
func TestWithheldNewRequestHeld(t *testing.T) {
	approve := make(chan struct{})
	var e *env
	var mu sync.Mutex
	var first string
	e = newEnv(t, func(n int, id string) (*vaultconn.Response, error) {
		if n == 1 {
			mu.Lock()
			first = id
			mu.Unlock()
			return ok(copies["marked"]), nil
		}
		mu.Lock()
		old := first
		mu.Unlock()
		waiting(e, old, time.Now().Add(time.Hour)) // stale
		waiting(e, id, time.Now().Add(2*time.Second))
		<-approve
		return ok(itemBody), nil
	}, nil)
	out, err := e.c.Get(context.Background(), itemID, nil)
	if err != nil || !out.Pending || !out.Waiting {
		t.Fatalf("Get: %+v, %v", out, err)
	}
	time.Sleep(450 * time.Millisecond) // past Options.Attempt and Unanswered
	if o, err := e.c.Status(context.Background(), out.RequestID); err != nil || !o.Pending || !o.Waiting {
		t.Fatalf("Status while held: %+v, %v", o, err)
	}
	e.c.mu.Lock()
	var exp time.Time
	for _, x := range e.c.entries {
		exp = x.exp
	}
	e.c.mu.Unlock()
	if time.Until(exp) > time.Minute {
		t.Errorf("the stale approval.waiting was taken: exp %v", exp)
	}
	close(approve)
	res, err := status(t, e, out.RequestID)
	if err != nil || res.Result == nil {
		t.Fatalf("Status: %+v, %v", res, err)
	}
	res.Result.Wipe()
	if c := e.conn.copies(); len(c) != 2 {
		t.Errorf("%d copies sent", len(c))
	}
}

// The new request starts afresh: the first one's approval (held, then
// answered by a copy after longer than Options.Unanswered) neither
// makes it Waiting nor makes Status call it unanswered.
func TestWithheldNewRequestStartsAfresh(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var e *env
	e = newEnv(t, func(n int, id string) (*vaultconn.Response, error) {
		if n == 1 {
			waiting(e, id, time.Now().Add(2*time.Second))
			time.Sleep(250 * time.Millisecond) // past Options.Unanswered
			return ok(copies["marked"]), nil
		}
		close(started)
		<-release
		return ok(itemBody), nil
	}, nil)
	var once sync.Once
	free := func() { once.Do(func() { close(release) }) }
	t.Cleanup(free) // before Close (cleanups run last first), even on a failure
	out, err := e.c.Get(context.Background(), itemID, nil)
	if err != nil || !out.Pending {
		t.Fatalf("Get: %+v, %v", out, err)
	}
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("not asked again")
	}
	if o, err := e.c.Status(context.Background(), out.RequestID); err != nil || !o.Pending || o.Waiting {
		t.Fatalf("Status after asking again: %+v, %v", o, err)
	}
	free()
	res, err := status(t, e, out.RequestID)
	if err != nil || res.Result == nil {
		t.Fatalf("Status: %+v, %v", res, err)
	}
	res.Result.Wipe()
}

// No new request once the vault suspended the agent.
func TestWithheldSuspended(t *testing.T) {
	var e *env
	// Suspended after the first copy was sent (do checks it before).
	e = newEnv(t, func(n int, id string) (*vaultconn.Response, error) {
		return ok(copies["marked"]), nil
	}, func(o *Options) { o.Suspended = func() bool { return len(e.conn.copies()) > 0 } })
	out, err := e.c.Get(context.Background(), itemID, nil)
	if !errors.Is(err, ErrSuspended) || out != nil {
		t.Fatalf("Get: %+v, %v", out, err)
	}
	if c := e.conn.copies(); len(c) != 1 {
		t.Errorf("copies: %+v", c)
	}
}

// A request whose tool call ended before it got the id asks nothing
// again: nobody could collect the value, and a new request would count a
// use and may ask the member.
func TestWithheldAbandoned(t *testing.T) {
	e := newEnv(t, func(n int, id string) (*vaultconn.Response, error) {
		time.Sleep(150 * time.Millisecond) // after the tool call ended
		return ok(copies["marked"]), nil
	}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err := e.c.Get(ctx, itemID, nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Get: %v", err)
	}
	eventually(t, "the request ends", func() bool {
		e.c.mu.Lock()
		defer e.c.mu.Unlock()
		return len(e.c.entries) == 0
	})
	if c := e.conn.copies(); len(c) != 1 {
		t.Errorf("copies: %+v", c)
	}
}

// While the vault is known to be held, nothing is asked again
// (AGENT-PLAN §4.4): the request ends with owner_check_required.
func TestWithheldHeld(t *testing.T) {
	var e *env
	e = newEnv(t, func(n int, id string) (*vaultconn.Response, error) {
		e.acc.mu.Lock()
		e.acc.held = true
		e.acc.mu.Unlock()
		return ok(copies["marked"]), nil
	}, nil)
	if _, err := e.c.Get(context.Background(), itemID, nil); !errors.Is(err, ErrOwnerCheck) {
		t.Fatalf("Get: %v", err)
	}
	if c := e.conn.copies(); len(c) != 1 {
		t.Errorf("copies: %+v", c)
	}
}

// The marker is checked for every op, not only item.get.
func TestWithheldAnyOp(t *testing.T) {
	cat := `{"items":[{"item_id":"` + itemID + `","name":"Bank","category":"login","labels":[]}]}`
	e := newEnv(t, func(n int, id string) (*vaultconn.Response, error) {
		if n == 1 {
			return ok(`{"items":[],"withheld":true}`), nil
		}
		return ok(cat), nil
	}, nil)
	out, err := e.c.Catalog(context.Background())
	if err != nil || out.Result == nil || len(out.Result.Catalog) != 1 {
		t.Fatalf("Catalog: %+v, %v", out, err)
	}
	if c := e.conn.copies(); len(c) != 2 || c[0].id == c[1].id {
		t.Errorf("copies: %+v", c)
	}
}

// "withheld" is absent from a live answer, never false (§8.2): any value
// but true is not an answer.
func TestWithheldNotTrue(t *testing.T) {
	for _, v := range []string{`false`, `null`, `"true"`, `1`} {
		body := strings.TrimSuffix(itemBody, "}") + `,"withheld":` + v + `}`
		e := newEnv(t, func(int, string) (*vaultconn.Response, error) { return ok(body), nil }, nil)
		if _, err := e.c.Get(context.Background(), itemID, nil); !errors.Is(err, ErrProtocol) {
			t.Errorf("withheld %s: %v", v, err)
		}
		if c := e.conn.copies(); len(c) != 1 {
			t.Errorf("withheld %s: copies: %+v", v, c)
		}
	}
}

// A `null` value is not a value (§10.11): the answer cannot be read.
func TestNullValueRefused(t *testing.T) {
	e := newEnv(t, func(int, string) (*vaultconn.Response, error) {
		return ok(`{"item_id":"` + itemID + `","name":"Bank","category":"login","fields":[{"field_id":"pw","label":"P","kind":"password","value":null}]}`), nil
	}, nil)
	if _, err := e.c.Get(context.Background(), itemID, nil); !errors.Is(err, ErrProtocol) {
		t.Fatalf("Get: %v", err)
	}
}

// Asked again after a resume or a clock jump: the access session is
// checked with the vault first (access Verify), and if that fails the
// request is not sent again, so nothing reaches the member's phone; the
// tool call gets the check's outcome.
func TestAskAgainVerifiesFirst(t *testing.T) {
	e := newEnv(t, func(n int, id string) (*vaultconn.Response, error) {
		return ok(copies["marked"]), nil
	}, nil)
	e.acc.mu.Lock()
	e.acc.verify = access.ErrUnreachable
	e.acc.mu.Unlock()
	out, err := e.c.Get(context.Background(), itemID, nil)
	if !errors.Is(err, ErrUnreachable) || out != nil {
		t.Fatalf("Get: %+v, %v", out, err)
	}
	if c := e.conn.copies(); len(c) != 1 {
		t.Fatalf("sent %d copies: asked again without the check", len(c))
	}
	e.acc.mu.Lock()
	n := e.acc.verifies
	e.acc.mu.Unlock()
	if n != 1 {
		t.Fatalf("%d checks before asking again", n)
	}
}
