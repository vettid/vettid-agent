package request

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vettid/vettid-agent/internal/vaultconn"
)

// The vault's cached copies of an item.get answer (VAULT-MESSAGING 0.91.1
// §8.2, §10.11; owner decision a, GC #15273): marked "withheld": true,
// fields without `value`, no notes.
var copies = map[string]string{
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
	time.Sleep(50 * time.Millisecond)
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

// A `null` value is not a value (§10.11): the answer cannot be read.
func TestNullValueRefused(t *testing.T) {
	e := newEnv(t, func(int, string) (*vaultconn.Response, error) {
		return ok(`{"item_id":"` + itemID + `","name":"Bank","category":"login","fields":[{"field_id":"pw","label":"P","kind":"password","value":null}]}`), nil
	}, nil)
	if _, err := e.c.Get(context.Background(), itemID, nil); !errors.Is(err, ErrProtocol) {
		t.Fatalf("Get: %v", err)
	}
}
