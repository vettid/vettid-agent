package request

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/vettid/vettid-vault/vms/envelope"
)

var errParse = errors.New("request: the answer does not have the expected shape")

// parse reads an ok answer to e's request (VAULT-MESSAGING §10.11). It
// checks that the answer is about what was asked: the same item, only
// the fields asked for, the same field and action. Values stay JSON text
// in byte slices of their own (encoding/json copies a RawMessage), never
// Go strings; on an error they are zeroed.
func parse(e *entry, body json.RawMessage) (*Result, error) {
	switch e.op {
	case OpCatalog:
		var b struct {
			Items *[]CatalogItem `json:"items"`
		}
		if json.Unmarshal(body, &b) != nil || b.Items == nil {
			return nil, errParse
		}
		for _, it := range *b.Items {
			if !envelope.ValidULID(it.ItemID) {
				return nil, errParse
			}
		}
		items := *b.Items
		if items == nil {
			items = []CatalogItem{}
		}
		return &Result{Op: OpCatalog, Catalog: items}, nil
	case OpGet:
		it := &Item{}
		res := &Result{Op: OpGet, Item: it}
		if err := json.Unmarshal(body, it); err != nil || !validItem(e, it) {
			res.Wipe()
			return nil, errParse
		}
		return res, nil
	case OpUse:
		var b struct {
			ItemID  string          `json:"item_id"`
			FieldID string          `json:"field_id"`
			Action  string          `json:"action"`
			Result  json.RawMessage `json:"result"`
		}
		if json.Unmarshal(body, &b) != nil || b.ItemID != e.itemID || b.FieldID != e.fieldID || b.Action != "hmac-sha256" {
			clear(b.Result)
			return nil, errParse
		}
		mac, ok := base64Bytes(b.Result)
		clear(b.Result)
		if !ok || len(mac) != 32 {
			clear(mac)
			return nil, errParse
		}
		return &Result{Op: OpUse, Use: &Use{ItemID: b.ItemID, FieldID: b.FieldID, Action: b.Action, Result: mac}}, nil
	}
	return nil, errParse
}

// validItem checks item.get's answer against the request; notes sent
// with fields asked for (which §10.11 rules out) are zeroed and dropped.
func validItem(e *entry, it *Item) bool {
	if it.ItemID != e.itemID || it.Fields == nil {
		return false
	}
	asked := map[string]bool{}
	for _, f := range e.fields {
		asked[f] = true
	}
	seen := map[string]bool{}
	for i := range it.Fields {
		f := &it.Fields[i]
		if !fieldIDRE.MatchString(f.FieldID) || seen[f.FieldID] || len(e.fields) > 0 && !asked[f.FieldID] {
			return false
		}
		seen[f.FieldID] = true
		switch {
		case f.Value == nil:
		case bytes.Equal(f.Value, []byte("null")):
			f.Value = nil
		case f.Value[0] != '"' && f.Value[0] != '{':
			return false
		}
	}
	switch {
	case it.Notes == nil:
	case bytes.Equal(it.Notes, []byte("null")):
		it.Notes = nil
	case len(e.fields) > 0:
		clear(it.Notes)
		it.Notes = nil
	case it.Notes[0] != '"':
		return false
	}
	return true
}

// base64Bytes decodes a JSON string of standard base64 (no escapes can
// occur in it) without making a Go string of it.
func base64Bytes(raw json.RawMessage) ([]byte, bool) {
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return nil, false
	}
	in := raw[1 : len(raw)-1]
	out := make([]byte, base64.StdEncoding.DecodedLen(len(in)))
	n, err := base64.StdEncoding.Decode(out, in)
	if err != nil {
		clear(out)
		return nil, false
	}
	return out[:n], true
}
