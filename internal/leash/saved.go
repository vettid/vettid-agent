package leash

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"
)

// The record's `leash` member (docs/STATE-FILE.md):
//
//	{"v":1,"as_of":"<RFC 3339>","suspended":false,"grants":[<grant>…]}
//
// each grant in its wire form (VAULT-MESSAGING §10.11) without the
// status members: statements are not saved.
type savedJSON struct {
	V         int               `json:"v"`
	AsOf      time.Time         `json:"as_of"`
	Suspended bool              `json:"suspended"`
	Grants    []json.RawMessage `json:"grants"`
}

const savedVersion = 1

type saved struct {
	grants    []*Grant
	suspended bool
	asOf      time.Time
}

var errSaved = errors.New("the saved grants are not valid")

func encodeSaved(gs []*Grant, suspended bool, asOf time.Time) (json.RawMessage, error) {
	s := savedJSON{V: savedVersion, AsOf: asOf.UTC(), Suspended: suspended, Grants: []json.RawMessage{}}
	for _, g := range gs {
		b, err := json.Marshal(g.wire())
		if err != nil {
			return nil, err
		}
		s.Grants = append(s.Grants, b)
	}
	return json.Marshal(s)
}

// decodeSaved parses the member strictly (no unknown members at its top
// level or in a grant, nothing after it) and checks each grant as when
// it arrived.
func decodeSaved(raw json.RawMessage, agentID string) (*saved, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var s savedJSON
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("%w: not the expected JSON", errSaved)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: data after it", errSaved)
	}
	if s.V != savedVersion || s.AsOf.IsZero() || len(s.Grants) > MaxGrants {
		return nil, fmt.Errorf("%w: unknown version or form", errSaved)
	}
	out := &saved{suspended: s.Suspended, asOf: s.AsOf}
	for _, r := range s.Grants {
		gd := json.NewDecoder(bytes.NewReader(r))
		gd.DisallowUnknownFields()
		var w wireGrant
		if err := gd.Decode(&w); err != nil || w.Status != nil || w.StatusSig != nil || w.Rotations != nil {
			return nil, fmt.Errorf("%w: a grant", errSaved)
		}
		g, err := parseGrant(&w, agentID)
		if err != nil {
			return nil, fmt.Errorf("%w: a grant", errSaved)
		}
		if slices.ContainsFunc(out.grants, func(o *Grant) bool { return o.ID == g.ID }) {
			return nil, fmt.Errorf("%w: a grant twice", errSaved)
		}
		out.grants = append(out.grants, g)
	}
	slices.SortFunc(out.grants, func(a, b *Grant) int { return strings.Compare(a.ID, b.ID) })
	return out, nil
}

// Saved is what the state file says of the grants, for
// `vettid-agent status` (which does not contact the vault).
type Saved struct {
	// Grants as last saved, without the ones expired at the time given
	// to ReadSaved.
	Grants    []GrantInfo
	Suspended bool
	// AsOf is when the vault last sent them.
	AsOf time.Time
}

// ReadSaved reads the record's `leash` member, whose grants must all be
// for deviceID; nil gives (nil, nil): no grants were ever saved.
func ReadSaved(raw json.RawMessage, deviceID string, now time.Time) (*Saved, error) {
	if raw == nil {
		return nil, nil
	}
	s, err := decodeSaved(raw, deviceID)
	if err != nil {
		return nil, err
	}
	return &Saved{Grants: infos(s.grants, nil, now), Suspended: s.suspended, AsOf: s.asOf}, nil
}
