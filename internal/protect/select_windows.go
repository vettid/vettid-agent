//go:build windows

package protect

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/vettid/vettid-agent/internal/state"
)

// dpapiProbe is the DPAPI protector ChooseProtector tries; tests replace
// it.
var dpapiProbe = func() probeProtector { return NewDPAPI() }

type probeProtector interface {
	Wrap([]byte) ([]byte, error)
	Unwrap([]byte) ([]byte, error)
}

// ChooseProtector picks the protector for a new state file (AGENT-PLAN
// §2 AG3). DPAPI is part of every Windows, so there is no "absent" case:
//
//   - DPAPI works (a probe key wraps and unwraps to the same bytes): the
//     DPAPI protector;
//   - DPAPI fails (no loaded profile, a logon without the user's
//     password, a policy that picks algorithms this version does not
//     accept): an error naming the cause and the fix, unless
//     opts.AllowPassphraseFallback is set (the operator asked for a
//     passphrase), in which case the passphrase protector with that
//     cause as the reason.
func ChooseProtector(opts ChooseOptions) (Choice, error) {
	err := tryDPAPI()
	if err == nil {
		return Choice{Protector: DPAPIName, Reason: "Windows DPAPI, for this Windows user", MachineBound: true}, nil
	}
	if opts.AllowPassphraseFallback {
		return Choice{Protector: PassphraseName, Reason: err.Error() + "; using a passphrase"}, nil
	}
	return Choice{}, fmt.Errorf("%w; or choose a passphrase instead (not bound to this computer)", err)
}

// tryDPAPI wraps and unwraps a random probe key.
func tryDPAPI() error {
	key := make([]byte, state.DataKeyLen)
	defer clear(key)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	p := dpapiProbe()
	blob, err := p.Wrap(key)
	if err != nil {
		return fmt.Errorf("Windows DPAPI does not work for this user: %w", err)
	}
	got, err := p.Unwrap(blob)
	if err != nil {
		return fmt.Errorf("Windows DPAPI does not open what it just protected: %w", err)
	}
	defer clear(got)
	if subtle.ConstantTimeCompare(got, key) != 1 {
		return errors.New("Windows DPAPI returned another key than it was given")
	}
	return nil
}
