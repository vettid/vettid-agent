package pairing

import (
	"errors"
	"fmt"

	"github.com/vettid/vettid-agent/internal/protect"
	"github.com/vettid/vettid-agent/internal/state"
)

// Passphrase prompts.
const (
	promptNewPassphrase = "Choose a passphrase to protect this connector's keys: "
	promptPassphrase    = "Passphrase that protects this connector's keys: "
)

// Protectors is the operator's protector choice for `pair` (AGENT-PLAN
// §2 AG3; owner decisions of 2026-10-18):
//
//   - by default the platform protector protect.ChooseProtector picks;
//     with no platform protector at all (no TPM; on macOS a build
//     without the Keychain entitlement) the passphrase protector, with
//     the "not bound to this computer" notice;
//   - a platform protector that is present but does not work (a TPM the
//     user cannot open): an error with the cause and the fix;
//   - Passphrase (--passphrase): the passphrase protector, chosen
//     explicitly, with the notice.
type Protectors struct {
	// Passphrase: the operator chose the passphrase protector.
	Passphrase bool
	// Source is where a passphrase is read from.
	Source protect.PassphraseSource
	// Pass is a passphrase already read (from --passphrase-fd, which must
	// be read before the state directory is opened), or nil. Clear
	// clears it.
	Pass []byte

	// NoPrompt: never ask on the terminal (`vettid-agent mcp`, whose
	// standard input carries MCP messages); a passphrase must come from
	// --passphrase-fd or --passphrase-file.
	NoPrompt bool

	// Dir is the state directory. A protector that keeps a key outside
	// the state file (the macOS Keychain) names its key by it, so that
	// it can delete the key from the header alone.
	Dir string

	choose   func(protect.ChooseOptions) (protect.Choice, error)
	platform func(string) state.Protector
	notices  func() []string // DPAPI's reach notices; tests replace it

	cached   state.Protector // the resolver's passphrase protector
	resolErr error
}

func (c *Protectors) chooser() func(protect.ChooseOptions) (protect.Choice, error) {
	if c.choose != nil {
		return c.choose
	}
	return protect.ChooseProtector
}

func (c *Protectors) platformFn() func(string) state.Protector {
	if c.platform != nil {
		return c.platform
	}
	return func(name string) state.Protector { return protect.Platform(name, c.Dir) }
}

func (c *Protectors) dpapiNotices() func() []string {
	if c.notices != nil {
		return c.notices
	}
	return protect.DPAPINotices
}

// sourceGiven reports whether a passphrase source flag was given.
func (c *Protectors) sourceGiven() bool {
	return c.Pass != nil || c.Source.FD >= 0 || c.Source.File != ""
}

// readPass returns a copy of the passphrase: the one already read, or
// one read now from the source.
func (c *Protectors) readPass(prompt string, confirm bool) ([]byte, error) {
	if c.Pass != nil {
		return append([]byte(nil), c.Pass...), nil
	}
	if c.NoPrompt && c.Source.FD < 0 && c.Source.File == "" {
		return nil, errNoPrompt
	}
	return c.Source.Read(prompt, confirm)
}

// New picks and prepares the protector for a new pairing (Options.Protector).
func (c *Protectors) New() (state.Protector, string, error) {
	choice, err := c.chooser()(protect.ChooseOptions{AllowPassphraseFallback: c.Passphrase})
	if err != nil {
		return nil, "", fmt.Errorf("%w\nTo protect the keys with a passphrase instead (not bound to this computer), run again with --passphrase.", err)
	}
	if choice.Protector != protect.PassphraseName {
		if c.Passphrase {
			choice = protect.Choice{Protector: protect.PassphraseName, Reason: "passphrase chosen with --passphrase"}
		} else {
			if c.sourceGiven() {
				return nil, "", fmt.Errorf("a passphrase source was given, but the keys would be protected by %s; to use the passphrase instead (not bound to this computer), add --passphrase", choice.Reason)
			}
			p := c.platformFn()(choice.Protector)
			if p == nil {
				return nil, "", fmt.Errorf("the protector %q is not available in this build", choice.Protector)
			}
			notice := "Keys are bound to this computer: " + choice.Reason + "."
			if choice.Protector == protect.DPAPIName {
				// How far the account's DPAPI keys reach beyond this
				// computer (owner decision, 2026-10-18): not refused,
				// said.
				for _, n := range c.dpapiNotices()() {
					notice += "\n" + n
				}
			}
			return p, notice, nil
		}
	}
	pass, err := c.readPass(promptNewPassphrase, true)
	if err != nil {
		return nil, "", err
	}
	defer clear(pass)
	if err := protect.CheckStrength(pass); err != nil {
		return nil, "", err
	}
	p, err := protect.NewPassphrase(pass)
	if err != nil {
		return nil, "", err
	}
	return p, choice.Reason + ".\n" + protect.NotMachineBound, nil
}

// Resolve returns the protector for an existing state file's header
// name (Options.Resolve). A passphrase is read the first time it is
// needed; a failure to read it is kept for ResolveErr.
func (c *Protectors) Resolve(name string) state.Protector {
	if name != protect.PassphraseName {
		return c.platformFn()(name)
	}
	if c.cached != nil {
		return c.cached
	}
	pass, err := c.readPass(promptPassphrase, false)
	if err != nil {
		c.resolErr = err
		return nil
	}
	defer clear(pass)
	p, err := protect.NewPassphrase(pass)
	if err != nil {
		c.resolErr = err
		return nil
	}
	c.cached = p
	return p
}

// ResolveErr returns why Resolve could not give the passphrase
// protector, or nil.
func (c *Protectors) ResolveErr() error { return c.resolErr }

// Clear forgets the passphrases held (best effort).
func (c *Protectors) Clear() {
	clear(c.Pass)
	c.Pass = nil
	if p, ok := c.cached.(*protect.Passphrase); ok {
		p.Forget()
	}
	c.cached = nil
}

// errNoPrompt: a passphrase is needed but asking for it is not allowed.
var errNoPrompt = errors.New("the keys are protected by a passphrase, and this command cannot ask for it (its standard input carries MCP messages): give it with --passphrase-file or --passphrase-fd")
