package pairing

import (
	"errors"
	"strings"
	"testing"

	"github.com/vettid/vettid-agent/internal/protect"
	"github.com/vettid/vettid-agent/internal/state"
)

const testPass = "Correct-Horse-Battery-9"

func fakeChoose(c protect.Choice, err error) func(protect.ChooseOptions) (protect.Choice, error) {
	return func(o protect.ChooseOptions) (protect.Choice, error) {
		if err != nil && o.AllowPassphraseFallback {
			return protect.Choice{Protector: protect.PassphraseName, Reason: err.Error() + "; using a passphrase"}, nil
		}
		return c, err
	}
}

// noFD sets the descriptor source to "not given", as AddFlags does.
func noFD(c *Protectors) *Protectors { c.Source.FD = -1; return c }

var platformTest = &testProtector{name: "tpm"}

func fakePlatform(name string) state.Protector {
	if name == "tpm" {
		return platformTest
	}
	return nil
}

// TestProtectorsNew: the owner's rules for `pair` (2026-10-18).
func TestProtectorsNew(t *testing.T) {
	works := protect.Choice{Protector: "tpm", Reason: "TPM 2.0 at /dev/tpmrm0", MachineBound: true}
	none := protect.Choice{Protector: protect.PassphraseName, Reason: "no TPM found; using a passphrase"}
	broken := errors.New("TPM: /dev/tpmrm0 cannot be opened by this user (permission denied): add your user to the tss group")

	// A working platform protector is used, and says so.
	c := noFD(&Protectors{choose: fakeChoose(works, nil), platform: fakePlatform})
	p, notice, err := c.New()
	if err != nil || p != platformTest || !strings.Contains(notice, "bound to this computer: TPM 2.0") {
		t.Errorf("works: %v %v %q", p, err, notice)
	}

	// Present but not working: refused with the cause, the fix and the
	// way to a passphrase; no passphrase is read.
	c = noFD(&Protectors{choose: fakeChoose(protect.Choice{}, broken), platform: fakePlatform})
	c.Source.FD = -1
	if _, _, err := c.New(); err == nil || !strings.Contains(err.Error(), "tss group") || !strings.Contains(err.Error(), "--passphrase") {
		t.Errorf("broken: %v", err)
	}

	// Present but not working, with --passphrase: the passphrase
	// protector, with the cause and the notice.
	c = noFD(&Protectors{Passphrase: true, Pass: []byte(testPass), choose: fakeChoose(protect.Choice{}, broken), platform: fakePlatform})
	p, notice, err = c.New()
	if err != nil || p.Name() != protect.PassphraseName || !strings.Contains(notice, "tss group") || !strings.Contains(notice, protect.NotMachineBound) {
		t.Errorf("broken + --passphrase: %v %q", err, notice)
	}

	// No platform protector at all: the passphrase, with the notice.
	c = noFD(&Protectors{Pass: []byte(testPass), choose: fakeChoose(none, nil), platform: fakePlatform})
	p, notice, err = c.New()
	if err != nil || p.Name() != protect.PassphraseName || !strings.HasSuffix(notice, protect.NotMachineBound) {
		t.Errorf("none: %v %q", err, notice)
	}

	// Working platform protector, --passphrase chosen explicitly.
	c = noFD(&Protectors{Passphrase: true, Pass: []byte(testPass), choose: fakeChoose(works, nil), platform: fakePlatform})
	p, notice, err = c.New()
	if err != nil || p.Name() != protect.PassphraseName || !strings.Contains(notice, protect.NotMachineBound) {
		t.Errorf("works + --passphrase: %v %q", err, notice)
	}

	// A passphrase source without --passphrase while the platform
	// protector works: refused rather than silently ignored.
	c = noFD(&Protectors{Pass: []byte(testPass), choose: fakeChoose(works, nil), platform: fakePlatform})
	if _, _, err := c.New(); err == nil || !strings.Contains(err.Error(), "add --passphrase") {
		t.Errorf("source without --passphrase: %v", err)
	}

	// A weak passphrase is refused before anything else happens.
	c = noFD(&Protectors{Pass: []byte("short"), choose: fakeChoose(none, nil), platform: fakePlatform})
	if _, _, err := c.New(); !errors.Is(err, protect.ErrWeakPassphrase) {
		t.Errorf("weak: %v", err)
	}
}

func TestProtectorsResolve(t *testing.T) {
	c := noFD(&Protectors{Pass: []byte(testPass), platform: fakePlatform})
	if c.Resolve("tpm") != platformTest || c.Resolve("unknown") != nil {
		t.Error("platform names")
	}
	p := c.Resolve(protect.PassphraseName)
	if p == nil || c.Resolve(protect.PassphraseName) != p {
		t.Error("passphrase protector not resolved or not cached")
	}
	c.Clear()
	if c.Pass != nil {
		t.Error("Clear kept the passphrase")
	}

	c = noFD(&Protectors{platform: fakePlatform})
	c.Source.FD = -1
	c.Source.File = "/nonexistent/passphrase"
	if c.Resolve(protect.PassphraseName) != nil || c.ResolveErr() == nil {
		t.Error("an unreadable passphrase source was not reported")
	}
}
