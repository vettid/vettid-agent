package main

import (
	"bytes"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/vettid/vettid-vault/vms/invite"

	"github.com/vettid/vettid-agent/internal/pairing"
	"github.com/vettid/vettid-agent/internal/pairing/pairtest"
	"github.com/vettid/vettid-agent/internal/state"
)

type cmdTestProtector struct{}

var cmdTestKey = make([]byte, 32)

func (cmdTestProtector) Name() string { return "test-key" }
func (cmdTestProtector) Wrap(k []byte) ([]byte, error) {
	a, _ := chacha20poly1305.NewX(cmdTestKey)
	n := make([]byte, a.NonceSize())
	return a.Seal(n, n, k, nil), nil
}
func (cmdTestProtector) Unwrap(w []byte) ([]byte, error) {
	a, _ := chacha20poly1305.NewX(cmdTestKey)
	if len(w) < a.NonceSize() {
		return nil, errors.New("short")
	}
	return a.Open(nil, w[:a.NonceSize()], w[a.NonceSize():], nil)
}
func (cmdTestProtector) Wipe() error { return nil }

// withTestPairing replaces the protector (the platform's is tested in
// internal/protect) and standard input for one test.
func withTestPairing(t *testing.T, v *pairtest.Vault, stdin string) {
	t.Helper()
	pairOptions = func(o *pairing.Options) {
		o.HTTP = v.HTTPClient()
		o.Protector = func() (state.Protector, string, error) { return cmdTestProtector{}, "", nil }
		o.Resolve = func(string) state.Protector { return cmdTestProtector{} }
		o.PollWait = 10 * time.Millisecond
	}
	oldIn, oldTerm := codeIn, codeInTerminal
	codeIn, codeInTerminal = strings.NewReader(stdin), func() bool { return false }
	t.Cleanup(func() { pairOptions, codeIn, codeInTerminal = nil, oldIn, oldTerm })
}

func newVault(t *testing.T) *pairtest.Vault {
	t.Helper()
	v, err := pairtest.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(v.Close)
	return v
}

// TestPairCommand: `pair` with the code as an argument and on standard
// input pairs; standard output stays empty; standard error has the
// texts and never the code.
func TestPairCommand(t *testing.T) {
	for _, viaStdin := range []bool{false, true} {
		v := newVault(t)
		code, err := v.Code(invite.KindAgent, 10*time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(t.TempDir(), "state")
		args := []string{"pair", "--state-dir", dir, "--name", "CI agent"}
		stdin := ""
		if viaStdin {
			stdin = "Pair with this: vettid://connect#" + code + "\n"
		} else {
			args = append(args, code)
		}
		withTestPairing(t, v, stdin)
		var out, errOut bytes.Buffer
		if rc := run(args, &out, &errOut); rc != 0 {
			t.Fatalf("stdin %v: exit %d\n%s", viaStdin, rc, errOut.String())
		}
		if out.Len() != 0 {
			t.Errorf("stdin %v: wrote to standard output: %q", viaStdin, out.String())
		}
		e := errOut.String()
		shown, _ := pairing.FormatSAS(v.SAS())
		for _, w := range []string{shown, pairing.TextWaiting, pairing.TextPaired} {
			if !strings.Contains(e, w) {
				t.Errorf("stdin %v: stderr lacks %q:\n%s", viaStdin, w, e)
			}
		}
		if viaStdin != strings.Contains(e, pairing.TextStart) {
			t.Errorf("stdin %v: start text shown %v", viaStdin, !viaStdin)
		}
		if strings.Contains(e, code) || strings.Contains(e, v.SAS()) {
			t.Errorf("stdin %v: stderr holds the code or the unformatted SAS", viaStdin)
		}
		if v.Name() != "CI agent" {
			t.Errorf("name %q", v.Name())
		}
		// Again: already paired.
		var errOut2 bytes.Buffer
		withTestPairing(t, v, "")
		if rc := run([]string{"pair", "--state-dir", dir, code}, &bytes.Buffer{}, &errOut2); rc != 1 || !strings.Contains(errOut2.String(), "already paired") {
			t.Errorf("second pair: exit %d: %s", rc, errOut2.String())
		}
	}
}

func TestPairUsage(t *testing.T) {
	for _, args := range [][]string{{"pair"}, {"pair", "--state-dir", t.TempDir(), "a", "b"}, {"pair", "--bogus"}} {
		var out, errOut bytes.Buffer
		if rc := run(args, &out, &errOut); rc != 2 || out.Len() != 0 {
			t.Errorf("%v: exit %d, stdout %q", args, rc, out.String())
		}
	}
	var errOut bytes.Buffer
	if rc := run([]string{"pair", "--state-dir", filepath.Join(t.TempDir(), "s"), "--name", " bad"}, &bytes.Buffer{}, &errOut); rc != 1 {
		t.Errorf("bad name: exit %d", rc)
	}
}
