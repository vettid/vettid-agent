package protect

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vettid/vettid-agent/internal/state"
)

// Test passphrases: public, protect nothing.
const (
	testPass  = "Correct-Horse-Battery-9"
	otherPass = "Correct-Horse-Battery-8"
)

// testParams keeps Argon2id cheap in tests. Production parameters are
// checked by TestProductionParams.
var testParams = Params{Time: 1, MemoryKiB: 256, Threads: 1}

func useTestParams(t *testing.T) {
	t.Helper()
	d, m := defaultParams, minParams
	defaultParams, minParams = testParams, testParams
	t.Cleanup(func() { defaultParams, minParams = d, m })
}

func newPass(t *testing.T, s string) *Passphrase {
	t.Helper()
	p, err := NewPassphrase([]byte(s))
	if err != nil {
		t.Fatalf("NewPassphrase: %v", err)
	}
	return p
}

func dataKey() []byte {
	k := make([]byte, state.DataKeyLen)
	for i := range k {
		k[i] = byte(i)
	}
	return k
}

func TestName(t *testing.T) {
	if got := newPass(t, testPass).Name(); got != "passphrase" {
		t.Fatalf("Name() = %q, want passphrase", got)
	}
}

func TestRoundTrip(t *testing.T) {
	useTestParams(t)
	blob, err := newPass(t, testPass).Wrap(dataKey())
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	got, err := newPass(t, testPass).Unwrap(blob)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if !bytes.Equal(got, dataKey()) {
		t.Fatal("unwrapped key differs")
	}
	// A fresh salt and nonce at every wrap.
	blob2, err := newPass(t, testPass).Wrap(dataKey())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(blob[10:26], blob2[10:26]) || bytes.Equal(blob[26:50], blob2[26:50]) {
		t.Error("salt or nonce repeated across wraps")
	}
}

func TestWrongPassphrase(t *testing.T) {
	useTestParams(t)
	blob, err := newPass(t, testPass).Wrap(dataKey())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newPass(t, otherPass).Unwrap(blob); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("Unwrap with another passphrase = %v, want ErrWrongPassphrase", err)
	}
}

// The same text typed composed or decomposed opens the same key.
func TestNFC(t *testing.T) {
	useTestParams(t)
	composed := "Café-Crème-2026"
	decomposed := "Café-Crème-2026"
	blob, err := newPass(t, composed).Wrap(dataKey())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newPass(t, decomposed).Unwrap(blob); err != nil {
		t.Fatalf("decomposed form: %v", err)
	}
	if !Equal([]byte(composed), []byte(decomposed)) {
		t.Error("Equal does not normalize")
	}
}

func TestWeakPassphrasesRefused(t *testing.T) {
	useTestParams(t)
	weak := map[string]string{
		"Short1!x":                     "characters",
		"Abcdefghij1":                  "characters", // 11
		"Cafe\u0301-Bar-1":             "characters", // 11 after NFC
		"alllowercaselettersonly":      "of these",
		"ALLUPPERCASE12345":            "of these",
		"lowercase and spaces":         "of these",
		"correct horse battery 9":      "of these", // spaces count for no class
		"123456789012!!":               "of these",
		"Tab\tInside-12345":            "control",
		"Line\nbreak-Inside-1":         "control",
		"Zero\u200bWidth-Space-1":      "invisible",
		"\ufeffByte-Order-Mark-1":      "invisible",
		"Bidi-Mark-Inside-1\u200e":     "invisible",
		"Private-Use-Inside-1\ue000":   "private-use",
		"Unassigned-Inside-1\u0378":    "unassigned",
		"Line\u2028Separator-Inside-1": "not visible",
		strings.Repeat("Aa1!", 257):    "longer",
		string([]byte{0xff, 'A', '1'}): "UTF-8",
	}
	for pass, want := range weak {
		err := CheckStrength([]byte(pass))
		if !errors.Is(err, ErrWeakPassphrase) {
			t.Errorf("CheckStrength(%q) = %v, want ErrWeakPassphrase", pass, err)
			continue
		}
		if !strings.Contains(err.Error(), want) {
			t.Errorf("CheckStrength(%q) = %q, want it to mention %q", pass, err, want)
		}
		if strings.Contains(err.Error(), pass) {
			t.Errorf("the error carries the passphrase")
		}
	}
	strong := []string{
		testPass,
		"correct horse battery 9!", // lower, digit, punctuation
		"CORRECT horse battery!",   // upper, lower, punctuation
		"ÄÖÜäöü123456",             // upper, lower, digit
		"パスワードはとても長いですAa",          // other, upper, lower
	}
	for _, pass := range strong {
		if err := CheckStrength([]byte(pass)); err != nil {
			t.Errorf("CheckStrength(%q) = %v, want nil", pass, err)
		}
	}
}

// A weak passphrase is refused when a state file is created, with a
// plain message, and nothing is written.
func TestWeakPassphraseRefusedAtCreate(t *testing.T) {
	useTestParams(t)
	s, err := state.Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	p, err := NewPassphrase([]byte("password1234"))
	if err != nil {
		t.Fatal(err)
	}
	err = s.Create(p, []byte("state"))
	if !errors.Is(err, ErrWeakPassphrase) {
		t.Fatalf("Create = %v, want ErrWeakPassphrase", err)
	}
	if !strings.Contains(err.Error(), "use at least 3 of these") {
		t.Errorf("message %q", err)
	}
	if ok, _ := s.Exists(); ok {
		t.Error("a state file was written")
	}
}

// A weaker passphrase made under older rules still opens: strength is
// checked when wrapping only.
func TestUnwrapDoesNotCheckStrength(t *testing.T) {
	useTestParams(t)
	blob := wrapUnchecked(t, "weak", testParams)
	if _, err := newPass(t, "weak").Unwrap(blob); err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
}

// wrapUnchecked wraps dataKey() under pass with the given parameters,
// bypassing the strength check.
func wrapUnchecked(t *testing.T, pass string, params Params) []byte {
	t.Helper()
	blob, err := (&Passphrase{pass: []byte(pass)}).wrap(dataKey(), params)
	if err != nil {
		t.Fatal(err)
	}
	return blob
}

func TestTamperedBlobRefused(t *testing.T) {
	useTestParams(t)
	blob, err := newPass(t, testPass).Wrap(dataKey())
	if err != nil {
		t.Fatal(err)
	}
	mut := func(f func(b []byte) []byte) []byte { return f(append([]byte{}, blob...)) }
	cases := map[string]struct {
		blob []byte
		want error
	}{
		"salt":           {mut(func(b []byte) []byte { b[12] ^= 1; return b }), ErrWrongPassphrase},
		"nonce":          {mut(func(b []byte) []byte { b[30] ^= 1; return b }), ErrWrongPassphrase},
		"ciphertext":     {mut(func(b []byte) []byte { b[len(b)-1] ^= 1; return b }), ErrWrongPassphrase},
		"time raised":    {mut(func(b []byte) []byte { binary.BigEndian.PutUint32(b[1:], 2); return b }), ErrWrongPassphrase},
		"memory raised":  {mut(func(b []byte) []byte { binary.BigEndian.PutUint32(b[5:], 512); return b }), ErrWrongPassphrase},
		"threads raised": {mut(func(b []byte) []byte { b[9] = 2; return b }), ErrWrongPassphrase},
		"time zero":      {mut(func(b []byte) []byte { binary.BigEndian.PutUint32(b[1:], 0); return b }), ErrParamsBelowMinimum},
		"memory low":     {mut(func(b []byte) []byte { binary.BigEndian.PutUint32(b[5:], 255); return b }), ErrParamsBelowMinimum},
		"threads zero":   {mut(func(b []byte) []byte { b[9] = 0; return b }), ErrParamsBelowMinimum},
		"time huge":      {mut(func(b []byte) []byte { binary.BigEndian.PutUint32(b[1:], 11); return b }), ErrParamsAboveMaximum},
		"memory huge":    {mut(func(b []byte) []byte { binary.BigEndian.PutUint32(b[5:], 256*1024+1); return b }), ErrParamsAboveMaximum},
		"threads huge":   {mut(func(b []byte) []byte { b[9] = 5; return b }), ErrParamsAboveMaximum},
		"version":        {mut(func(b []byte) []byte { b[0] = 2; return b }), ErrBlobFormat},
		"truncated":      {blob[:len(blob)-1], ErrBlobFormat},
		"trailing":       {append(append([]byte{}, blob...), 0), ErrBlobFormat},
		"empty":          {nil, ErrBlobFormat},
	}
	for name, c := range cases {
		if _, err := newPass(t, testPass).Unwrap(c.blob); !errors.Is(err, c.want) {
			t.Errorf("%s: Unwrap = %v, want %v", name, err, c.want)
		}
	}
}

// The production parameters are the vault's for passwords
// (VAULT-MESSAGING §3.5.1), new wraps use them, Unwrap refuses anything
// below them, and the maximum is what a small host can afford. The
// derivation is replaced by a stub here; the real one at production
// cost runs once, in TestPassphraseVectors.
func TestProductionParams(t *testing.T) {
	want := Params{Time: 3, MemoryKiB: 64 * 1024, Threads: 1}
	if DefaultParams() != want || MinParams() != want {
		t.Fatalf("DefaultParams %+v, MinParams %+v, want both %+v", DefaultParams(), MinParams(), want)
	}
	if maxParams != (Params{Time: 10, MemoryKiB: 256 * 1024, Threads: 4}) {
		t.Errorf("maxParams %+v", maxParams)
	}
	var used []Params
	old := deriveKey
	deriveKey = func(_, _ []byte, p Params) []byte { used = append(used, p); return make([]byte, 32) }
	defer func() { deriveKey = old }()

	blob, err := newPass(t, testPass).Wrap(dataKey())
	if err != nil {
		t.Fatal(err)
	}
	if got := (Params{binary.BigEndian.Uint32(blob[1:]), binary.BigEndian.Uint32(blob[5:]), blob[9]}); got != want {
		t.Errorf("blob parameters %+v, want %+v", got, want)
	}
	if _, err := newPass(t, testPass).Unwrap(blob); err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if len(used) != 2 || used[0] != want || used[1] != want {
		t.Errorf("derivations used %+v, want two at %+v", used, want)
	}
	// Below the production minimum: refused before any derivation.
	used = nil
	for _, low := range []Params{testParams, {2, 64 * 1024, 1}, {3, 64*1024 - 1, 1}, {3, 64 * 1024, 0}} {
		b := append([]byte{}, blob...)
		binary.BigEndian.PutUint32(b[1:], low.Time)
		binary.BigEndian.PutUint32(b[5:], low.MemoryKiB)
		b[9] = low.Threads
		if _, err := newPass(t, testPass).Unwrap(b); !errors.Is(err, ErrParamsBelowMinimum) {
			t.Errorf("%+v: Unwrap = %v, want ErrParamsBelowMinimum", low, err)
		}
	}
	if len(used) != 0 {
		t.Errorf("%d derivations ran for refused parameters", len(used))
	}
}

// Wipe deletes no key material (there is none) and leaves the
// protector usable; Forget clears the passphrase.
func TestWipeAndForget(t *testing.T) {
	useTestParams(t)
	p := newPass(t, testPass)
	blob, err := p.Wrap(dataKey())
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Wipe(); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Unwrap(blob); err != nil {
		t.Errorf("Unwrap after Wipe: %v", err)
	}
	p.Forget()
	if _, err := p.Unwrap(blob); !errors.Is(err, ErrForgotten) {
		t.Errorf("Unwrap after Forget = %v", err)
	}
	if _, err := p.Wrap(dataKey()); !errors.Is(err, ErrForgotten) {
		t.Errorf("Wrap after Forget = %v", err)
	}
}

// A Store.Wipe followed by Create with the same protector works.
func TestStoreWipeThenCreate(t *testing.T) {
	useTestParams(t)
	s, err := state.Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	p := newPass(t, testPass)
	if err := s.Create(p, []byte("first pairing")); err != nil {
		t.Fatal(err)
	}
	if err := s.Wipe(nil); err != nil {
		t.Fatalf("Wipe: %v", err)
	}
	if err := s.Create(p, []byte("second pairing")); err != nil {
		t.Fatalf("Create after Wipe: %v", err)
	}
	if got, err := s.Load(func(string) state.Protector { return p }); err != nil || string(got) != "second pairing" {
		t.Fatalf("Load = %q, %v", got, err)
	}
}

func TestNewPassphraseRefuses(t *testing.T) {
	for _, b := range [][]byte{nil, {}, bytes.Repeat([]byte("a"), MaxBytes+1), {0xff, 0xfe}} {
		if _, err := NewPassphrase(b); err == nil {
			t.Errorf("NewPassphrase(%d bytes) accepted", len(b))
		}
	}
}

// A state file created with this protector opens again, and does not
// open with another passphrase.
func TestStateFileWithPassphrase(t *testing.T) {
	useTestParams(t)
	dir := filepath.Join(t.TempDir(), "state")
	s, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Create(newPass(t, testPass), []byte("device state")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := s.Save([]byte("device state 2")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	s.Close()

	s, err = state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	resolve := func(p *Passphrase) state.Resolver {
		return func(name string) state.Protector {
			if name == PassphraseName {
				return p
			}
			return nil
		}
	}
	if _, err := s.Load(resolve(newPass(t, otherPass))); !errors.Is(err, state.ErrUnwrap) || !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("Load with another passphrase = %v, want ErrUnwrap and ErrWrongPassphrase", err)
	}
	got, err := s.Load(resolve(newPass(t, testPass)))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if string(got) != "device state 2" {
		t.Errorf("Load = %q", got)
	}
	if s.Protector().Name() != PassphraseName {
		t.Errorf("protector %q", s.Protector().Name())
	}
}

// The passphrase never reaches the log or an error, on the create,
// unwrap and failure paths.
func TestPassphraseNotLogged(t *testing.T) {
	useTestParams(t)
	var logs bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(old)

	const phrase = "Marker-Phrase-Under-Test-4711"
	const weakPhrase = "weakmarkerphraseundertest"
	var errs []error
	note := func(err error) {
		if err != nil {
			errs = append(errs, err)
			slog.Error("operation failed", "err", err) // as a caller would log it
		}
	}

	dir := filepath.Join(t.TempDir(), "state")
	s, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	note(s.Create(newPass(t, phrase), []byte("state")))
	if len(errs) != 0 {
		t.Fatalf("Create: %v", errs[0])
	}
	note(s.CreateReplace(newPass(t, weakPhrase), []byte("state"), nil))
	s.Close()

	s, err = state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, pass := range []string{phrase, phrase + "x", weakPhrase} {
		p := newPass(t, pass)
		_, err := s.Load(func(string) state.Protector { return p })
		note(err)
	}
	blob, err := newPass(t, phrase).Wrap(dataKey())
	if err != nil {
		t.Fatal(err)
	}
	blob[12] ^= 1
	_, err = newPass(t, phrase).Unwrap(blob)
	note(err)
	binary.BigEndian.PutUint32(blob[1:], 0)
	_, err = newPass(t, phrase).Unwrap(blob)
	note(err)

	// The sources' failure paths.
	file := filepath.Join(t.TempDir(), "pass")
	if err := os.WriteFile(file, []byte(phrase+"\nsecond line "+phrase+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = PassphraseSource{FD: -1, File: file}.Read("", false)
	note(err)
	_, err = readLine(strings.NewReader(strings.Repeat(phrase, 100)), "--passphrase-fd 3")
	note(err)

	if len(errs) < 6 {
		t.Fatalf("only %d failure paths exercised", len(errs))
	}
	if logs.Len() == 0 {
		t.Fatal("nothing logged; the capture is not working")
	}
	text := logs.String()
	for _, e := range errs {
		text += "\n" + e.Error()
	}
	for _, s := range []string{phrase, weakPhrase} {
		for _, form := range []string{s, hex.EncodeToString([]byte(s)), base64.StdEncoding.EncodeToString([]byte(s)), s[:12]} {
			if strings.Contains(text, form) {
				t.Errorf("log or error output contains the passphrase (form %q)", form)
			}
		}
	}
}

// The protector keeps its own copy: the caller may clear its bytes.
func TestNewPassphraseCopies(t *testing.T) {
	useTestParams(t)
	in := []byte(testPass)
	p, err := NewPassphrase(in)
	if err != nil {
		t.Fatal(err)
	}
	clear(in)
	blob, err := p.Wrap(dataKey())
	if err != nil {
		t.Fatalf("Wrap after the caller cleared its copy: %v", err)
	}
	if _, err := newPass(t, testPass).Unwrap(blob); err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	// CheckStrength and Equal leave their input alone.
	in = []byte(testPass)
	_ = CheckStrength(in)
	_ = Equal(in, in)
	if string(in) != testPass {
		t.Error("CheckStrength or Equal changed its input")
	}
}
