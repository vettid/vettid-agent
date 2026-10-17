package protect

import (
	"bytes"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadLine(t *testing.T) {
	cases := map[string]string{
		"Pass-Phrase-1\n":            "Pass-Phrase-1",
		"Pass-Phrase-1\r\n":          "Pass-Phrase-1",
		"Pass-Phrase-1":              "Pass-Phrase-1",
		"Pass-Phrase-1\nmore\n":      "Pass-Phrase-1",
		"with spaces  inside\n":      "with spaces  inside",
		"  leading and trailing  \n": "  leading and trailing  ",
	}
	for in, want := range cases {
		got, err := readLine(strings.NewReader(in), "test")
		if err != nil || string(got) != want {
			t.Errorf("readLine(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "\n", "\r\n", strings.Repeat("a", lineLimit+1)} {
		if _, err := readLine(strings.NewReader(in), "test"); err == nil {
			t.Errorf("readLine(%d bytes) accepted", len(in))
		}
	}
	// Nothing after the first line break is consumed.
	r := strings.NewReader("first\nsecond")
	if _, err := readLine(r, "test"); err != nil {
		t.Fatal(err)
	}
	if r.Len() != len("second") {
		t.Errorf("readLine consumed past the line break")
	}
}

func writeFile(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "passphrase")
	writePrivate(t, path, content, mode)
	return path
}

func TestReadFile(t *testing.T) {
	cases := map[string]string{
		"Pass-Phrase-1\n":   "Pass-Phrase-1",
		"Pass-Phrase-1\r\n": "Pass-Phrase-1",
		"Pass-Phrase-1":     "Pass-Phrase-1",
		"Trailing space \n": "Trailing space ",
	}
	for in, want := range cases {
		got, err := PassphraseSource{FD: -1, File: writeFile(t, in, 0o600)}.Read("", false)
		if err != nil || string(got) != want {
			t.Errorf("file %q: %q, %v; want %q", in, got, err, want)
		}
	}
	// Exactly one trailing line break is removed; a second one is a
	// second line.
	for _, in := range []string{"Pass-Phrase-1\n\n", "two\nlines\n", "", "\n", strings.Repeat("a", lineLimit+1)} {
		if _, err := (PassphraseSource{FD: -1, File: writeFile(t, in, 0o600)}).Read("", false); err == nil {
			t.Errorf("file %q accepted", in)
		}
	}
	if _, err := (PassphraseSource{FD: -1, File: filepath.Join(t.TempDir(), "missing")}).Read("", false); err == nil {
		t.Error("missing file accepted")
	}
	if _, err := (PassphraseSource{FD: -1, File: t.TempDir()}).Read("", false); err == nil {
		t.Error("directory accepted")
	}
}

func TestAddFlags(t *testing.T) {
	var s PassphraseSource
	fs := flag.NewFlagSet("x", flag.ContinueOnError)
	s.AddFlags(fs)
	if s.FD != -1 {
		t.Fatalf("FD default %d", s.FD)
	}
	if err := fs.Parse([]string{"--passphrase-fd", "3", "--passphrase-file", "/x"}); err != nil {
		t.Fatal(err)
	}
	if s.FD != 3 || s.File != "/x" {
		t.Fatalf("parsed %+v", s)
	}
	if _, err := s.Read("", false); err == nil || !strings.Contains(err.Error(), "not both") {
		t.Errorf("both sources: %v", err)
	}
	fs = flag.NewFlagSet("x", flag.ContinueOnError)
	fs.SetOutput(&bytes.Buffer{})
	s.AddFlags(fs)
	if err := fs.Parse([]string{"--passphrase-fd", "-1"}); err == nil {
		t.Error("negative fd accepted")
	}
}

// fakeTerminal replaces the terminal for one test.
func fakeTerminal(t *testing.T, tty bool, answers ...string) *bytes.Buffer {
	t.Helper()
	var out bytes.Buffer
	oIs, oRead, oOut := isTerminal, readPassword, promptOut
	isTerminal = func(int) bool { return tty }
	readPassword = func(int) ([]byte, error) {
		if len(answers) == 0 {
			return nil, errors.New("no more input")
		}
		a := answers[0]
		answers = answers[1:]
		return []byte(a), nil
	}
	promptOut = &out
	t.Cleanup(func() { isTerminal, readPassword, promptOut = oIs, oRead, oOut })
	return &out
}

func TestPrompt(t *testing.T) {
	out := fakeTerminal(t, true, "Pass-Phrase-1")
	got, err := PassphraseSource{FD: -1}.Read("Passphrase: ", false)
	if err != nil || string(got) != "Pass-Phrase-1" {
		t.Fatalf("Read = %q, %v", got, err)
	}
	if !strings.Contains(out.String(), "Passphrase: ") || strings.Contains(out.String(), "Pass-Phrase-1") {
		t.Errorf("prompt output %q", out.String())
	}

	fakeTerminal(t, true, "Pass-Phrase-1", "Pass-Phrase-1")
	if got, err := (PassphraseSource{FD: -1}).Read("New passphrase: ", true); err != nil || string(got) != "Pass-Phrase-1" {
		t.Errorf("confirmed Read = %q, %v", got, err)
	}

	fakeTerminal(t, true, "Pass-Phrase-1", "Pass-Phrase-2")
	if _, err := (PassphraseSource{FD: -1}).Read("New passphrase: ", true); err == nil || !strings.Contains(err.Error(), "do not match") {
		t.Errorf("mismatch: %v", err)
	}

	fakeTerminal(t, true, "")
	if _, err := (PassphraseSource{FD: -1}).Read("Passphrase: ", false); err == nil {
		t.Error("empty passphrase accepted")
	}

	fakeTerminal(t, false)
	if _, err := (PassphraseSource{FD: -1}).Read("Passphrase: ", false); err == nil || !strings.Contains(err.Error(), "--passphrase-fd") {
		t.Errorf("no terminal: %v", err)
	}
}
