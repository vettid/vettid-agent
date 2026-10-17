//go:build linux || darwin

package protect

import (
	"os"
	"strings"
	"syscall"
	"testing"
)

func TestReadFileRefusesLooseModes(t *testing.T) {
	for _, m := range []os.FileMode{0o640, 0o604, 0o660, 0o644} {
		_, err := PassphraseSource{FD: -1, File: writeFile(t, "Pass-Phrase-1\n", m)}.Read("", false)
		if err == nil || !strings.Contains(err.Error(), "owner only") {
			t.Errorf("mode %04o: %v", m, err)
		}
	}
	if _, err := (PassphraseSource{FD: -1, File: writeFile(t, "Pass-Phrase-1\n", 0o400)}).Read("", false); err != nil {
		t.Errorf("mode 0400: %v", err)
	}
}

func TestReadFD(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	// readFD takes ownership of the descriptor it is given and closes
	// it, so give it a duplicate.
	fd, err := syscall.Dup(int(r.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("Pass-Phrase-1\nnot read\n")); err != nil {
		t.Fatal(err)
	}
	w.Close()
	got, err := PassphraseSource{FD: fd}.Read("", false)
	if err != nil || string(got) != "Pass-Phrase-1" {
		t.Fatalf("Read = %q, %v", got, err)
	}
	if err := syscall.Close(fd); err == nil {
		t.Error("readFD left the descriptor open")
	}
}
