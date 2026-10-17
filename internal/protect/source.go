package protect

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"

	"golang.org/x/term"
)

// PassphraseSource says where a passphrase comes from (AGENT-PLAN §2
// AG3): a file descriptor (--passphrase-fd N), a file
// (--passphrase-file PATH), or, when neither is set, a prompt on the
// terminal with no echo.
//
// A passphrase never appears in an error or a log, and the prompt is
// written to standard error, never standard output (which `vettid-agent
// mcp` reserves for MCP messages).
type PassphraseSource struct {
	FD   int    // -1 when not set
	File string // "" when not set
}

// AddFlags registers --passphrase-fd and --passphrase-file on fs.
func (s *PassphraseSource) AddFlags(fs *flag.FlagSet) {
	s.FD = -1
	fs.Func("passphrase-fd", "read the passphrase from file descriptor `N` (up to the first line break)", func(v string) error {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return errors.New("not a file descriptor number")
		}
		s.FD = n
		return nil
	})
	fs.StringVar(&s.File, "passphrase-file", "", "read the passphrase from the owner-only file `PATH` (one line)")
}

// Terminal access, replaced in tests.
var (
	stdinFD                = int(os.Stdin.Fd())
	isTerminal             = term.IsTerminal
	readPassword           = term.ReadPassword
	promptOut    io.Writer = os.Stderr
)

// Read returns the passphrase from the source. For a new passphrase
// (confirm set) the prompt asks twice and refuses a mismatch. The caller
// clears the returned bytes when done.
func (s PassphraseSource) Read(prompt string, confirm bool) ([]byte, error) {
	switch {
	case s.FD >= 0 && s.File != "":
		return nil, errors.New("give either --passphrase-fd or --passphrase-file, not both")
	case s.FD >= 0:
		return readFD(s.FD)
	case s.File != "":
		return readFile(s.File)
	default:
		return readPrompt(prompt, confirm)
	}
}

// lineLimit is the most a source reads: the longest passphrase plus a
// line break.
const lineLimit = MaxBytes + 2

// readFD reads from file descriptor fd up to its first line break or
// end of file, and closes it.
func readFD(fd int) ([]byte, error) {
	f := os.NewFile(uintptr(fd), "passphrase-fd")
	if f == nil {
		return nil, fmt.Errorf("--passphrase-fd %d: not an open file descriptor", fd)
	}
	defer f.Close()
	return readLine(f, fmt.Sprintf("--passphrase-fd %d", fd))
}

// readLine reads up to the first line break or end of file, one byte at
// a time so that nothing after the line is consumed, and removes a "\r"
// before the line break.
func readLine(r io.Reader, label string) ([]byte, error) {
	buf := make([]byte, 0, lineLimit+1) // no reallocation, so no stray copies
	var one [1]byte
	for {
		n, err := r.Read(one[:])
		if n == 1 {
			if one[0] == '\n' {
				break
			}
			if len(buf) >= lineLimit {
				clear(buf)
				return nil, fmt.Errorf("%s: passphrase longer than %d bytes", label, MaxBytes)
			}
			buf = append(buf, one[0])
			continue
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			clear(buf)
			return nil, fmt.Errorf("%s: read failed", label)
		}
	}
	buf = bytes.TrimSuffix(buf, []byte("\r"))
	if len(buf) == 0 {
		return nil, fmt.Errorf("%s: empty passphrase", label)
	}
	return buf, nil
}

// readFile reads a passphrase file: it must be private to the current
// user (POSIX, checkPassphraseFile), hold one line, and one trailing
// line break ("\n" or "\r\n") is removed.
func readFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("--passphrase-file: %w", err)
	}
	defer f.Close()
	if err := checkPassphraseFile(f); err != nil {
		return nil, fmt.Errorf("--passphrase-file: %w", err)
	}
	raw, err := io.ReadAll(io.LimitReader(f, lineLimit+1))
	if err != nil {
		return nil, errors.New("--passphrase-file: read failed")
	}
	if len(raw) > lineLimit {
		clear(raw)
		return nil, fmt.Errorf("--passphrase-file: passphrase longer than %d bytes", MaxBytes)
	}
	pass := raw
	if bytes.HasSuffix(pass, []byte("\r\n")) {
		pass = pass[:len(pass)-2]
	} else if bytes.HasSuffix(pass, []byte("\n")) {
		pass = pass[:len(pass)-1]
	}
	if bytes.ContainsAny(pass, "\r\n") {
		clear(raw)
		return nil, errors.New("--passphrase-file: the file must hold the passphrase on one line")
	}
	if len(pass) == 0 {
		return nil, errors.New("--passphrase-file: empty passphrase")
	}
	return pass, nil
}

func readPrompt(prompt string, confirm bool) ([]byte, error) {
	if !isTerminal(stdinFD) {
		return nil, errors.New("no terminal to ask for the passphrase; use --passphrase-fd or --passphrase-file")
	}
	ask := func(p string) ([]byte, error) {
		fmt.Fprint(promptOut, p)
		b, err := readPassword(stdinFD)
		fmt.Fprintln(promptOut)
		if err != nil {
			return nil, errors.New("could not read the passphrase from the terminal")
		}
		return b, nil
	}
	pass, err := ask(prompt)
	if err != nil {
		return nil, err
	}
	if len(pass) == 0 {
		return nil, errors.New("empty passphrase")
	}
	if !confirm {
		return pass, nil
	}
	again, err := ask("Enter it again: ")
	if err != nil {
		clear(pass)
		return nil, err
	}
	defer clear(again)
	if !Equal(pass, again) {
		clear(pass)
		return nil, errors.New("the two passphrases do not match")
	}
	return pass, nil
}
