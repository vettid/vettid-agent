package channel

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// The console exchange of pair, status and forget, after the hellos: the
// client sends one Request line, and the service answers with lines of
// text for the person at the command, then the command's exit code. The
// client only shows the text; what the command does is the service's
// (A3.10b).

// Request is what pair, status or forget send. Code is the pairing
// code, sent once and never stored or logged; Label is the name the
// phone shows for the agent; Restart discards an earlier pairing.
type Request struct {
	Code    string `json:"code,omitempty"`
	Label   string `json:"label,omitempty"`
	Restart bool   `json:"restart,omitempty"`
}

// maxConsoleLine bounds one line of the exchange.
const maxConsoleLine = 64 << 10

type consoleLine struct {
	Text *string `json:"text,omitempty"`
	Exit *int    `json:"exit,omitempty"`
}

// SendRequest writes r as one line, and zeroes the bytes it wrote from
// (they may hold the pairing code).
func SendRequest(w io.Writer, r Request) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	_, err = w.Write(b)
	clear(b)
	return err
}

// ReadRequest reads a client's Request (the service's side).
func ReadRequest(r io.Reader) (Request, error) {
	var req Request
	line, err := readConsoleLine(r)
	if err != nil {
		return req, err
	}
	defer clear(line)
	d := json.NewDecoder(bytes.NewReader(line))
	d.DisallowUnknownFields()
	if err := d.Decode(&req); err != nil {
		return Request{}, ErrBadHello
	}
	return req, nil
}

// readConsoleLine reads one line a byte at a time, so that nothing after
// it is consumed.
func readConsoleLine(r io.Reader) ([]byte, error) {
	var b [1]byte
	var line []byte
	for len(line) <= maxConsoleLine {
		if _, err := io.ReadFull(r, b[:]); err != nil {
			clear(line)
			return nil, fmt.Errorf("%w: %w", ErrBadHello, err)
		}
		if b[0] == '\n' {
			return line, nil
		}
		line = append(line, b[0])
	}
	clear(line)
	return nil, ErrBadHello
}

// WriteText sends a line of text for the person at the command (the
// service's side).
func WriteText(w io.Writer, text string) error {
	b, err := json.Marshal(consoleLine{Text: &text})
	if err != nil {
		return err
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

// WriteExit sends the command's exit code, the last line (the service's
// side).
func WriteExit(w io.Writer, code int) error {
	b, err := json.Marshal(consoleLine{Exit: &code})
	if err != nil {
		return err
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

// ErrNoAnswer: the service closed the channel before the command's exit
// code.
var ErrNoAnswer = errors.New("the connector service stopped before it answered")

// Relay writes the service's text to out, one line each, until its exit
// code, which it returns (0 to 125).
func Relay(r io.Reader, out io.Writer) (int, error) {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 4096), maxConsoleLine)
	for s.Scan() {
		var l consoleLine
		d := json.NewDecoder(bytes.NewReader(s.Bytes()))
		d.DisallowUnknownFields()
		if d.Decode(&l) != nil || (l.Text == nil) == (l.Exit == nil) {
			return 1, ErrBadHello
		}
		if l.Exit != nil {
			if *l.Exit < 0 || *l.Exit > 125 {
				return 1, ErrBadHello
			}
			return *l.Exit, nil
		}
		if _, err := fmt.Fprintln(out, *l.Text); err != nil {
			return 1, err
		}
	}
	if err := s.Err(); err != nil {
		return 1, fmt.Errorf("%w: %w", ErrNoAnswer, err)
	}
	return 1, ErrNoAnswer
}
