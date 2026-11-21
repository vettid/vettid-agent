// Package channel is the local channel between the stub and the
// connector service of the separate-account mode (AGENT-PLAN §2 AG14,
// §6 A3.10a; AGENT-SEPARATE-ACCOUNT §2, §4).
//
// On Windows it is a named pipe, \\.\pipe\vettid-agent-<n>-<random>
// (pipe_windows.go). The Unix socket end comes with A5.6.
//
// A connection starts with a hello each way, one line of JSON: the
// client names its operation (Op) and its version, the server answers
// with its version or a refusal. Each end refuses a peer of another
// version. After the hello the channel carries the operation's bytes
// unchanged: for OpMCP, MCP messages framed as on stdio. No file
// descriptors or handles cross it, and the server takes no path or
// configuration from the client: the pairing is chosen by the channel's
// name alone.
package channel

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
	"unicode/utf16"
)

// Op is what a client asks the service for.
type Op string

// The operations. Tools (OpMCP) are for the member only; OpPair and
// OpForget for an elevated administrator only; OpStatus for either
// (Admit).
const (
	OpMCP    Op = "mcp"
	OpStatus Op = "status"
	OpPair   Op = "pair"
	OpForget Op = "forget"
)

func (o Op) valid() bool {
	switch o {
	case OpMCP, OpStatus, OpPair, OpForget:
		return true
	}
	return false
}

// Identity is who a client is, as the server reads it from the client's
// token (never from anything the client says, and never by its process
// id).
type Identity struct {
	// Member: the client's user is the member the pairing is bound to.
	Member bool
	// ElevatedAdmin: the client's token has the Administrators group
	// enabled and is at high integrity or above (System included).
	ElevatedAdmin bool
}

// Admit reports whether a client may run op: the member for tools and
// status; an elevated administrator for pair, forget and status, never
// for tools unless they are the member too (AGENT-PLAN §6 A3.10a, the
// lead's call). pair and forget from the member's normal process are
// refused whatever the client says.
func Admit(op Op, id Identity) error {
	switch op {
	case OpMCP:
		if id.Member {
			return nil
		}
	case OpStatus:
		if id.Member || id.ElevatedAdmin {
			return nil
		}
	case OpPair, OpForget:
		if id.ElevatedAdmin {
			return nil
		}
	}
	return ErrNotAllowed
}

// Refusal codes in the server's hello.
const (
	codeNotAllowed     = "not_allowed"
	codeVersionsDiffer = "versions_differ"
	codeInUse          = "in_use"
	codeBadHello       = "bad_hello"
)

// Errors a client or server sees.
var (
	// ErrNoService: the channel does not exist (the service is not
	// running, or is not installed).
	ErrNoService = errors.New("the connector service is not running")
	// ErrNotService: something answered on the channel's name, but the
	// channel is not the connector service's (its owner is another
	// account): a squatted name. Nothing is sent to it.
	ErrNotService = errors.New("the channel is not the connector service's")
	// ErrVersionsDiffer: the other end runs another version.
	ErrVersionsDiffer = errors.New("the connector service and this program are different versions")
	// ErrNotAllowed: this client may not run this operation.
	ErrNotAllowed = errors.New("this account may not do that on the connector's channel")
	// ErrInUse: another agent app is using the pairing.
	ErrInUse = errors.New("the pairing is in use by another agent app")
	// ErrNameTaken: Listen found the channel's name already taken.
	ErrNameTaken = errors.New("another program took the connector's channel name")
	// ErrBadHello: the peer did not speak the channel's hello.
	ErrBadHello = errors.New("the other end of the connector's channel did not answer as expected")
)

// Refusal returns an error that the server's hello sends as a refusal:
// ErrInUse, ErrNotAllowed or ErrVersionsDiffer (A3.10b's service uses
// ErrInUse).
func refusalCode(err error) string {
	switch {
	case errors.Is(err, ErrInUse):
		return codeInUse
	case errors.Is(err, ErrVersionsDiffer):
		return codeVersionsDiffer
	case errors.Is(err, ErrBadHello):
		return codeBadHello
	default:
		return codeNotAllowed
	}
}

func refusalErr(code string) error {
	switch code {
	case codeInUse:
		return ErrInUse
	case codeVersionsDiffer:
		return ErrVersionsDiffer
	case codeNotAllowed:
		return ErrNotAllowed
	default:
		return ErrBadHello
	}
}

// helloVersion is the hello's own format version.
const helloVersion = 1

// maxHello bounds a hello line.
const maxHello = 1024

type clientHello struct {
	Channel int    `json:"vettid_channel"`
	Op      Op     `json:"op"`
	Version string `json:"version"`
}

type serverHello struct {
	Channel int    `json:"vettid_channel"`
	Version string `json:"version"`
	Refused string `json:"refused,omitempty"`
}

// readLine reads one hello line a byte at a time, so that nothing after
// it is consumed: the operation's bytes follow on the same stream.
func readLine(r io.Reader) ([]byte, error) {
	var b [1]byte
	var line []byte
	for len(line) <= maxHello {
		if _, err := io.ReadFull(r, b[:]); err != nil {
			// The peer left, or the line was cut short however it ended
			// (end of file, a pipe closed, a deadline).
			return nil, fmt.Errorf("%w: %w", ErrBadHello, err)
		}
		if b[0] == '\n' {
			return line, nil
		}
		line = append(line, b[0])
	}
	return nil, ErrBadHello
}

func writeLine(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

// clientHandshake sends the client's hello and reads the server's. A
// refusal, or a server of another version, is an error.
func clientHandshake(rw io.ReadWriter, op Op, version string) error {
	if err := writeLine(rw, clientHello{Channel: helloVersion, Op: op, Version: version}); err != nil {
		return err
	}
	line, err := readLine(rw)
	if err != nil {
		return err
	}
	var h serverHello
	if json.Unmarshal(line, &h) != nil || h.Channel != helloVersion {
		return ErrBadHello
	}
	if h.Refused != "" {
		return refusalErr(h.Refused)
	}
	if h.Version != version {
		return ErrVersionsDiffer
	}
	return nil
}

// readClientHello reads a client's hello. A malformed one, or one of
// another version, is answered with a refusal and returned as an error.
func readClientHello(rw io.ReadWriter, version string) (Op, error) {
	line, err := readLine(rw)
	if err != nil {
		return "", err
	}
	var h clientHello
	d := json.NewDecoder(bytes.NewReader(line))
	d.DisallowUnknownFields()
	if d.Decode(&h) != nil || h.Channel != helloVersion || !h.Op.valid() {
		_ = refuse(rw, version, ErrBadHello)
		return "", ErrBadHello
	}
	if h.Version != version {
		_ = refuse(rw, version, ErrVersionsDiffer)
		return "", ErrVersionsDiffer
	}
	return h.Op, nil
}

func refuse(w io.Writer, version string, err error) error {
	return writeLine(w, serverHello{Channel: helloVersion, Version: version, Refused: refusalCode(err)})
}

func accept(w io.Writer, version string) error {
	return writeLine(w, serverHello{Channel: helloVersion, Version: version})
}

// nameRE is a pairing's name (chosen; not in the spec): it becomes part
// of a service name, an account name and a pipe name.
var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// ValidName reports whether n can name a pairing.
func ValidName(n string) bool { return nameRE.MatchString(n) }

// ServiceName is the Windows service of pairing n.
func ServiceName(n string) string { return "vettid-agent-" + n }

// ServiceSID returns the SID of the virtual service account
// NT SERVICE\<service>, in string form: S-1-5-80 followed by the SHA-1
// of the service's name in upper case, as UTF-16LE, read as five
// little-endian 32-bit numbers. It is what Windows gives that account,
// so the stub can check the channel's owner without asking anything the
// channel's other end could answer.
func ServiceSID(service string) string {
	u := utf16.Encode([]rune(strings.ToUpper(service)))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	sum := sha1.Sum(b)
	var s strings.Builder
	s.WriteString("S-1-5-80")
	for i := 0; i < 5; i++ {
		fmt.Fprintf(&s, "-%d", binary.LittleEndian.Uint32(sum[4*i:]))
	}
	return s.String()
}

// pipeRE is the pipe name of pairing n: vettid-agent-<n>-<random>, the
// random part 32 lowercase hexadecimal digits (chosen; not in the spec).
func validPipe(n, pipe string) bool {
	p := `vettid-agent-` + regexp.QuoteMeta(n) + `-[0-9a-f]{32}`
	ok, _ := regexp.MatchString(`^`+p+`$`, pipe)
	return ValidName(n) && ok
}

// DialConfig configures Dial.
type DialConfig struct {
	// Pipe is the pipe's name, without \\.\pipe\.
	Pipe string
	// Service is the SID the pipe's owner must have: the connector
	// service's (ServiceSID).
	Service string
	Op      Op
	Version string
	// Wait bounds the wait for a free instance (default 5 s).
	Wait time.Duration

	anonymous bool   // tests only: allow the server only anonymous
	server    string // tests only: open the pipe through this computer's name, as a remote client
}
