package run

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"io"
	"os"
)

// Program is a resolved program held so that exactly the bytes hashed are
// the bytes started (AGENT-PLAN §4.9, "Run exactly what was hashed"):
// on Windows the file held open with sharing that refuses writing and
// deleting, on Linux a sealed memory file, on macOS a private copy. Close
// it once the process has started, or when the run is refused.
type Program struct {
	// Path is the resolved path: the `program` sent and shown, and what
	// argv[0] must still resolve to at the start.
	Path string
	// SHA256 is the file's SHA-256 as read, 64 lowercase hex digits: the
	// item.run `sha256`.
	SHA256 string

	plat platProgram
}

// StartSpec says how a prepared program is started.
type StartSpec struct {
	// Argv is the command; Argv[0] is the request's argv[0], which is
	// resolved again just before the start (Start).
	Argv []string
	// RunPath is the operator's --run-path directories, as Resolve takes
	// them.
	RunPath []string
	// Pinned is the catalog entry's pinned path, as ResolvePinned takes
	// it; "" for none.
	Pinned string
	// Env is the process environment as Env returns it.
	Env []string
	// Dir is the working directory, an absolute path.
	Dir string
	// Stdin, Stdout and Stderr are the process's standard files; nil is
	// the null device. The output limits and redaction are the caller's.
	Stdin, Stdout, Stderr *os.File
}

// resolveAgain is ResolvePinned, replaced by tests of the start alone.
var resolveAgain = ResolvePinned

// recheck resolves argv[0] again just before the start and refuses the
// run if it now names another path (AGENT-PLAN §4.9).
func (p *Program) recheck(s StartSpec) error {
	if len(s.Argv) == 0 {
		return badRequest("argv is empty")
	}
	got, err := resolveAgain(s.Argv[0], s.RunPath, s.Pinned)
	if err != nil {
		return err
	}
	if !samePath(got, p.Path) {
		return notFound("%s now resolves to %s, not to the program that was checked", s.Argv[0], got)
	}
	return nil
}

// hashingCopy reads r to its end into w (nil: nowhere) through SHA-256,
// refuses a script, content that starts with #! (AGENT-PLAN §4.9,
// "Scripts"), and anything that is not this system's own program format
// (checkFormat), and refuses content longer than limit bytes (0: no
// limit). It returns the lowercase hex digest.
func hashingCopy(w io.Writer, r io.Reader, path string, limit int64) (string, error) {
	h := sha256.New()
	var head [4]byte
	n, err := io.ReadFull(r, head[:])
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return "", notFound("%s can't be read: %v", path, err)
	}
	if bytes.HasPrefix(head[:n], []byte("#!")) {
		return "", notFound("%s is a script (it starts with #!); run its interpreter with the script as an argument", path)
	}
	if err := checkFormat(head[:n]); err != nil {
		return "", notFound("%s %v", path, err)
	}
	cw := &copyWriter{w: w}
	dst := io.MultiWriter(h, cw)
	if _, err := dst.Write(head[:n]); err != nil {
		return "", runFailed("%s can't be copied: %v", path, err)
	}
	src := r
	if limit > 0 {
		src = io.LimitReader(r, limit-int64(n)+1)
	}
	copied, err := io.Copy(dst, src)
	if err != nil {
		if cw.err != nil {
			return "", runFailed("%s can't be copied: %v", path, err)
		}
		return "", notFound("%s can't be read: %v", path, err)
	}
	if limit > 0 && int64(n)+copied > limit {
		return "", notFound("%s is larger than %d MiB, the most the connector runs", path, limit>>20)
	}
	return digest(h), nil
}

// copyWriter writes to w, if any, and remembers its error, so a failed
// copy (run_failed) is told from a failed read (program_not_found).
type copyWriter struct {
	w   io.Writer
	err error
}

func (c *copyWriter) Write(b []byte) (int, error) {
	if c.w == nil {
		return len(b), nil
	}
	n, err := c.w.Write(b)
	if err != nil {
		c.err = err
	}
	return n, err
}

// Process is a started run.
type Process struct {
	// Pid is the process id, for logs.
	Pid  int
	plat platProcess
}

// Wait waits for the process to end and returns its exit code.
func (p *Process) Wait() (int, error) { return p.plat.wait() }

// Kill ends the process (the process alone; groups and jobs are added
// with the process limits).
func (p *Process) Kill() error { return p.plat.kill() }

func digest(h hash.Hash) string { return hex.EncodeToString(h.Sum(nil)) }
