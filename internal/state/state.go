// Package state keeps the connector's secret state at rest (AGENT-PLAN
// §2 AG3, §4.2): one encrypted state file per state directory, written
// atomically, readable by the current user only, guarded by an
// exclusive lock for the life of the process, and wiped on request.
//
// The state is opaque here (in practice the vault client's Save output).
// It is encrypted with XChaCha20-Poly1305 under a random 256-bit data
// key; the data key is wrapped by a Protector, whose name and wrapped
// key are in the file's header. The format is in format.go and
// docs/STATE-FILE.md.
//
// This package never logs. Its errors name the check that failed, never
// the data: no keys, wrapped keys, nonces or state bytes.
//
// In-memory keys are cleared when no longer needed, as far as Go
// allows: the runtime may have copied them (garbage collection, stack
// growth) and those copies cannot be reached to clear. This is best
// effort, not a guarantee.
package state

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Protector wraps and unwraps the data key. Implementations are in
// internal/protect (passphrase, TPM, Keychain, DPAPI; AGENT-PLAN §3.1).
//
// Errors from Wrap, Unwrap and Wipe name the check that failed and never
// contain key material, the wrapped key, or a secret the protector was
// given (a passphrase).
type Protector interface {
	// Name is the protector's name in the header: lower case letters,
	// digits and '-', at most 32 characters, starting with a letter.
	Name() string
	// Wrap returns dataKey wrapped. It does not keep dataKey.
	Wrap(dataKey []byte) (wrapped []byte, err error)
	// Unwrap returns the data key from a value Wrap returned. A value
	// that was not made by this protector (or under its key) is an
	// error.
	Unwrap(wrapped []byte) (dataKey []byte, err error)
	// Wipe destroys the protector's own key (a TPM object, a Keychain
	// item), if it has one, so that wrapped values can no longer be
	// unwrapped. A protector with no key of its own returns nil.
	Wipe() error
}

// Resolver returns the protector for a header's protector name, or nil
// if the name is unknown.
type Resolver func(name string) Protector

// File names inside the state directory.
const (
	StateFileName = "vettid-agent.state"
	LockFileName  = "vettid-agent.lock"
	tempPrefix    = "." + StateFileName + "."
	tempSuffix    = ".tmp"
)

var (
	// ErrInUse: another process holds the state directory's lock.
	ErrInUse = errors.New("state directory is in use by another agent app")
	// ErrNotFound: there is no state file (not paired).
	ErrNotFound = errors.New("no state file")
	// ErrFormat: the file does not have the state file format. The
	// error is a *FormatError naming the check.
	ErrFormat = errors.New("state file format")
	// ErrUnknownProtector: the header names a protector this build does
	// not know.
	ErrUnknownProtector = errors.New("state file names an unknown protector")
	// ErrUnwrap: the protector could not unwrap the data key.
	ErrUnwrap = errors.New("the protector could not unwrap the state file's key")
	// ErrDecrypt: the state did not decrypt under the data key: the
	// wrong key, or the file or its header was altered.
	ErrDecrypt = errors.New("state file does not decrypt (wrong key, or the file was altered)")
	// ErrNotOwnerOnly: the state directory or file is accessible to
	// someone other than the current user, or owned by someone else.
	ErrNotOwnerOnly = errors.New("state is not private to the current user")
	// ErrNotLoaded: Save before Create or Load.
	ErrNotLoaded = errors.New("state: Save before Create or Load")
	// ErrClosed: the store was closed.
	ErrClosed = errors.New("state: store is closed")
)

// Store is one state directory, locked by this process from Open until
// Close. It is not safe for concurrent use by several goroutines.
type Store struct {
	dir  string
	lock io.Closer

	// Set by Create or Load, used by Save.
	prot      Protector
	wrapped   []byte
	dataKey   []byte
	createdAt int64
}

// Open opens the state directory dir, creating it (and missing parents)
// readable by the current user only if it does not exist, checks that it
// is private to the current user, and takes its exclusive lock. A second
// Open of the same directory, in this process or another, fails with
// ErrInUse until Close.
func Open(dir string) (*Store, error) {
	if dir == "" {
		return nil, errors.New("state: empty state directory")
	}
	dir = filepath.Clean(dir)
	if err := mkdirOwnerOnly(dir); err != nil {
		return nil, err
	}
	if err := checkDir(dir); err != nil {
		return nil, err
	}
	lk, err := lockDir(filepath.Join(dir, LockFileName))
	if err != nil {
		return nil, err
	}
	s := &Store{dir: dir, lock: lk}
	// Temporary files left by a crash during a write hold an older
	// state; remove them now that this process owns the directory.
	if err := s.removeTemps(false); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

// Dir returns the state directory.
func (s *Store) Dir() string { return s.dir }

// Path returns the state file's path.
func (s *Store) Path() string { return filepath.Join(s.dir, StateFileName) }

// Close forgets the keys (best effort) and releases the lock.
func (s *Store) Close() error {
	s.forget()
	if s.lock == nil {
		return nil
	}
	err := s.lock.Close()
	s.lock = nil
	return err
}

func (s *Store) forget() {
	clear(s.dataKey)
	s.dataKey = nil
	s.wrapped = nil
	s.prot = nil
	s.createdAt = 0
}

// Exists reports whether a state file is present.
func (s *Store) Exists() (bool, error) {
	if s.lock == nil {
		return false, ErrClosed
	}
	_, err := os.Lstat(s.Path())
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, os.ErrNotExist):
		return false, nil
	default:
		return false, err
	}
}

// Create writes state under a new random data key wrapped by p,
// replacing any state file (AGENT-PLAN §4.2: a new data key at each
// pairing). Later Saves keep this data key.
func (s *Store) Create(p Protector, state []byte) error {
	if s.lock == nil {
		return ErrClosed
	}
	if p == nil || !protectorName.MatchString(p.Name()) {
		return errors.New("state: invalid protector")
	}
	key := make([]byte, DataKeyLen)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	wrapped, err := p.Wrap(key)
	if err != nil {
		clear(key)
		return fmt.Errorf("state: protector %s could not wrap the key: %w", p.Name(), err)
	}
	h := &header{V: Version, Protector: p.Name(), WrappedKey: wrapped, CreatedAt: time.Now().Unix()}
	if err := s.write(h, key, state); err != nil {
		clear(key)
		return err
	}
	s.forget()
	s.prot, s.wrapped, s.dataKey, s.createdAt = p, wrapped, key, h.CreatedAt
	return nil
}

// Save writes state under the data key of the last Create or Load, with
// a fresh nonce; the header's protector, wrapped key and created_at are
// unchanged.
func (s *Store) Save(state []byte) error {
	if s.lock == nil {
		return ErrClosed
	}
	if s.dataKey == nil {
		return ErrNotLoaded
	}
	h := &header{V: Version, Protector: s.prot.Name(), WrappedKey: s.wrapped, CreatedAt: s.createdAt}
	return s.write(h, s.dataKey, state)
}

func (s *Store) write(h *header, key, state []byte) error {
	h.Nonce = make([]byte, NonceLen)
	if _, err := rand.Read(h.Nonce); err != nil {
		return err
	}
	raw, err := encodeFile(h, key, state)
	if err != nil {
		return err
	}
	return writeAtomic(s.dir, s.Path(), raw)
}

// Load reads, checks and decrypts the state file. resolve maps the
// header's protector name to a Protector. Load refuses a state file or
// directory that is not private to the current user (ErrNotOwnerOnly),
// a missing file (ErrNotFound), a malformed one (ErrFormat), an unknown
// protector (ErrUnknownProtector), a key the protector cannot unwrap
// (ErrUnwrap) and a file that does not decrypt (ErrDecrypt).
func (s *Store) Load(resolve Resolver) ([]byte, error) {
	if s.lock == nil {
		return nil, ErrClosed
	}
	if err := checkDir(s.dir); err != nil {
		return nil, err
	}
	raw, err := readNoFollow(s.Path(), maxFileLen, true)
	if err != nil {
		return nil, err
	}
	pt, h, p, key, err := decodeFile(raw, resolve)
	if err != nil {
		return nil, err
	}
	s.forget()
	s.prot, s.wrapped, s.dataKey, s.createdAt = p, h.WrappedKey, key, h.CreatedAt
	return pt, nil
}

// Protector returns the protector of the last Create or Load, or nil.
func (s *Store) Protector() Protector { return s.prot }

// CreatedAt returns the header's created_at of the last Create or Load
// (the time of pairing), or the zero time.
func (s *Store) CreatedAt() time.Time {
	if s.createdAt == 0 {
		return time.Time{}
	}
	return time.Unix(s.createdAt, 0)
}

// Wipe destroys the state (AGENT-PLAN §4.2 "Wipe"; AG12): it overwrites
// the state file's bytes in place, syncs, deletes it, deletes temporary
// files left by an interrupted write, and calls the protector's Wipe.
// The protector is the one of the last Create or Load or, when the file
// was not opened (a forgotten passphrase), the one resolve returns for
// the header's name. Every step is attempted even when an earlier one
// fails; the errors are joined. A missing state file is not an error.
//
// Overwriting is best effort against recovery from the disk: journaling
// and copy-on-write file systems and SSD wear levelling can keep older
// copies. The protector's Wipe is what makes such copies unreadable
// where the protector has a key of its own.
func (s *Store) Wipe(resolve Resolver) error {
	if s.lock == nil {
		return ErrClosed
	}
	p := s.prot
	if p == nil && resolve != nil {
		// The header only names the protector; the file is being
		// destroyed, so its permissions are not checked here.
		if raw, err := readNoFollow(s.Path(), maxFileLen, false); err == nil {
			if hb, _, err := splitFile(raw); err == nil {
				if h, err := parseHeader(hb); err == nil {
					p = resolve(h.Protector)
				}
			}
		}
	}
	var errs []error
	if err := overwriteAndRemove(s.Path()); err != nil && !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, fmt.Errorf("state: wipe state file: %w", err))
	}
	if err := s.removeTemps(true); err != nil {
		errs = append(errs, err)
	}
	if err := syncDir(s.dir); err != nil {
		errs = append(errs, fmt.Errorf("state: sync state directory: %w", err))
	}
	if p != nil {
		if err := p.Wipe(); err != nil {
			errs = append(errs, fmt.Errorf("state: protector %s could not delete its key: %w", p.Name(), err))
		}
	}
	s.forget()
	return errors.Join(errs...)
}

// removeTemps deletes temporary state files, overwriting them first when
// overwrite is set.
func (s *Store) removeTemps(overwrite bool) error {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return err
	}
	var errs []error
	for _, e := range entries {
		n := e.Name()
		if !strings.HasPrefix(n, tempPrefix) || !strings.HasSuffix(n, tempSuffix) {
			continue
		}
		path := filepath.Join(s.dir, n)
		if overwrite {
			err = overwriteAndRemove(path)
		} else {
			err = os.Remove(path)
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Errorf("state: remove temporary file: %w", err))
		}
	}
	return errors.Join(errs...)
}

// testHookBeforeRename, when set (tests only), runs after the temporary
// file is written and synced and before it is renamed over the state
// file. An error stands for a crash at that point.
var testHookBeforeRename func(tmp string) error

// writeAtomic writes raw to path through a new owner-only temporary file
// in dir: write, sync the file, rename over path, sync dir. If any step
// fails, path is unchanged and the temporary file is removed.
func writeAtomic(dir, path string, raw []byte) error {
	f, tmp, err := createTemp(dir, tempPrefix, tempSuffix)
	if err != nil {
		return fmt.Errorf("state: create temporary file: %w", err)
	}
	fail := func(step string, err error) error {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("state: %s: %w", step, err)
	}
	if _, err := f.Write(raw); err != nil {
		return fail("write temporary file", err)
	}
	if err := f.Sync(); err != nil {
		return fail("sync temporary file", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("state: close temporary file: %w", err)
	}
	if testHookBeforeRename != nil {
		if err := testHookBeforeRename(tmp); err != nil {
			return err
		}
	}
	if err := renameReplace(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("state: replace state file: %w", err)
	}
	if err := syncDir(dir); err != nil {
		return fmt.Errorf("state: sync state directory: %w", err)
	}
	return nil
}

// overwriteAndRemove overwrites a file's bytes with zeros in place,
// syncs it and deletes it.
func overwriteAndRemove(path string) error {
	f, err := openForOverwrite(path)
	if err != nil {
		return err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	zeros := make([]byte, 64<<10)
	for left := fi.Size(); left > 0; {
		n := int64(len(zeros))
		if left < n {
			n = left
		}
		if _, err := f.Write(zeros[:n]); err != nil {
			f.Close()
			return err
		}
		left -= n
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Remove(path)
}

// readNoFollow opens path without following a symbolic link and reads at
// most max bytes. With check set it first checks that the file is a
// regular file with one link, private to the current user.
func readNoFollow(path string, max int64, check bool) ([]byte, error) {
	f, err := openPrivate(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	defer f.Close()
	if check {
		if err := checkFile(f); err != nil {
			return nil, err
		}
	}
	raw, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > max {
		return nil, formatErr("file too large")
	}
	return raw, nil
}

// notPrivate builds an ErrNotOwnerOnly naming what failed.
func notPrivate(what, check string) error {
	return fmt.Errorf("%w: %s %s", ErrNotOwnerOnly, what, check)
}
