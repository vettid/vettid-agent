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
	"sync/atomic"
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
	// unwrapped. A protector with no key of its own, or whose key is
	// already gone, returns nil, so Wipe may be retried. After Wipe the
	// protector can Wrap again (a new pairing), making a new key if it
	// uses one.
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
	// ErrExists: Create found a state file; replacing one is
	// CreateReplace.
	ErrExists = errors.New("a state file already exists (this connector is paired); replacing it must be explicit")
	// ErrProtectorUnknown: the protector of the state file cannot be
	// determined, so its key may remain. WipeAll with every known
	// protector deletes it.
	ErrProtectorUnknown = errors.New("the state file's protector is not known, so its key may remain; wipe with every known protector")
	// ErrNothingToWipe: Wipe found no state file and nothing loaded.
	ErrNothingToWipe = errors.New("no state file: nothing to wipe (not paired)")
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
	openStores.Add(1)
	// Temporary files left by a crash during a write hold an older
	// state; overwrite and remove them now that this process owns the
	// directory.
	if err := s.removeTemps(); err != nil {
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
	openStores.Add(-1)
	return err
}

// openStores counts the Stores open in this process.
var openStores atomic.Int32

// OpenStores returns how many Stores this process has open. Secrets read
// from inherited file descriptors (protect.PassphraseSource) are read
// while it is 0, so that a descriptor number given on the command line
// can never name a Store's lock or state file.
func OpenStores() int { return int(openStores.Load()) }

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

// Create writes state under a new random data key wrapped by p
// (AGENT-PLAN §4.2: a new data key at each pairing). Later Saves keep
// this data key. If a state file (or anything else) is already at the
// state file's path, Create returns ErrExists and changes nothing:
// replacing a state file is CreateReplace.
func (s *Store) Create(p Protector, state []byte) error {
	if s.lock == nil {
		return ErrClosed
	}
	if err := checkProtector(p); err != nil {
		return err
	}
	exists, err := s.Exists()
	if err != nil {
		return err
	}
	if exists {
		return ErrExists
	}
	return s.create(p, state)
}

// CreateReplace is Create that destroys an existing state file instead
// of refusing it. In order:
//
//  1. The old protector's key is wiped (Protector.Wipe). The old
//     protector is the one of the last Create or Load or, when the file
//     was not opened, the one resolve returns for the old header's
//     name. If neither gives one, CreateReplace returns
//     ErrProtectorUnknown and changes nothing (WipeAll, then Create, is
//     the way out). If the wipe fails, nothing else is changed.
//  2. The old file is opened and held; the new state is written under a
//     new data key and renamed over the path.
//  3. The old file's bytes are overwritten with zeros through the held
//     descriptor and synced; closing it deletes it.
//
// p may be the old protector itself: a protector can wrap again after
// its Wipe.
func (s *Store) CreateReplace(p Protector, state []byte, resolve Resolver) error {
	if s.lock == nil {
		return ErrClosed
	}
	if err := checkProtector(p); err != nil {
		return err
	}
	exists, err := s.Exists()
	if err != nil {
		return err
	}
	if !exists {
		return s.create(p, state)
	}
	oldP := s.oldProtector(resolve)
	if oldP == nil {
		return ErrProtectorUnknown
	}
	// Decided before anything is wiped: whether this file system can
	// rename over a file this process holds open. If it cannot, the old
	// file is overwritten and closed before the new one is written.
	holdOld := canReplaceOpenFile(s.dir) && !testHookOverwriteFirst
	if err := oldP.Wipe(); err != nil {
		return fmt.Errorf("state: protector %s could not delete the old key; nothing was replaced: %w", oldP.Name(), err)
	}
	s.forget()
	old, err := openForOverwrite(s.Path())
	switch {
	case errors.Is(err, errNotRegular):
		old = nil // a link or other non-file: the rename replaces the name itself
	case err != nil:
		return fmt.Errorf("state: open the old state file: %w", err)
	}
	if old != nil && !holdOld {
		// The old key is already gone, so the old file cannot be opened
		// any more; overwrite it now and let the rename replace it.
		err := overwriteFile(old)
		old.Close()
		old = nil
		if err != nil {
			return fmt.Errorf("state: overwrite the old state file: %w", err)
		}
	}
	// create returns only after the new file is renamed into place and
	// flushed (file and directory), so the old bytes are overwritten
	// only once the new state is durable.
	if err := s.create(p, state); err != nil {
		if old != nil {
			old.Close()
		}
		return err
	}
	if old == nil {
		return nil
	}
	if err := overwriteFile(old); err != nil {
		old.Close()
		return fmt.Errorf("state: the new state is written, but overwriting the old file failed: %w", err)
	}
	return old.Close()
}

// testHookOverwriteFirst (tests only) makes CreateReplace take the order
// used where an open file cannot be renamed over.
var testHookOverwriteFirst bool

func checkProtector(p Protector) error {
	if p == nil || !protectorName.MatchString(p.Name()) {
		return errors.New("state: invalid protector")
	}
	return nil
}

func (s *Store) create(p Protector, state []byte) error {
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

// Wipe destroys the state (AGENT-PLAN §4.2 "Wipe"; AG12). In order:
//
//  1. The protector's key is wiped first (Protector.Wipe). The
//     protector is the one of the last Create or Load or, when the file
//     was not opened (a forgotten passphrase), the one resolve returns
//     for the header's name. If that wipe fails, Wipe returns the error
//     and keeps the state file, so that a retry finds the protector
//     again.
//  2. The state file's bytes are overwritten with zeros in place,
//     synced, and the file deleted; leftover temporary files are
//     treated the same way; the directory is synced. A symbolic link
//     (or other non-file) at a path is deleted itself, never followed.
//
// If no protector can be determined because the header is unreadable
// or zeroed, Wipe still deletes the files but returns
// ErrProtectorUnknown, because a protector key may remain: WipeAll with
// every known protector is the fallback. If there is no state file (and
// no temporary file) and nothing was loaded, there is nothing to wipe:
// Wipe changes nothing and returns ErrNothingToWipe, which callers such
// as `forget` report as "not paired" (a key left by some earlier
// pairing is not known here; WipeAll removes it). With a loaded
// protector and no file (the file was already deleted), Wipe deletes the
// protector's key and returns nil. Wipe never returns nil while a
// protector key may remain.
//
// Overwriting is best effort against recovery from the disk: journaling
// and copy-on-write file systems and SSD wear levelling can keep older
// copies. The protector's Wipe is what makes such copies unreadable
// where the protector has a key of its own.
func (s *Store) Wipe(resolve Resolver) error {
	if s.lock == nil {
		return ErrClosed
	}
	p := s.oldProtector(resolve)
	if p == nil {
		exists, err := s.Exists()
		if err != nil {
			return err
		}
		if !exists && !s.hasTemps() {
			return ErrNothingToWipe
		}
	}
	if p != nil {
		if err := p.Wipe(); err != nil {
			return fmt.Errorf("state: protector %s could not delete its key; the state file is kept so that the wipe can be retried: %w", p.Name(), err)
		}
	}
	errs := s.removeFiles()
	s.forget()
	if p == nil {
		errs = append([]error{ErrProtectorUnknown}, errs...)
	}
	return errors.Join(errs...)
}

// WipeAll is the fallback when the protector is not known: it asks every
// protector in ps to delete its key (a protector without a key present
// succeeds without doing anything; nil entries are skipped), then
// removes the state and temporary files as Wipe does, whatever the
// protectors answered. Every step is
// attempted; the errors are joined. It may be retried.
func (s *Store) WipeAll(ps []Protector) error {
	if s.lock == nil {
		return ErrClosed
	}
	var errs []error
	for _, p := range ps {
		if p == nil {
			continue
		}
		if err := p.Wipe(); err != nil {
			errs = append(errs, fmt.Errorf("state: protector %s could not delete its key: %w", p.Name(), err))
		}
	}
	errs = append(errs, s.removeFiles()...)
	s.forget()
	return errors.Join(errs...)
}

// oldProtector returns the protector of the last Create or Load or,
// failing that, the one resolve returns for the state file's header.
// The header only names the protector, and the file is about to be
// destroyed, so its permissions are not checked here.
func (s *Store) oldProtector(resolve Resolver) Protector {
	if s.prot != nil {
		return s.prot
	}
	if resolve == nil {
		return nil
	}
	raw, err := readNoFollow(s.Path(), maxFileLen, false)
	if err != nil {
		return nil
	}
	hb, _, err := splitFile(raw)
	if err != nil {
		return nil
	}
	h, err := parseHeader(hb)
	if err != nil {
		return nil
	}
	if p := resolve(h.Protector); p != nil && p.Name() == h.Protector {
		return p
	}
	return nil
}

// removeFiles overwrites and deletes the state file and leftover
// temporary files, and syncs the directory.
func (s *Store) removeFiles() []error {
	var errs []error
	if err := overwriteAndRemove(s.Path()); err != nil && !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, fmt.Errorf("state: wipe state file: %w", err))
	}
	if err := s.removeTemps(); err != nil {
		errs = append(errs, err)
	}
	if err := syncDir(s.dir); err != nil {
		errs = append(errs, fmt.Errorf("state: sync state directory: %w", err))
	}
	return errs
}

// hasTemps reports whether temporary state files are present.
func (s *Store) hasTemps() bool {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return true // unknown: let removeFiles try
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), tempPrefix) && strings.HasSuffix(e.Name(), tempSuffix) {
			return true
		}
	}
	return false
}

// removeTemps overwrites and deletes temporary state files.
func (s *Store) removeTemps() error {
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
		if err := overwriteAndRemove(filepath.Join(s.dir, n)); err != nil && !errors.Is(err, os.ErrNotExist) {
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

// errNotRegular: openForOverwrite found a symbolic link or another
// non-file at the path.
var errNotRegular = errors.New("not a regular file")

// overwriteAndRemove overwrites a file's bytes with zeros in place,
// syncs it and deletes it. A symbolic link or other non-file at the
// path is deleted itself, never followed or written.
func overwriteAndRemove(path string) error {
	f, err := openForOverwrite(path)
	if errors.Is(err, errNotRegular) {
		return os.Remove(path)
	}
	if err != nil {
		return err
	}
	if err := overwriteFile(f); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Remove(path)
}

// overwriteFile writes zeros over the whole of f from its start and
// syncs it.
func overwriteFile(f *os.File) error {
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	zeros := make([]byte, 64<<10)
	for left := fi.Size(); left > 0; {
		n := int64(len(zeros))
		if left < n {
			n = left
		}
		if _, err := f.Write(zeros[:n]); err != nil {
			return err
		}
		left -= n
	}
	return f.Sync()
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
