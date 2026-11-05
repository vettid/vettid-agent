package state

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Per-run directories (AGENT-PLAN §4.9, "Run"). Each run gets
// <state dir>/run/<id>/ with:
//
//	tmp/     TMPDIR (POSIX) or TEMP and TMP (Windows)
//	work/    the default working directory
//	secret/  holds the secret file of the `file` way
//
// Every directory and the secret file are owner-only by the same helpers
// as the state directory (mode 0700 and 0600; on Windows the protected
// single-entry DACL). The secret file is overwritten before it is
// removed; run/ is emptied at every connector start by ClearRuns.

// RunDirName is the name of the directory under the state directory
// that holds the per-run directories.
const RunDirName = "run"

// MaxRunIDLen bounds the length of a run id.
const MaxRunIDLen = 64

// RunDirs names the directories of one run.
type RunDirs struct {
	ID     string
	Root   string // run/<id>
	Tmp    string // run/<id>/tmp
	Work   string // run/<id>/work
	Secret string // run/<id>/secret
}

// ErrBadRunID: the run id is empty, too long or has a character outside
// [0-9A-Za-z_-].
var ErrBadRunID = errors.New("state: invalid run id")

func validRunID(id string) bool {
	if id == "" || len(id) > MaxRunIDLen || reservedName(id) {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= '0' && c <= '9', c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}

func (s *Store) runRoot() string { return filepath.Join(s.dir, RunDirName) }

// checkRunRoot makes sure run/ exists as an owner-only directory (not a
// link) and returns its path.
func (s *Store) checkRunRoot() (string, error) {
	root := s.runRoot()
	if err := mkdirOwnerOnly(root); err != nil {
		return "", fmt.Errorf("state: run directory: %w", err)
	}
	if err := checkDir(root); err != nil {
		return "", err
	}
	return root, nil
}

// PrepareRun creates the owner-only directories of run id, which must
// not exist yet. On failure nothing is left behind.
func (s *Store) PrepareRun(id string) (RunDirs, error) {
	if !validRunID(id) {
		return RunDirs{}, ErrBadRunID
	}
	root, err := s.checkRunRoot()
	if err != nil {
		return RunDirs{}, err
	}
	d := RunDirs{ID: id, Root: filepath.Join(root, id)}
	d.Tmp = filepath.Join(d.Root, "tmp")
	d.Work = filepath.Join(d.Root, "work")
	d.Secret = filepath.Join(d.Root, "secret")
	if _, err := os.Lstat(d.Root); err == nil {
		return RunDirs{}, fmt.Errorf("state: run %s already exists", id)
	}
	for _, dir := range []string{d.Root, d.Tmp, d.Work, d.Secret} {
		if err := mkdirOwnerOnly(dir); err != nil {
			s.removeRunDir(d.Root)
			return RunDirs{}, fmt.Errorf("state: create run directory: %w", err)
		}
		if err := checkDir(dir); err != nil {
			s.removeRunDir(d.Root)
			return RunDirs{}, err
		}
	}
	return d, nil
}

// WriteRunSecret writes value to a new owner-only file in the run's
// secret directory and returns its path. The file is overwritten and
// removed by RemoveRun.
func (s *Store) WriteRunSecret(d RunDirs, value []byte) (string, error) {
	if !validRunID(d.ID) || d.Secret != filepath.Join(s.runRoot(), d.ID, "secret") {
		return "", ErrBadRunID
	}
	if err := checkDir(d.Secret); err != nil {
		return "", err
	}
	f, path, err := createTemp(d.Secret, "s-", "")
	if err != nil {
		return "", fmt.Errorf("state: create secret file: %w", err)
	}
	_, werr := f.Write(value)
	if werr == nil {
		werr = f.Sync()
	}
	cerr := f.Close()
	if werr == nil {
		werr = cerr
	}
	if werr != nil {
		overwriteAndRemove(path)
		return "", fmt.Errorf("state: write secret file: %w", werr)
	}
	return path, nil
}

// RemoveRun overwrites the run's secret files and removes run/<id>/.
// A run that does not exist is not an error. A failure is returned, so
// that the caller can say so; ClearRuns at the next start removes what
// is left.
func (s *Store) RemoveRun(id string) error {
	if !validRunID(id) {
		return ErrBadRunID
	}
	return s.removeRunDir(filepath.Join(s.runRoot(), id))
}

// ClearRuns removes everything under run/ (overwriting secret files
// first). The connector calls it at every start, so a crash leaves
// nothing past the next start. A missing run/ is not an error.
func (s *Store) ClearRuns() error {
	root := s.runRoot()
	fi, err := os.Lstat(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("state: run directory: %w", err)
	}
	if !fi.IsDir() { // a link or a file: delete it itself, never follow
		if err := os.Remove(root); err != nil {
			return fmt.Errorf("state: run directory: %w", err)
		}
		return nil
	}
	es, err := os.ReadDir(root)
	if err != nil {
		return fmt.Errorf("state: run directory: %w", err)
	}
	var errs []error
	for _, e := range es {
		if err := s.removeRunDir(filepath.Join(root, e.Name())); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// removeRunDir overwrites the files in dir/secret, then removes dir.
// Links are removed themselves, never followed.
func (s *Store) removeRunDir(dir string) error {
	fi, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var errs []error
	if fi.IsDir() {
		sec := filepath.Join(dir, "secret")
		if sfi, err := os.Lstat(sec); err == nil && sfi.IsDir() {
			es, err := os.ReadDir(sec)
			if err != nil {
				errs = append(errs, err)
			}
			for _, e := range es {
				if err := overwriteAndRemove(filepath.Join(sec, e.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
					errs = append(errs, err)
				}
			}
		}
	}
	if err := os.RemoveAll(dir); err != nil {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return fmt.Errorf("state: remove run directory: %w", errors.Join(errs...))
	}
	return nil
}

// reservedName: a Windows device name (CON, NUL, COM1, ...), which can't
// be a directory there; refused everywhere, so ids behave the same on
// every system.
func reservedName(id string) bool {
	u := strings.ToUpper(id)
	switch u {
	case "CON", "PRN", "AUX", "NUL":
		return true
	}
	if len(u) == 4 && (strings.HasPrefix(u, "COM") || strings.HasPrefix(u, "LPT")) && u[3] >= '1' && u[3] <= '9' {
		return true
	}
	return false
}
