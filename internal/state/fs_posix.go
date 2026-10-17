//go:build linux || darwin

package state

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// POSIX owner-only files: the state directory is mode 0700 and the
// state file mode 0600, both owned by the effective user. Modes are set
// explicitly after creation, so the umask cannot loosen or break them.

// mkdirOwnerOnly creates dir with mode 0700 if it does not exist.
// Missing parents are created with mode 0700 too. An existing directory
// is left as it is; checkDir decides whether it is acceptable.
func mkdirOwnerOnly(dir string) error {
	if fi, err := os.Lstat(dir); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return notPrivate("state directory", "is a symbolic link")
		}
		if !fi.IsDir() {
			return fmt.Errorf("state: %s is not a directory", dir)
		}
		return nil
	}
	if err := mkdirAll0700(filepath.Dir(dir)); err != nil {
		return fmt.Errorf("state: create parent directory: %w", err)
	}
	if err := mkdir0700(dir); err != nil {
		return fmt.Errorf("state: create state directory: %w", err)
	}
	return nil
}

// mkdir0700 creates dir with mode 0700 exactly. A directory that
// appeared meanwhile is left alone (checkDir decides).
func mkdir0700(dir string) error {
	if err := os.Mkdir(dir, 0o700); err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil
		}
		return err
	}
	return os.Chmod(dir, 0o700)
}

// mkdirAll0700 is os.MkdirAll with every new directory mode 0700
// exactly (os.MkdirAll leaves the mode to the umask, which can remove
// the owner's own write or search permission).
func mkdirAll0700(dir string) error {
	if fi, err := os.Stat(dir); err == nil {
		if !fi.IsDir() {
			return fmt.Errorf("%s is not a directory", dir)
		}
		return nil
	}
	if parent := filepath.Dir(dir); parent != dir {
		if err := mkdirAll0700(parent); err != nil {
			return err
		}
	}
	return mkdir0700(dir)
}

// checkOwnerMode is the owner-only rule: owned by euid, and no access
// for group or others.
func checkOwnerMode(what string, mode os.FileMode, uid, euid uint32) error {
	if uid != euid {
		return notPrivate(what, "is owned by another user")
	}
	if mode.Perm()&0o077 != 0 {
		return notPrivate(what, fmt.Sprintf("is accessible to group or others (mode %04o)", mode.Perm()))
	}
	return nil
}

func checkDir(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("state: state directory: %w", err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return notPrivate("state directory", "is a symbolic link")
	}
	if !fi.IsDir() {
		return fmt.Errorf("state: %s is not a directory", dir)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return notPrivate("state directory", "has no readable owner")
	}
	return checkOwnerMode("state directory", fi.Mode(), st.Uid, uint32(os.Geteuid()))
}

func checkFile(f *os.File) error {
	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("state: state file: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return notPrivate("state file", "is not a regular file")
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return notPrivate("state file", "has no readable owner")
	}
	if st.Nlink != 1 {
		return notPrivate("state file", "has more than one link")
	}
	return checkOwnerMode("state file", fi.Mode(), st.Uid, uint32(os.Geteuid()))
}

func openPrivate(path string) (*os.File, error) {
	// O_NONBLOCK: a FIFO planted at the path opens instead of hanging,
	// and checkFile then refuses it.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if errors.Is(err, syscall.ELOOP) {
		return nil, notPrivate("state file", "is a symbolic link")
	}
	return f, err
}

func openForOverwrite(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.EISDIR) || errors.Is(err, syscall.ENXIO) {
		// A symbolic link, a directory, or a FIFO without a reader.
		return nil, errNotRegular
	}
	if err != nil {
		return nil, err
	}
	if fi, serr := f.Stat(); serr != nil || !fi.Mode().IsRegular() {
		f.Close()
		return nil, errNotRegular
	}
	return f, nil
}

func createTemp(dir, prefix, suffix string) (*os.File, string, error) {
	var r [16]byte
	if _, err := rand.Read(r[:]); err != nil {
		return nil, "", err
	}
	name := filepath.Join(dir, prefix+hex.EncodeToString(r[:])+suffix)
	// O_EXCL with O_CREATE refuses anything already at the name,
	// a symbolic link included.
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, "", err
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		os.Remove(name)
		return nil, "", err
	}
	return f, name, nil
}

func renameReplace(from, to string) error { return os.Rename(from, to) }

// replaceOpenFileSupport: rename(2) replaces a name whose file is open.
func replaceOpenFileSupport(string) (bool, error) { return true, nil }

// flushRenamed: the file was synced before the rename; syncDir makes
// the new name durable.
func flushRenamed(string) error { return nil }

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	err = d.Sync()
	if errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOTSUP) {
		// The file system cannot sync a directory.
		return nil
	}
	return err
}

// lockDir takes an exclusive flock on the lock file, without waiting.
// The lock lasts until the returned Closer is closed or the process
// exits; the lock file itself stays.
func lockDir(path string) (io.Closer, error) {
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("state: open lock file: %w", err)
	}
	f := os.NewFile(uintptr(fd), path)
	if err := unix.Fchmod(fd, 0o600); err != nil {
		f.Close()
		return nil, fmt.Errorf("state: set lock file mode: %w", err)
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, ErrInUse
		}
		return nil, fmt.Errorf("state: lock: %w", err)
	}
	return f, nil
}

// flushRetries: a failed fsync is not retried on POSIX (see
// retryDurable).
const flushRetries = 0
