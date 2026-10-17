//go:build linux || darwin

package protect

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// checkPassphraseFile refuses a passphrase file that is not a regular
// file owned by the current user with no access for group or others.
func checkPassphraseFile(f *os.File) error {
	fi, err := f.Stat()
	if err != nil {
		return errors.New("cannot read the file's mode")
	}
	if !fi.Mode().IsRegular() {
		return errors.New("not a regular file")
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Geteuid()) {
		return errors.New("the file must be owned by the current user")
	}
	if m := fi.Mode().Perm(); m&0o077 != 0 {
		return fmt.Errorf("the file must be readable by its owner only (mode %04o; use chmod 600)", m)
	}
	return nil
}

// openPassphraseFile opens with O_NONBLOCK, so that a FIFO at the path
// opens at once (and checkPassphraseFile refuses it) instead of waiting
// for a writer.
func openPassphraseFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
}

// checkPassphraseFD accepts a pipe that belongs to the current user (a
// named FIFO also with mode 0600 or 0400), or a regular file that passes
// the same owner-only check as --passphrase-file.
func checkPassphraseFD(fd int) error {
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return errors.New("not an open file descriptor")
	}
	switch st.Mode & syscall.S_IFMT {
	case syscall.S_IFIFO:
		// Every pipe must belong to the current user. A named FIFO on
		// disk must also have no group or other permission bits (0600
		// or 0400): one that others can open could carry their
		// passphrase instead of the operator's. Anonymous pipes have no
		// name to reach them by.
		if st.Uid != uint32(os.Geteuid()) {
			return errors.New("the pipe must belong to the current user")
		}
		if m := os.FileMode(st.Mode).Perm(); m&0o077 != 0 && namedFIFO(fd) {
			return fmt.Errorf("the named FIFO must be readable and writable by its owner only (mode %04o; use mode 0600)", m)
		}
		return nil
	case syscall.S_IFREG:
		if st.Uid != uint32(os.Geteuid()) {
			return errors.New("the file must be owned by the current user")
		}
		if m := os.FileMode(st.Mode).Perm(); m&0o077 != 0 {
			return fmt.Errorf("the file must be readable by its owner only (mode %04o; use chmod 600)", m)
		}
		return nil
	default:
		return errors.New("not a pipe or a regular file")
	}
}
