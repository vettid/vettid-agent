//go:build windows

package protect

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"

	"github.com/vettid/vettid-agent/internal/state"
)

// checkPassphraseFD accepts an inherited handle to a pipe, or to a disk
// file that passes the state file's owner-only rule (owned by the
// current user, no access for anyone else; state.CheckOwnerOnlyHandle),
// and that is not one of the standard handles.
func checkPassphraseFD(fd int) error {
	h := windows.Handle(fd)
	for _, std := range []uint32{windows.STD_INPUT_HANDLE, windows.STD_OUTPUT_HANDLE, windows.STD_ERROR_HANDLE} {
		if s, err := windows.GetStdHandle(std); err == nil && s == h {
			return errors.New("standard input, output and error cannot be used; pass another handle")
		}
	}
	t, err := windows.GetFileType(h)
	if err != nil {
		return errors.New("not an open handle")
	}
	switch t {
	case windows.FILE_TYPE_PIPE:
		return nil
	case windows.FILE_TYPE_DISK:
		return ownerOnly(state.CheckOwnerOnlyHandle(h, "passphrase file"))
	default:
		return errors.New("not a pipe or a regular file")
	}
}

// checkPassphraseFile applies the same owner-only rule to a
// --passphrase-file.
func checkPassphraseFile(f *os.File) error {
	fi, err := f.Stat()
	if err != nil {
		return errors.New("cannot read the file's attributes")
	}
	if !fi.Mode().IsRegular() {
		return errors.New("not a regular file")
	}
	return ownerOnly(state.CheckOwnerOnlyHandle(windows.Handle(f.Fd()), "passphrase file"))
}

// ownerOnly adds the fix to a refusal.
func ownerOnly(err error) error {
	if err == nil || !errors.Is(err, state.ErrNotOwnerOnly) {
		return err
	}
	return errors.Join(err, errors.New(`the file must be readable by its owner only; for example: icacls <file> /inheritance:r /grant:r "%USERNAME%:F"`))
}

func openPassphraseFile(path string) (*os.File, error) { return os.Open(path) }
