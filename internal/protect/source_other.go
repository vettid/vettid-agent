//go:build !linux && !darwin

package protect

import (
	"errors"
	"os"
)

// checkPassphraseFile on systems without POSIX modes checks only that
// the file is a regular file. On Windows the file's DACL is not checked
// (AGENT-PLAN §6 A1.2 asks for the owner-only check on POSIX); keep the
// file in a directory only the current user can read.
func checkPassphraseFile(f *os.File) error {
	fi, err := f.Stat()
	if err != nil {
		return errors.New("cannot read the file's attributes")
	}
	if !fi.Mode().IsRegular() {
		return errors.New("not a regular file")
	}
	return nil
}

func openPassphraseFile(path string) (*os.File, error) { return os.Open(path) }
