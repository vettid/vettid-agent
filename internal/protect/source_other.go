//go:build !linux && !darwin && !windows

package protect

import (
	"errors"
	"os"
)

// checkPassphraseFile on other systems (not supported by the connector,
// AGENT-PLAN §2 AG4) checks only that the file is a regular file.
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
