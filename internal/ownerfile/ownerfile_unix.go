//go:build !windows

package ownerfile

import (
	"fmt"
	"os"
)

// WriteFile writes data to path with mode 0600.
func WriteFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0o600)
}

// MkdirAll creates dir and any missing parents with mode 0700.
func MkdirAll(dir string) error {
	return os.MkdirAll(dir, 0o700)
}

// Check returns an error if path is accessible to anyone but its owner.
func Check(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("has mode %o, expected 0600", perm)
	}
	return nil
}
