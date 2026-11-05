//go:build !windows

package run

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// writable reports whether dir can be written by the connector's own user,
// or by its group or others. The same rule holds for a --run-path
// directory and for each of its parents: a writable parent lets its
// entries be renamed, the directory included.
func writable(dir string, _ bool) (bool, error) {
	fi, err := os.Stat(dir)
	if err != nil {
		return false, fmt.Errorf("can't be checked: %w", err)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return true, nil
	}
	return unix.Access(dir, unix.W_OK) == nil, nil
}
