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
