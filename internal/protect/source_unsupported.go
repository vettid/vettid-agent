//go:build !linux && !darwin && !windows

package protect

import "errors"

func checkPassphraseFD(int) error { return errors.New("not supported on this operating system") }
