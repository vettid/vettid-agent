//go:build devstack && linux

package devstack

import (
	"os/exec"
	"syscall"
)

// setStackAttrs makes a stack this process started get SIGTERM (and so
// tear itself down) if the test process dies without stopping it, for
// example on a test timeout.
func setStackAttrs(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
}
