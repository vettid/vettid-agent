//go:build devstack && unix && !linux

package devstack

import (
	"os/exec"
	"syscall"
)

// setStackAttrs starts the stack in a process group of its own, which
// Close signals as a whole. Without Pdeathsig, a stack left behind by a
// killed test process must be stopped by hand.
func setStackAttrs(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}
