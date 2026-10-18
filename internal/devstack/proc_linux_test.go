//go:build devstack && linux

package devstack

import (
	"os/exec"
	"syscall"
)

// setStackAttrs starts the stack in a process group of its own, which
// Close signals as a whole, and makes it get SIGTERM (and so tear itself
// down) if the test process dies without stopping it, for example on a
// test timeout.
//
// Pdeathsig is tied to the thread that started the child, not to the
// process: the child gets the signal when that thread exits. startStack
// therefore starts the stack from a goroutine locked to its thread that
// stays locked until the stack is gone.
func setStackAttrs(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGTERM}
}
