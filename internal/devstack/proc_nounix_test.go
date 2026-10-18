//go:build devstack && !unix

package devstack

import (
	"os/exec"
	"syscall"
)

// setStackAttrs: without process groups here, a stack left behind by a
// killed test process must be stopped by hand.
func setStackAttrs(*exec.Cmd) {}

// signalGroup signals the stack's own process only.
func signalGroup(cmd *exec.Cmd, sig syscall.Signal) error {
	if sig == syscall.SIGKILL {
		return cmd.Process.Kill()
	}
	return cmd.Process.Signal(sig)
}

// groupAlive: no group to look at once the stack's process is gone.
func groupAlive(*exec.Cmd) bool { return false }
