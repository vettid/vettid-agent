//go:build devstack && unix

package devstack

import (
	"os/exec"
	"syscall"
)

// signalGroup sends sig to the stack's process group (setStackAttrs:
// its pid is the group's id).
func signalGroup(cmd *exec.Cmd, sig syscall.Signal) error {
	return syscall.Kill(-cmd.Process.Pid, sig)
}

// groupAlive reports whether a process of the stack's group remains.
func groupAlive(cmd *exec.Cmd) bool {
	return syscall.Kill(-cmd.Process.Pid, 0) == nil
}
