//go:build devstack && !linux

package devstack

import "os/exec"

// setStackAttrs: elsewhere a stack left behind by a killed test process
// must be stopped by hand.
func setStackAttrs(*exec.Cmd) {}
