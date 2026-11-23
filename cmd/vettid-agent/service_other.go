//go:build !windows

package main

import (
	"fmt"
	"io"
)

// runService: the connector service on Linux and macOS comes with their
// own rows (AGENT-PLAN A3.10, A5.6).
func runService(_ []string, _, stderr io.Writer) int {
	fmt.Fprintln(stderr, "vettid-agent service: not yet available on this system")
	return 2
}
