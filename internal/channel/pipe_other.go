//go:build !windows && !linux

package channel

import (
	"context"
	"fmt"
	"os"
)

// The channel is built for Windows (A3.10a) and Linux (A5.6); the macOS
// end comes with card #15817. Until then the stub finds no service here.

// ServiceAccount is the account that must own pairing n's channel: none
// here.
func ServiceAccount(n string) string { return "" }

// ReadPipe answers ErrNoService: no channel is built for this system yet.
func ReadPipe(n string) (string, error) {
	if !ValidName(n) {
		return "", fmt.Errorf("%q is not a pairing's name: use 1 to 32 lowercase letters, digits or hyphens, starting with a letter or digit", n)
	}
	return "", fmt.Errorf("%w: the connector service is not built for this system yet", ErrNoService)
}

// Dial answers ErrNoService: no channel is built for this system yet.
func Dial(ctx context.Context, cfg DialConfig) (*os.File, error) {
	return nil, ErrNoService
}
