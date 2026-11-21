//go:build !windows

package channel

import (
	"context"
	"fmt"
	"os"
)

// The Unix socket end of the channel comes with AGENT-PLAN A5.6; until
// then the stub finds no service here.

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
