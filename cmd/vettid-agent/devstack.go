//go:build devstack

package main

// A devstack build (AGENT-PLAN §4.8) reaches vettid-vault's local dev
// stack when VETTID_AGENT_DEVSTACK names the stack's control port: `pair`
// and `mcp` then send relay requests to the stack's TLS front, trusting
// only its TEST TLS root (internal/devstack). Release builds never carry
// the tag, so this file and that package are not in them.

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/vettid/vettid-agent/internal/devstack"
	"github.com/vettid/vettid-agent/internal/pairing"
	"github.com/vettid/vettid-agent/internal/vaultconn"
)

// devstackClient is the dev stack's relay client for the running
// command, nil when VETTID_AGENT_DEVSTACK is not set.
var devstackClient *http.Client

func init() {
	for i, c := range commands {
		if c.name == "pair" || c.name == "mcp" {
			commands[i].run = withDevstack(c.name, c.run)
		}
	}
	pairOptions = func(o *pairing.Options) {
		if devstackClient != nil {
			o.HTTP = devstackClient
		}
	}
	mcpOptions = func(o *vaultconn.Options) {
		if devstackClient != nil {
			o.HTTP = devstackClient
		}
	}
}

// withDevstack resolves the dev stack's relay client before the command
// runs, so before the state directory is opened or a passphrase read: a
// stack that cannot be reached ends the command with exit code 1 before
// anything is opened, sent or saved.
func withDevstack(name string, run func(args []string, stdout, stderr io.Writer) int) func(args []string, stdout, stderr io.Writer) int {
	return func(args []string, stdout, stderr io.Writer) int {
		hc, err := devstack.FromEnv(context.Background())
		if err != nil {
			fmt.Fprintf(stderr, "vettid-agent %s (devstack build): %v\n", name, err)
			return 1
		}
		devstackClient = hc
		return run(args, stdout, stderr)
	}
}
