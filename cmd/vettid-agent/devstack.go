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
	"net/http"
	"os"

	"github.com/vettid/vettid-agent/internal/devstack"
	"github.com/vettid/vettid-agent/internal/pairing"
	"github.com/vettid/vettid-agent/internal/vaultconn"
)

func init() {
	pairOptions = func(o *pairing.Options) {
		if hc := devstackHTTP(); hc != nil {
			o.HTTP = hc
		}
	}
	mcpOptions = func(o *vaultconn.Options) {
		if hc := devstackHTTP(); hc != nil {
			o.HTTP = hc
		}
	}
}

// devstackHTTP returns the dev stack's relay client, nil when
// VETTID_AGENT_DEVSTACK is not set; a stack that cannot be reached ends
// the command (before anything is sent, so before anything is saved).
func devstackHTTP() *http.Client {
	hc, err := devstack.FromEnv(context.Background())
	if err != nil {
		fmt.Fprintf(os.Stderr, "vettid-agent (devstack build): %v\n", err)
		os.Exit(1)
	}
	return hc
}
