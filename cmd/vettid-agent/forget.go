package main

import (
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/vettid/vettid-agent/internal/channel"
)

const forgetUsage = `Usage: vettid-agent forget --name NAME

Deletes the keys and state of a pairing whose connector runs as a service
in an account of its own; it needs an administrator. For a connector
that runs in your own account, forget is not yet available.

Flags:
`

func runForget(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("forget", flag.ContinueOnError)
	fs.SetOutput(stderr)
	name := fs.String("name", "", "the `NAME` of a pairing whose connector runs as a service (needs an administrator)")
	fs.Usage = func() {
		fmt.Fprint(stderr, forgetUsage)
		fs.PrintDefaults()
	}
	if !nameGiven(args) {
		fmt.Fprintln(stderr, "vettid-agent forget: not yet available")
		return 2
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if rc := onlyName(fs, "forget", *name, stderr, 0); rc != 0 {
		return rc
	}
	return runChannelCommand("forget", *name, channel.OpForget, noRequest, stdout, stderr)
}
