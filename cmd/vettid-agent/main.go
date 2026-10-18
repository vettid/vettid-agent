// Command vettid-agent is the VettID agent connector: an MCP server that
// runs next to an AI agent, paired with the member's vault as a device of
// role "agent" (VAULT-MESSAGING §6.7). It is being rebuilt; see
// https://github.com/vettid/vettid.org/blob/master/docs/AGENT-PLAN.md.
//
// This file holds flags and dispatch only (AGENT-PLAN §3.1).
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
)

// command is one subcommand. A nil run means the subcommand is planned
// but not yet available.
type command struct {
	name    string
	summary string
	run     func(args []string, stdout, stderr io.Writer) int
}

var commands = []command{
	{name: "pair", summary: "pair with your vault", run: runPair},
	{name: "mcp", summary: "run for an MCP client over standard input and output (vault connection only; tools not yet available)", run: runMCP},
	{name: "status", summary: "show the pairing and access state (not yet available)"},
	{name: "forget", summary: "delete this connector's keys and state (not yet available)"},
	{name: "version", summary: "print the version, commit and Go version", run: runVersion},
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run dispatches args to a subcommand and returns the process exit code:
// 0 on success, 1 on failure, 2 on a usage error.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	name := args[0]
	switch name {
	case "help", "-h", "-help", "--help":
		usage(stdout)
		return 0
	}
	for _, c := range commands {
		if c.name != name {
			continue
		}
		if c.run == nil {
			fmt.Fprintf(stderr, "vettid-agent %s: not yet available\n", name)
			return 2
		}
		return c.run(args[1:], stdout, stderr)
	}
	fmt.Fprintf(stderr, "vettid-agent: unknown command %q\n\n", name)
	usage(stderr)
	return 2
}

func usage(w io.Writer) {
	fmt.Fprint(w, `Usage: vettid-agent <command> [flags]

The VettID agent connector. It is being rebuilt; some commands are not
yet available.

Commands:
`)
	for _, c := range commands {
		fmt.Fprintf(w, "  %-8s  %s\n", c.name, c.summary)
	}
}

func runVersion(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: vettid-agent version")
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return 2
	}
	fmt.Fprint(stdout, readVersion().String())
	return 0
}
