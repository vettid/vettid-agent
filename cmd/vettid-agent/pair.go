package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/term"

	"github.com/vettid/vettid-agent/internal/pairing"
	"github.com/vettid/vettid-agent/internal/protect"
	"github.com/vettid/vettid-agent/internal/state"
)

// Standard input for the code, replaced in tests.
var (
	codeIn         io.Reader = os.Stdin
	codeInTerminal           = func() bool { return term.IsTerminal(int(os.Stdin.Fd())) }
	// pairOptions lets tests adjust the pairing options (the HTTP client
	// and clock); nil in the binary.
	pairOptions func(*pairing.Options)
)

const pairUsage = `Usage: vettid-agent pair --state-dir DIR [flags] [CODE]

Pairs this connector with your vault as an agent. On your phone, open
Devices & agents and choose Pair an agent, then give the code it shows:
as CODE, or pasted when asked, or on standard input. A CODE on the
command line can be seen by other users of this computer while the
command runs; pasting it when asked avoids that.

Each MCP client gets its own state directory, and so its own pairing.

Flags:
`

func runPair(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("pair", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("state-dir", "", "the state `DIR`ectory for this MCP client's pairing (required)")
	name := fs.String("name", "", "the `NAME` your phone shows for this agent (default \"Agent on <host name>\")")
	usePass := fs.Bool("passphrase", false, "protect the keys with a passphrase (not bound to this computer) instead of the computer's TPM or DPAPI")
	restart := fs.Bool("restart", false, "discard what the state directory holds (an unfinished or completed pairing, or a file that does not open) and pair again")
	prot := &pairing.Protectors{}
	prot.Source.AddFlags(fs)
	fs.Usage = func() {
		fmt.Fprint(stderr, pairUsage)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *dir == "" || fs.NArg() > 1 {
		fs.Usage()
		return 2
	}
	prot.Passphrase = *usePass
	defer prot.Clear()
	// A passphrase from a descriptor is read before the state directory
	// is opened (protect.PassphraseSource).
	if prot.Source.FD >= 0 {
		pass, err := prot.Source.Read("", false)
		if err != nil {
			fmt.Fprintf(stderr, "vettid-agent pair: %v\n", err)
			return 1
		}
		prot.Pass = pass
	}
	store, err := state.Open(*dir)
	if err != nil {
		fmt.Fprintf(stderr, "vettid-agent pair: %v\n", err)
		return 1
	}
	defer store.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	code := func() (string, error) {
		if fs.NArg() == 1 {
			return fs.Arg(0), nil
		}
		fmt.Fprintln(stderr, pairing.TextStart)
		if codeInTerminal() {
			fmt.Fprint(stderr, "Code: ")
			line, err := bufio.NewReaderSize(codeIn, 4096).ReadString('\n')
			if err != nil && line == "" {
				return "", errors.New("no pairing code was given")
			}
			return line, nil
		}
		b, err := io.ReadAll(io.LimitReader(codeIn, pairing.MaxCodeInput+1))
		if err != nil {
			return "", errors.New("could not read the pairing code from standard input")
		}
		return string(b), nil
	}
	o := pairing.Options{
		Store:         store,
		Resolve:       prot.Resolve,
		ResolveErr:    prot.ResolveErr,
		AllProtectors: protect.All(),
		Protector:     prot.New,
		Code:          code,
		CodeGiven:     fs.NArg() == 1,
		Restart:       *restart,
		Name:          *name,
		Out:           stderr,
	}
	if pairOptions != nil {
		pairOptions(&o)
	}
	if err := pairing.Pair(ctx, o); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}
