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
	"strings"
	"syscall"

	"golang.org/x/term"

	"github.com/vettid/vettid-agent/internal/channel"
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
       vettid-agent pair --name NAME [--label LABEL] [--restart] [CODE]

Pairs this connector with your vault as an agent. On your phone, open
Devices & agents and choose Pair an agent, then give the code it shows:
as CODE, or pasted when asked, or on standard input. A CODE on the
command line can be seen by other users of this computer while the
command runs; pasting it when asked avoids that.

Each MCP client gets its own state directory, and so its own pairing.

With --name, the pairing is that of a connector service in an account
of its own; it needs an administrator.

Flags:
`

func runPair(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("pair", flag.ContinueOnError)
	fs.SetOutput(stderr)
	name := fs.String("name", "", "the `NAME` of a pairing whose connector runs as a service (instead of --state-dir; needs an administrator)")
	dir := fs.String("state-dir", "", "the state `DIR`ectory for this MCP client's pairing (required without --name)")
	label := fs.String("label", "", "the `LABEL` your phone shows for this agent (default \"Agent on <host name>\")")
	usePass := fs.Bool("passphrase", false, "protect the keys with a passphrase (not bound to this computer) instead of the computer's TPM, Keychain or DPAPI")
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
	code := func() (string, error) { return readPairingCode(fs, stderr) }
	if *name != "" {
		if rc := onlyName(fs, "pair", *name, stderr, 1, "label", "restart"); rc != 0 {
			return rc
		}
		if *label != "" {
			if err := pairing.CheckName(*label); err != nil {
				fmt.Fprintf(stderr, "vettid-agent pair: --label: %v\n", err)
				return 1
			}
		}
		// The service pairs. This command reads the code first, before it
		// opens the channel: nothing is typed while the service holds a
		// stub's session off for it, and the service's request deadline
		// never meets a person still pasting. The code is sent once
		// (AGENT-PLAN §4.7: never stored or logged).
		c, err := code()
		if err == nil && strings.TrimSpace(c) == "" {
			err = errors.New("no pairing code was given")
		}
		if err != nil {
			fmt.Fprintf(stderr, "vettid-agent pair: %v\n", err)
			return 1
		}
		return runChannelCommand("pair", *name, channel.OpPair, func() (channel.Request, error) {
			return channel.Request{Code: c, Label: *label, Restart: *restart}, nil
		}, stderr, stderr)
	}
	if *dir == "" || fs.NArg() > 1 {
		fs.Usage()
		return 2
	}
	prot.Passphrase = *usePass
	prot.Dir = *dir
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
	o := pairing.Options{
		Store:         store,
		Resolve:       prot.Resolve,
		ResolveErr:    prot.ResolveErr,
		AllProtectors: protect.All(*dir),
		Protector:     prot.New,
		Code:          code,
		CodeGiven:     fs.NArg() == 1,
		// A resume does not read standard input; say so when it may
		// hold a code.
		CodeOnStdin:      fs.NArg() == 0 && !codeInTerminal(),
		PassphraseChosen: *usePass,
		Restart:          *restart,
		Name:             *label,
		Out:              stderr,
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

// readPairingCode reads the pairing code: CODE, or pasted at a prompt, or
// standard input.
func readPairingCode(fs *flag.FlagSet, stderr io.Writer) (string, error) {
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
