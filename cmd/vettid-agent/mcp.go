package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/vettid/vettid-agent/internal/leash"
	"github.com/vettid/vettid-agent/internal/leash/request"
	"github.com/vettid/vettid-agent/internal/pairing"
	"github.com/vettid/vettid-agent/internal/state"
	"github.com/vettid/vettid-agent/internal/vaultconn"
)

// Standard input of `mcp` and a hook for the connection's options,
// replaced in tests.
var (
	mcpIn      io.Reader = os.Stdin
	mcpOptions func(*vaultconn.Options)
	// mcpRequestOptions adjusts the requests' options (tests' timings).
	mcpRequestOptions func(*request.Options)
	// mcpResolve replaces the protector resolver (tests' protector).
	mcpResolve state.Resolver
	// mcpSignals returns a context that ends on SIGINT or SIGTERM
	// (tests end it themselves).
	mcpSignals = func(ctx context.Context) (context.Context, context.CancelFunc) {
		return signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	}
	// mcpStopWait bounds each of the two waits for the MCP session to end
	// at shutdown (stopSession).
	mcpStopWait = 2 * time.Second
)

const mcpUsage = `Usage: vettid-agent mcp --state-dir DIR [--passphrase-fd N | --passphrase-file PATH]
       vettid-agent mcp --name NAME

Runs the connector as an MCP server for the MCP client that starts it,
over standard input and output, with the pairing in DIR. It offers the
LEASH tools (leash.list_available, leash.request_secret,
leash.execute_action, leash.check_status, leash.connection_info) and
stays connected to your vault until the client closes standard input.
Standard output carries only MCP messages; notices go to standard error.

With --name, the connector runs as a service in an account of its own,
installed by an administrator, and this command only passes the MCP
client's messages to that service and its answers back. It holds no
keys and no state.

Flags:
`

func runMCP(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	fs.SetOutput(stderr)
	name := fs.String("name", "", "the `NAME` of a pairing whose connector runs as a service in its own account (instead of --state-dir)")
	dir := fs.String("state-dir", "", "the state `DIR`ectory of this MCP client's pairing (required without --name)")
	accessMinutes := fs.Int("access-minutes", 60, "how long an access session to ask your phone for, in `minutes` (1 to 1440)")
	verbose := fs.Bool("verbose", false, "log each message type and id to standard error")
	prot := &pairing.Protectors{NoPrompt: true}
	prot.Source.AddFlags(fs)
	fs.Usage = func() {
		fmt.Fprint(stderr, mcpUsage)
		fs.PrintDefaults()
	}
	if nameGiven(args) && runFlagGiven(args) {
		fmt.Fprintf(stderr, "vettid-agent mcp: %s\n", TextStubRunFlags)
		return 2
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *name != "" {
		// The stub: the pairing's name and --verbose only.
		if code := onlyName(fs, "mcp", *name, stderr, 0, "verbose"); code != 0 {
			return code
		}
		return runStub(*name, *verbose, stdout, stderr)
	}
	if *dir == "" || fs.NArg() != 0 || *accessMinutes < 1 || *accessMinutes > 1440 {
		fs.Usage()
		return 2
	}
	fail := func(err error) int {
		fmt.Fprintf(stderr, "vettid-agent mcp: %v\n", err)
		return 1
	}
	prot.Dir = *dir
	defer prot.Clear()
	if prot.Source.FD >= 0 {
		pass, err := prot.Source.Read("", false)
		if err != nil {
			return fail(err)
		}
		prot.Pass = pass
	}
	store, err := state.Open(*dir)
	if err != nil {
		return fail(err)
	}
	defer store.Close()
	if ok, err := store.Exists(); err != nil {
		return fail(err)
	} else if !ok {
		return fail(vaultconn.ErrNotPaired)
	}
	resolve := state.Resolver(prot.Resolve)
	if mcpResolve != nil {
		resolve = mcpResolve
	}
	raw, err := store.Load(resolve)
	if err != nil {
		if rerr := prot.ResolveErr(); rerr != nil {
			err = rerr
		}
		return fail(fmt.Errorf("the state file cannot be opened: %w", err))
	}
	rec, err := pairing.DecodeRecord(raw)
	clear(raw)
	if err != nil {
		return fail(err)
	}
	if rec.Phase != pairing.PhasePaired {
		return fail(errors.New("the pairing is not finished: run `vettid-agent pair`"))
	}
	level := slog.LevelWarn
	if *verbose {
		level = slog.LevelInfo
	}
	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: level}))
	ctx, stop := mcpSignals(context.Background())
	defer stop()
	err = session{
		Store:         store,
		Resolve:       resolve,
		Record:        rec,
		AccessMinutes: *accessMinutes,
		Log:           logger,
		Notices:       stderr,
		In:            mcpIn,
		Out:           stdout,
	}.run(ctx)
	switch {
	case errors.Is(err, context.Canceled):
		return 0
	case errors.Is(err, vaultconn.ErrUnlinked), errors.Is(err, vaultconn.ErrRefused):
		// Run has told the operator.
		return 1
	default:
		return fail(err)
	}
}

// newGrants returns the LEASH grants kept for the paired record
// (internal/leash); Bind loads the saved ones and takes the device id
// from the vault client.
func newGrants(rec *pairing.Record, logger *slog.Logger, onAnswer func(string, pairing.Access)) *leash.Manager {
	var dev struct {
		Name    string `json:"name"`
		VaultID string `json:"vault_id"`
	}
	_ = json.Unmarshal(rec.Device, &dev)
	return leash.New(leash.Options{Saved: rec.Leash, VaultID: dev.VaultID, Name: dev.Name,
		OnAnswer: onAnswer, Log: logger})
}

// stopSession waits for the MCP session (serveDone) to end once its
// context has: its tool calls are cancelled, and it ends at once unless
// a write to standard output is blocked because the MCP client keeps
// standard output open but does not read it. Then, after mcpStopWait, a
// write deadline in the past makes that write fail where standard
// output supports deadlines (a pipe or socket the Go runtime polls; not
// a blocking pipe, which is what most MCP clients hand over). If the
// session still has not ended after mcpStopWait more, the connector
// stops without it: the blocked write is abandoned (the process exits
// right after), so a client that never reads cannot keep the connector
// running after a signal.
func stopSession(serveDone <-chan struct{}, stdout io.Writer, logger *slog.Logger) {
	t := time.NewTimer(mcpStopWait)
	defer t.Stop()
	select {
	case <-serveDone:
		return
	case <-t.C:
	}
	if f, ok := stdout.(*os.File); ok {
		_ = f.SetWriteDeadline(time.Now())
	}
	t.Reset(mcpStopWait)
	select {
	case <-serveDone:
	case <-t.C:
		logger.Warn("the MCP client does not read standard output; stopping without finishing the write")
	}
}
