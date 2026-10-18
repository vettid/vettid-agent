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

	"github.com/vettid/vettid-agent/internal/access"
	"github.com/vettid/vettid-agent/internal/leash"
	"github.com/vettid/vettid-agent/internal/pairing"
	"github.com/vettid/vettid-agent/internal/state"
	"github.com/vettid/vettid-agent/internal/vaultconn"
)

// Standard input of `mcp` and a hook for the connection's options,
// replaced in tests.
var (
	mcpIn      io.Reader = os.Stdin
	mcpOptions func(*vaultconn.Options)
	// mcpResolve replaces the protector resolver (tests' protector).
	mcpResolve state.Resolver
)

const mcpUsage = `Usage: vettid-agent mcp --state-dir DIR [--passphrase-fd N | --passphrase-file PATH]

Runs the connector for the MCP client that starts it, over standard
input and output, with the pairing in DIR. It stays connected to your
vault until the client closes standard input. Standard output carries
only MCP messages; notices go to standard error. (The MCP tools are not
available yet: this version keeps the vault connection and the grants only.)

Flags:
`

func runMCP(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("state-dir", "", "the state `DIR`ectory of this MCP client's pairing (required)")
	accessMinutes := fs.Int("access-minutes", 60, "how long an access session to ask your phone for, in `minutes` (1 to 1440)")
	verbose := fs.Bool("verbose", false, "log each message type and id to standard error")
	prot := &pairing.Protectors{NoPrompt: true}
	prot.Source.AddFlags(fs)
	fs.Usage = func() {
		fmt.Fprint(stderr, mcpUsage)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *dir == "" || fs.NArg() != 0 || *accessMinutes < 1 || *accessMinutes > 1440 {
		fs.Usage()
		return 2
	}
	fail := func(err error) int {
		fmt.Fprintf(stderr, "vettid-agent mcp: %v\n", err)
		return 1
	}
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
	// The access policy (AG8) sees each event and vault.status; it is
	// created once the connection exists (the callbacks run only in Run).
	var mgr *access.Manager
	grants := newGrants(rec, logger, func(code string, sentWith pairing.Access) { mgr.OnAnswer(code, sentWith) })
	o := vaultconn.Options{
		Store:   store,
		Resolve: resolve,
		Record:  rec,
		Out:     stderr,
		Log:     logger,
		OnEvent: func(ev vaultconn.Event) { mgr.OnEvent(ev) },
		OnStatus: func(oc string) {
			mgr.OnStatus(oc)
			grants.OnStatus(oc)
		},
		Grants: grants,
	}
	if mcpOptions != nil {
		mcpOptions(&o)
	}
	conn, err := vaultconn.New(o)
	if err != nil {
		return fail(err)
	}
	mgr = access.New(conn, *accessMinutes*60, nil)
	// Every grant must name this device (the client's device id); without
	// one nothing could be checked, so the connector does not run.
	if err := grants.Bind(conn); err != nil {
		return fail(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// The MCP client ends the session by closing standard input. The MCP
	// messages themselves are handled from A3.3 on; until then they are
	// read and dropped, and nothing is written to standard output.
	in := mcpIn
	go func() {
		_, _ = io.Copy(io.Discard, in)
		cancel()
	}()
	// A saved session that has not expired is checked once at start
	// (internal/access Start), through Run's goroutine.
	startDone := make(chan struct{})
	go func() {
		defer close(startDone)
		if err := mgr.Start(ctx); err != nil && ctx.Err() == nil {
			logger.Warn("access session check at start failed", "err", err)
		}
	}()
	// The grants' status statements are kept fresh (internal/leash Run).
	go grants.Run(ctx)
	err = conn.Run(ctx)
	// The check ends with Run (its request fails once Run stops); wait
	// for it, so that nothing writes to standard error after return.
	cancel()
	<-startDone
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
