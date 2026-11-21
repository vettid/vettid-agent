package main

// The stub and the channel's clients (AGENT-PLAN §6 A3.10a; AGENT-SEPARATE-ACCOUNT §2, §4):
// `vettid-agent mcp --name <n>` passes MCP messages between its standard
// input and output and the connector service's channel, unchanged; `pair`,
// `status` and `forget` with --name send their request and show the
// service's answer. None of them holds a key, a state file or a value, and
// the only thing they choose is the pairing, by its name: the channel's name
// comes from the configuration file only an administrator can change, and
// the service's identity from the pairing's name.

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"

	"github.com/vettid/vettid-agent/internal/channel"
	"github.com/vettid/vettid-agent/internal/leash/request"
	"github.com/vettid/vettid-agent/internal/mcp"
)

// The channel, replaced in tests.
var (
	stubReadPipe = channel.ReadPipe
	stubDial     = func(ctx context.Context, cfg channel.DialConfig) (io.ReadWriteCloser, error) {
		f, err := channel.Dial(ctx, cfg)
		if err != nil {
			return nil, err
		}
		return f, nil
	}
	// stubService is the SID the channel's owner must have.
	stubService = func(name string) string { return channel.ServiceSID(channel.ServiceName(name)) }
)

// TextStubRunFlags answers a stub given --run-path or --run-env (AGENT-PLAN
// §11, 0.1.16).
const TextStubRunFlags = "--run-path and --run-env are set in the connector service's configuration by an administrator, not on this command."

// TextNeedsAdmin answers `pair` or `forget` with --name run without
// elevation, which the service refuses (chosen; not in the spec).
const TextNeedsAdmin = "This needs an administrator: start it as an administrator, as the README says."

// TextNotThisAccount answers `status` or the stub run by an account the
// channel refuses (chosen; not in the spec).
const TextNotThisAccount = "This account can't use this pairing's connector service: it belongs to another user of this computer."

// dialService opens pairing name's channel for op.
func dialService(ctx context.Context, name string, op channel.Op) (io.ReadWriteCloser, error) {
	pipe, err := stubReadPipe(name)
	if err != nil {
		return nil, err
	}
	return stubDial(ctx, channel.DialConfig{Pipe: pipe, Service: stubService(name), Op: op, Version: readVersion().Version})
}

// runStub is `vettid-agent mcp --name <n>`.
func runStub(name string, verbose bool, stdout, stderr io.Writer) int {
	level := slog.LevelWarn
	if verbose {
		level = slog.LevelInfo
	}
	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: level}))
	ctx, stop := mcpSignals(context.Background())
	defer stop()
	conn, err := dialService(ctx, name, channel.OpMCP)
	switch {
	case err == nil:
	case errors.Is(err, channel.ErrInUse):
		fmt.Fprintf(stderr, "vettid-agent mcp: %v\n", err)
		return 1
	case errors.Is(err, channel.ErrVersionsDiffer):
		return serveUnavailable(ctx, mcp.VersionsDiffer(), err, logger, stdout, stderr)
	case errors.Is(err, channel.ErrNotAllowed):
		fmt.Fprintf(stderr, "vettid-agent mcp: %s\n", TextNotThisAccount)
		return serveUnavailable(ctx, mcp.NoService(), err, logger, stdout, stderr)
	default:
		// No channel, a configuration file that fails its check, or a
		// channel that isn't the service's: "No service". The connector
		// never runs in this process instead.
		return serveUnavailable(ctx, mcp.NoService(), err, logger, stdout, stderr)
	}
	return pump(ctx, conn, mcpIn, stdout, stderr)
}

// serveUnavailable answers the MCP client itself: the usual tools, each
// answered with e. The text goes to standard error once, with why.
func serveUnavailable(ctx context.Context, e *request.Error, why error, logger *slog.Logger, stdout, stderr io.Writer) int {
	fmt.Fprintf(stderr, "vettid-agent mcp: %s (%v)\n", e.Text, why)
	srv := mcp.New(mcp.Options{Unavailable: e, Version: readVersion().Version, Log: logger})
	if err := srv.Serve(ctx, mcpIn, stdout); err != nil && ctx.Err() == nil {
		logger.Warn("MCP input failed", "err", "read error")
	}
	return 1
}

// pump copies the MCP client's messages to the service and the service's
// to the client, unchanged, until the client closes standard input (the
// stub then closes the channel and exits 0), the service closes the
// channel (exit 1), or a signal.
func pump(ctx context.Context, conn io.ReadWriteCloser, in io.Reader, out, stderr io.Writer) int {
	defer conn.Close()
	inDone := make(chan struct{})
	outDone := make(chan error, 1)
	go func() {
		_, _ = io.Copy(conn, in)
		close(inDone)
	}()
	go func() {
		_, err := io.Copy(out, conn)
		outDone <- err
	}()
	select {
	case <-inDone:
		return 0
	case <-ctx.Done():
		return 0
	case err := <-outDone:
		if err != nil {
			fmt.Fprintf(stderr, "vettid-agent mcp: the connector service's channel failed: %v\n", err)
		} else {
			fmt.Fprintln(stderr, "vettid-agent mcp: the connector service closed the channel")
		}
		return 1
	}
}

// runChannelCommand is `pair`, `status` or `forget` with --name: it opens
// the channel, then sends the request req builds (pair reads the code
// only once the service has answered), and shows the service's answer on
// out, returning the service's exit code.
func runChannelCommand(cmd, name string, op channel.Op, req func() (channel.Request, error), out, stderr io.Writer) int {
	fail := func(text string) int {
		fmt.Fprintf(stderr, "vettid-agent %s: %s\n", cmd, text)
		return 1
	}
	ctx, stop := mcpSignals(context.Background())
	defer stop()
	conn, err := dialService(ctx, name, op)
	switch {
	case err == nil:
	case errors.Is(err, channel.ErrVersionsDiffer):
		return fail(mcp.TextVersionsDiffer)
	case errors.Is(err, channel.ErrNotAllowed) && (op == channel.OpPair || op == channel.OpForget):
		return fail(TextNeedsAdmin)
	case errors.Is(err, channel.ErrNotAllowed):
		return fail(TextNotThisAccount)
	case errors.Is(err, channel.ErrInUse):
		return fail(err.Error())
	default:
		fmt.Fprintf(stderr, "vettid-agent %s: %s (%v)\n", cmd, mcp.NoService().Text, err)
		return 1
	}
	defer conn.Close()
	r, err := req()
	if err != nil {
		return fail(err.Error())
	}
	if err := channel.SendRequest(conn, r); err != nil {
		return fail(fmt.Sprintf("the connector service's channel failed: %v", err))
	}
	code, err := channel.Relay(conn, out)
	if err != nil {
		return fail(err.Error())
	}
	return code
}

// textBadName answers a pairing's name that isn't valid.
const textBadName = "--name: a pairing's name is 1 to 32 lowercase letters, digits or hyphens, starting with a letter or digit."

// flagGiven reports whether args hold one of the flags named (as -f, --f,
// -f=v or --f=v), before any "--".
func flagGiven(args []string, names ...string) bool {
	for _, a := range args {
		if a == "--" {
			return false
		}
		f := strings.TrimLeft(a, "-")
		if len(f) == len(a) || len(a)-len(f) > 2 {
			continue
		}
		f, _, _ = strings.Cut(f, "=")
		for _, n := range names {
			if f == n {
				return true
			}
		}
	}
	return false
}

// runFlagGiven: --run-path or --run-env, which a stub refuses with its own
// text rather than as an unknown flag.
func runFlagGiven(args []string) bool { return flagGiven(args, "run-path", "run-env") }

func nameGiven(args []string) bool { return flagGiven(args, "name") }

// noRequest is the request of status and forget.
func noRequest() (channel.Request, error) { return channel.Request{}, nil }

// onlyName checks a command given --name: no flag but name and the ones
// allowed, at most maxArgs arguments, and a valid name. It returns 0, or
// the exit code once it said why.
func onlyName(fs *flag.FlagSet, cmd, name string, stderr io.Writer, maxArgs int, allowed ...string) int {
	other := ""
	fs.Visit(func(f *flag.Flag) {
		if f.Name != "name" && !slices.Contains(allowed, f.Name) && other == "" {
			other = f.Name
		}
	})
	if other != "" {
		fmt.Fprintf(stderr, "vettid-agent %s: --%s can't be used with --name: the connector service has the pairing's settings\n", cmd, other)
		return 2
	}
	if fs.NArg() > maxArgs {
		fs.Usage()
		return 2
	}
	if !channel.ValidName(name) {
		fmt.Fprintf(stderr, "vettid-agent %s: %s\n", cmd, textBadName)
		return 2
	}
	return 0
}
