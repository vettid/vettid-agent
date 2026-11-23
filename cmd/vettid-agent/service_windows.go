//go:build windows

package main

// `vettid-agent service --name <n>`: the connector service of pairing n,
// as the service manager starts it (AGENT-PLAN §6 A3.10b;
// AGENT-SEPARATE-ACCOUNT §3, §5). It checks its own token first and
// refuses to run if it holds more than it should; then it reads the
// pairing's configuration, takes the channel's name and serves the
// member's stub, status and an administrator's pair and forget until
// it has been idle for a while, or the service manager stops it.

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"

	"github.com/vettid/vettid-agent/internal/channel"
	"github.com/vettid/vettid-agent/internal/pairing"
	"github.com/vettid/vettid-agent/internal/service"
)

// The service's exit codes beyond the self-check's (service.Code*),
// read by `status` from the service manager (chosen; not in the spec).
const (
	codeConfig    uint32 = 110 // the configuration file is missing or fails its check
	codePipeTaken uint32 = 111 // the channel's name is taken (AGENT-SEPARATE-ACCOUNT §4)
	codeChannel   uint32 = 112 // the channel or the state directory failed
)

// textServiceFromSCM answers `service` started from a command line.
const textServiceFromSCM = "vettid-agent service is started by Windows' service manager, as the installer sets it up; it can't be run from a command line."

// isWindowsService is replaced in tests.
var isWindowsService = svc.IsWindowsService

func runService(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("service", flag.ContinueOnError)
	fs.SetOutput(stderr)
	name := fs.String("name", "", "the `NAME` of the pairing")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: vettid-agent service --name NAME (started by the service manager only)")
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 || !channel.ValidName(*name) {
		fs.Usage()
		return 2
	}
	in, err := isWindowsService()
	if err != nil || !in {
		fmt.Fprintln(stderr, textServiceFromSCM)
		return 2
	}
	if err := svc.Run(channel.ServiceName(*name), &winService{name: *name}); err != nil {
		return 1
	}
	return 0
}

type winService struct{ name string }

// stateDir is pairing n's state directory, %ProgramData%\VettID\agent\<n>,
// from Windows' known folders (never the ProgramData variable).
func stateDir(n string) (string, error) {
	cfg, err := channel.ConfigPath(n)
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(cfg), n), nil
}

func (s *winService) Execute(_ []string, reqs <-chan svc.ChangeRequest, st chan<- svc.Status) (bool, uint32) {
	st <- svc.Status{State: svc.StartPending}
	name := channel.ServiceName(s.name)
	// The installer registers the event source (A5.5); without it the
	// entries are still written, with a generic description.
	elog, err := eventlog.Open(name)
	if err != nil {
		elog = nil
	}
	if elog != nil {
		defer elog.Close()
	}
	logger := slog.New(&eventLogHandler{elog: elog, name: s.name})
	fail := func(code uint32, text string) (bool, uint32) {
		logger.Error(text, "code", code)
		return true, code
	}
	if _, err := service.SelfCheck(s.name); err != nil {
		var ce *service.CheckError
		if errors.As(err, &ce) {
			return fail(ce.Code, "the service refuses to run: "+ce.Detail)
		}
		return fail(service.CodeTokenUnreadable, "the service refuses to run: "+err.Error())
	}
	cfg, err := channel.ReadServiceConfig(s.name)
	if err != nil {
		return fail(codeConfig, "the configuration: "+err.Error())
	}
	dir, err := stateDir(s.name)
	if err != nil {
		return fail(codeConfig, err.Error())
	}
	l, err := channel.Listen(channel.ListenConfig{
		Pipe: cfg.Pipe, Owner: channel.ServiceAccount(s.name), Member: cfg.Member, Version: readVersion().Version,
		OnRefused: func(op channel.Op, err error) {
			logger.Warn("a client was refused", "op", string(op), "why", err.Error())
		},
	})
	if errors.Is(err, channel.ErrNameTaken) {
		return fail(codePipeTaken, "the channel's name is taken by another account: "+err.Error())
	}
	if err != nil {
		return fail(codeChannel, "the channel: "+err.Error())
	}
	defer l.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stopped := make(chan struct{})
	defer close(stopped)
	go func() {
		for {
			select {
			case <-stopped:
				return
			case c := <-reqs:
				switch c.Cmd {
				case svc.Interrogate:
					st <- c.CurrentStatus
				case svc.Stop, svc.Shutdown:
					cancel()
				}
			}
		}
	}()
	st <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	logger.Info("started")
	h := &serviceHost{Dir: dir, AccessMinutes: cfg.AccessMinutes, Log: logger,
		IdleStop:   time.Duration(cfg.IdleStopSeconds) * time.Second,
		Protectors: &pairing.Protectors{NoPrompt: true, Dir: dir}}
	err = h.Serve(ctx, func(ctx context.Context) (*hostConn, error) {
		c, err := l.Accept(ctx)
		if err != nil {
			return nil, err
		}
		return &hostConn{rw: c, op: c.Op, accept: c.Accept, refuse: c.Refuse, close: c.Close}, nil
	})
	st <- svc.Status{State: svc.StopPending}
	switch {
	case errors.Is(err, errIdle):
		logger.Info("stopped: idle")
	case ctx.Err() != nil:
		logger.Info("stopped by the service manager")
	default:
		return fail(codeChannel, "stopped: "+err.Error())
	}
	return false, 0
}

// eventLogHandler writes the service's log to the Event Log under the
// pairing's name: the message and its attributes as text. The service's
// log carries ids, types, sizes and codes only (CLAUDE.md, Conventions;
// AGENT-SEPARATE-ACCOUNT §3 "Logs").
type eventLogHandler struct {
	elog  *eventlog.Log
	name  string
	attrs []slog.Attr
}

func (h *eventLogHandler) Enabled(_ context.Context, l slog.Level) bool { return l >= slog.LevelInfo }

func (h *eventLogHandler) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder
	fmt.Fprintf(&b, "pairing %s: %s", h.name, r.Message)
	add := func(a slog.Attr) bool {
		fmt.Fprintf(&b, " %s=%s", a.Key, a.Value.String())
		return true
	}
	for _, a := range h.attrs {
		add(a)
	}
	r.Attrs(add)
	if h.elog == nil {
		return nil
	}
	const eventID = 1
	switch {
	case r.Level >= slog.LevelError:
		return h.elog.Error(eventID, b.String())
	case r.Level >= slog.LevelWarn:
		return h.elog.Warning(eventID, b.String())
	default:
		return h.elog.Info(eventID, b.String())
	}
}

func (h *eventLogHandler) WithAttrs(as []slog.Attr) slog.Handler {
	return &eventLogHandler{elog: h.elog, name: h.name, attrs: append(append([]slog.Attr(nil), h.attrs...), as...)}
}

func (h *eventLogHandler) WithGroup(string) slog.Handler { return h }

func init() {
	stubStartService = startService
	stubServiceRefusal = serviceRefusal
}

// serviceRefusal: a *serviceRefusedError if pairing n's service is
// stopped with a code of its own, else nil (also when its state can't be
// read).
func serviceRefusal(n string) error {
	m, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return nil
	}
	defer windows.CloseServiceHandle(m)
	p, _ := windows.UTF16PtrFromString(channel.ServiceName(n))
	h, err := windows.OpenService(m, p, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return nil
	}
	defer windows.CloseServiceHandle(h)
	var ss windows.SERVICE_STATUS
	if windows.QueryServiceStatus(h, &ss) != nil || ss.CurrentState != windows.SERVICE_STOPPED ||
		ss.Win32ExitCode != uint32(windows.ERROR_SERVICE_SPECIFIC_ERROR) {
		return nil
	}
	return &serviceRefusedError{code: ss.ServiceSpecificExitCode}
}

// startWait bounds how long startService waits for the service to run.
const startWait = 20 * time.Second

// startService starts pairing n's service through the service manager,
// as the member may (the installer's access list grants the member
// SERVICE_START and SERVICE_QUERY_STATUS, A5.5), and waits until it runs
// or stops. A service that stopped with a code of its own is a
// *serviceRefusedError.
func startService(n string) error {
	m, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return fmt.Errorf("the service manager: %w", err)
	}
	defer windows.CloseServiceHandle(m)
	p, _ := windows.UTF16PtrFromString(channel.ServiceName(n))
	h, err := windows.OpenService(m, p, windows.SERVICE_START|windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return fmt.Errorf("the connector service %s: %w", channel.ServiceName(n), err)
	}
	defer windows.CloseServiceHandle(h)
	if err := windows.StartService(h, 0, nil); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
		return fmt.Errorf("starting the connector service: %w", err)
	}
	for end := time.Now().Add(startWait); ; time.Sleep(100 * time.Millisecond) {
		var ss windows.SERVICE_STATUS
		if err := windows.QueryServiceStatus(h, &ss); err != nil {
			return fmt.Errorf("the connector service's state: %w", err)
		}
		switch ss.CurrentState {
		case windows.SERVICE_RUNNING:
			return nil
		case windows.SERVICE_STOPPED:
			if ss.Win32ExitCode == uint32(windows.ERROR_SERVICE_SPECIFIC_ERROR) {
				return &serviceRefusedError{code: ss.ServiceSpecificExitCode}
			}
			if ss.Win32ExitCode != 0 {
				return fmt.Errorf("the connector service stopped: %w", windows.Errno(ss.Win32ExitCode))
			}
			// Started and already stopped again (idle): dial anyway.
			return nil
		}
		if time.Now().After(end) {
			return fmt.Errorf("the connector service did not start within %v", startWait)
		}
	}
}
