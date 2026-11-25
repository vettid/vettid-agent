//go:build windows

package main

// A Modern Standby (S0 low power idle) sends a service none of the power
// events that end a sleep (PBT_APMRESUMEAUTOMATIC, PBT_APMRESUMESUSPEND),
// so Resumed is never called for it, and the clock check (internal/access)
// misses a short one: the unbiased interrupt time keeps counting through
// part of it. PowerRegisterSuspendResumeNotification would not help: it
// delivers the same PBT_APM* events. What a Modern Standby normally does is
// turn the console's display off as it begins and on as it ends, and a
// service can be told of that (GUID_CONSOLE_DISPLAY_STATE, through
// RegisterPowerSettingNotification with the service's status handle). So
// each change of the display's state is taken as a possible standby
// beginning or ending: the access session is checked with the vault, as
// after a resume. A display that only went off for its idle timeout costs
// the same one vault.status per change, nothing more.
//
// Not covered, where the clock check alone applies (the vault still
// enforces the session's own end): a standby during which the display
// does not change again after one vault.status has cleared the suspicion
// (no console display, Remote Desktop only, an agent working while the
// display is off); the stub's own session when it is not a service
// (`vettid-agent mcp --state-dir`); and the 15 s between the fallback's
// checks when the registration failed.
//
// This loads user32.dll into the service, for the registration only.
//
// The event's data (the new state) is not read: x/sys/windows/svc hands it
// to Execute after the service's control handler has returned, when
// Windows no longer promises it is there. Only this one setting is
// registered, so every power setting change is the display's.

import (
	"context"
	"log/slog"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// pbtPowerSettingChange is the power event of a registered power setting's
// change.
const pbtPowerSettingChange = 0x8013

// deviceNotifyServiceHandle: the recipient is a service status handle.
const deviceNotifyServiceHandle = 1

// guidConsoleDisplayState is GUID_CONSOLE_DISPLAY_STATE
// (6FE69556-704A-47A0-8F24-C28D936FDA47).
var guidConsoleDisplayState = windows.GUID{Data1: 0x6fe69556, Data2: 0x704a, Data3: 0x47a0,
	Data4: [8]byte{0x8f, 0x24, 0xc2, 0x8d, 0x93, 0x6f, 0xda, 0x47}}

var (
	user32                               = windows.NewLazySystemDLL("user32.dll")
	procRegisterPowerSettingNotification = user32.NewProc("RegisterPowerSettingNotification")
	procUnregisterPowerSettingNotif      = user32.NewProc("UnregisterPowerSettingNotification")
)

// registerDisplayNotice asks for the console display's state changes to
// be sent to the service with status handle h, as power events. It
// returns the function that ends that.
func registerDisplayNotice(h windows.Handle) (func(), error) {
	if err := procRegisterPowerSettingNotification.Find(); err != nil {
		return nil, err
	}
	r, _, err := procRegisterPowerSettingNotification.Call(uintptr(h),
		uintptr(unsafe.Pointer(&guidConsoleDisplayState)), deviceNotifyServiceHandle)
	if r == 0 {
		return nil, err
	}
	return func() { procUnregisterPowerSettingNotif.Call(r) }, nil
}

// unregisteredEvery is how often the session is made suspect while the
// display's state can't be followed: as often as the clock check looks
// (internal/access's clockEvery).
const unregisteredEvery = 15 * time.Second

// followDisplay registers for the display's state changes (register). If
// that fails it logs it once and, until ctx ends, calls suspect every
// every instead: a standby can't be ruled out, so the session is treated
// as if one may have happened. It returns the function that ends either.
func followDisplay(ctx context.Context, logger *slog.Logger, register func() (func(), error), suspect func(), every time.Duration) func() {
	end, err := register()
	if err == nil {
		return end
	}
	logger.Warn("the display's state can't be followed: the access session is checked with the vault every few seconds while it is used")
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				suspect()
			}
		}
	}()
	return func() { cancel(); <-done }
}
