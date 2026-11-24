//go:build windows

package main

// A Modern Standby (S0 low power idle) sends a service none of the power
// events that end a sleep (PBT_APMRESUMEAUTOMATIC, PBT_APMRESUMESUSPEND),
// so Resumed is never called for it, and the clock check (internal/access)
// misses a short one: the unbiased interrupt time keeps counting through
// part of it. PowerRegisterSuspendResumeNotification would not help: it
// delivers the same PBT_APM* events. What a Modern Standby always does is
// turn the console's display off as it begins and on as it ends, and a
// service can be told of that (GUID_CONSOLE_DISPLAY_STATE, through
// RegisterPowerSettingNotification with the service's status handle). So
// the display coming on after it was off is taken as a possible wake: the
// access session is checked with the vault, as after a resume. A display
// that only went off for its idle timeout costs the same one vault.status,
// nothing more.

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// pbtPowerSettingChange is the power event that carries a power setting's
// new value (a POWERBROADCAST_SETTING).
const pbtPowerSettingChange = 0x8013

// deviceNotifyServiceHandle: the recipient is a service status handle.
const deviceNotifyServiceHandle = 1

// guidConsoleDisplayState is GUID_CONSOLE_DISPLAY_STATE
// (6FE69556-704A-47A0-8F24-C28D936FDA47); its value is a DWORD: 0 off,
// 1 on, 2 dimmed.
var guidConsoleDisplayState = windows.GUID{Data1: 0x6fe69556, Data2: 0x704a, Data3: 0x47a0,
	Data4: [8]byte{0x8f, 0x24, 0xc2, 0x8d, 0x93, 0x6f, 0xda, 0x47}}

const (
	displayOff = 0
	displayOn  = 1
)

// powerSetting is POWERBROADCAST_SETTING up to its data, which follows.
type powerSetting struct {
	Setting    windows.GUID
	DataLength uint32
	Data       [1]byte
}

// displayWatch follows the console's display state from the power events.
// It is used from one goroutine only.
type displayWatch struct{ off bool }

// event reports whether the power event of type t with data p (a
// POWERBROADCAST_SETTING, or nil) is the console's display coming on
// after it was off. A dimmed display neither starts nor ends an off spell.
func (w *displayWatch) event(t uint32, p unsafe.Pointer) bool {
	if t != pbtPowerSettingChange || p == nil {
		return false
	}
	s := (*powerSetting)(p)
	if s.Setting != guidConsoleDisplayState || s.DataLength < 4 {
		return false
	}
	switch *(*uint32)(unsafe.Pointer(&s.Data[0])) {
	case displayOff:
		w.off = true
	case displayOn:
		if w.off {
			w.off = false
			return true
		}
	}
	return false
}

// eventPointer is a power event's data (svc.ChangeRequest.EventData) as
// the pointer the service manager passed.
func eventPointer(d *uintptr) unsafe.Pointer { return *(*unsafe.Pointer)(unsafe.Pointer(d)) }

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
