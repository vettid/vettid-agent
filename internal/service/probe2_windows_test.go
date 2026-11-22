//go:build windows

package service

// AGENT-PLAN §6 A3.10b's second measurement, for the owner's decision B:
// the connector's virtual account holds SeChangeNotifyPrivilege only and
// starts runs through the secondary logon service. TestRunnerHopProbe
// registers that service (cut to SeChangeNotifyPrivilege, nothing
// granted) and measures, with every outcome checked (probe2Expect):
//
//  1. The launcher hop: the service starts a launcher as the runner with
//     CreateProcessWithLogonW (no profile, its own window station and
//     desktop, suspended, a kill-on-close job, then resumed). The
//     launcher makes a restricted token from its own (every privilege
//     but SeChangeNotifyPrivilege removed; INTERACTIVE deny-only, and in
//     a second run LOCAL too) and starts the program with
//     CreateProcessAsUser, suspended, with only its standard handles
//     (PROC_THREAD_ATTRIBUTE_HANDLE_LIST). The program reads back its own
//     token's groups and privileges.
//  2. The image check: the launcher reads its suspended child's image
//     name; the service finds the program in the job's process list and
//     tries to open it with PROCESS_QUERY_LIMITED_INFORMATION.
//  3. Window station and desktop: whether the service can make a window
//     station of its own and a desktop in it for the runner; a program
//     that loads user32 there, under the job's UI limits.
//  4. DCOM: a throwaway class whose AppID runs as the Interactive User
//     and lets only INTERACTIVE launch it; a program with INTERACTIVE
//     deny-only, and one with it enabled.
//  5. Inheritance: an inheritable handle open in the service while the
//     launcher starts, and one in the launcher while the program starts.
//  6. B's runner shape: RDP and network logon denied, no batch right,
//     interactive logon granted explicitly, a password that never
//     expires; and the errors with that grant removed, with interactive
//     logon denied, with the password to be changed, and with the
//     secondary logon service disabled.
//
// It runs only with VETTID_AGENT_TEST_OTHER_USER=1 and removes what it
// made (the virtual account's profile excepted, as in
// TestServiceAccountProbe).

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/vettid/vettid-agent/internal/channel"
)

var (
	moduser32                    = windows.NewLazySystemDLL("user32.dll")
	procCreateWindowStationW     = moduser32.NewProc("CreateWindowStationW")
	procCreateDesktopW           = moduser32.NewProc("CreateDesktopW")
	procSetProcessWindowStation  = moduser32.NewProc("SetProcessWindowStation")
	procGetProcessWindowStation  = moduser32.NewProc("GetProcessWindowStation")
	procCloseWindowStation       = moduser32.NewProc("CloseWindowStation")
	procCloseDesktop             = moduser32.NewProc("CloseDesktop")
	procGetThreadDesktop         = moduser32.NewProc("GetThreadDesktop")
	procGetUserObjectInformation = moduser32.NewProc("GetUserObjectInformationW")
	procMessageBeep              = moduser32.NewProc("MessageBeep")
	procGetHandleInformation     = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetHandleInformation")
	procCreateRestrictedToken2   = modadvapi32.NewProc("CreateRestrictedToken")
	procCoCreateInstance         = windows.NewLazySystemDLL("ole32.dll").NewProc("CoCreateInstance")
	procSwitchDesktop            = moduser32.NewProc("SwitchDesktop")
	procOpenDesktopW             = moduser32.NewProc("OpenDesktopW")
	procExitWindowsEx            = moduser32.NewProc("ExitWindowsEx")
	procGlobalAddAtomW           = windows.NewLazySystemDLL("kernel32.dll").NewProc("GlobalAddAtomW")
	procGlobalFindAtomW          = windows.NewLazySystemDLL("kernel32.dll").NewProc("GlobalFindAtomW")
	procGlobalDeleteAtom         = windows.NewLazySystemDLL("kernel32.dll").NewProc("GlobalDeleteAtom")
	procIsProcessInJob           = windows.NewLazySystemDLL("kernel32.dll").NewProc("IsProcessInJob")
	procGetProcessIdOfThread     = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetProcessIdOfThread")
)

// The children's flags.
var (
	p2Mode     = flag.String("p2-mode", "", "probe2 child: launcher, program, user32, dcom, wait")
	p2Out      = flag.String("p2-out", "", "probe2 child: where to write its record")
	p2Exe      = flag.String("p2-exe", "", "probe2 launcher: the program to start")
	p2Restrict = flag.String("p2-restrict", "", "probe2 launcher: interactive, interactive+local")
	p2Sentinel = flag.Uint64("p2-sentinel", 0, "probe2 child: a handle value to check for")
	p2CLSID    = flag.String("p2-clsid", "", "probe2 dcom: the class to activate")
	p2Tools    = flag.String("p2-tools", "", "probe2 launcher: a JSON file of tools to start")
	p2Quick    = flag.Bool("p2-quick", false, "probe2 launcher: check user32 only, in itself and one restricted child")
	p2Target   = flag.Uint64("p2-target", 0, "probe2 openlauncher: the launcher's process id")
	p2Delay    = flag.Duration("p2-delay", 0, "probe2 openlauncher: wait this long first")
	p2Exit     = flag.Bool("p2-exit-after", false, "probe2 launcher: start the openlauncher program and exit right after resuming it")
	p2SvcSID   = flag.String("p2-svcsid", "", "probe2 launcher: give the service this access in the program's default DACL")
	p2Thread   = flag.Uint64("p2-thread", 0, "probe2 openlauncher: a thread id of the launcher's")
	p2Handoff  = flag.Bool("p2-handoff", false, "probe2 launcher: start the program suspended, hand it to the service and exit")
	p2UI       = flag.Bool("p2-ui-limits", false, "probe2 launcher: the job has UI limits (the uilimits child then also tries ExitWindowsEx)")
	p2AtomA    = flag.String("p2-atom-a", "", "probe2 uilimits: a global atom the service added, to look for")
	p2AtomB    = flag.String("p2-atom-b", "", "probe2 uilimits: a global atom to add, for the service to look for")
	p2ExitWin  = flag.Bool("p2-exitwindows", false, "probe2 uilimits: also try ExitWindowsEx")
	p2LockTok  = flag.Bool("p2-lock-token", false, "probe2 launcher, handoff: lock its own token and process with OWNER RIGHTS DACLs first")
	p2Created  = flag.Uint64("p2-target-created", 0, "probe2 openlauncher: the launcher's creation time, to tell it from a process that reuses its id")
	p2Detach   = flag.Bool("p2-detached", false, "probe2 launcher, handoff: start the program DETACHED_PROCESS (no console) with pipes for its output")
)

// tokenFacts is what a process reads of its own token.
type tokenFacts struct {
	User        string   `json:"user"`
	Interactive string   `json:"interactive"` // "enabled", "deny-only", "absent"
	Local       string   `json:"local"`
	Batch       string   `json:"batch"`
	Privileges  []string `json:"privileges"`
	Integrity   uint32   `json:"integrity"`
}

func groupState(groups *windows.Tokengroups, sid string) string {
	for _, g := range groups.AllGroups() {
		if g.Sid.String() == sid {
			switch {
			case g.Attributes&windows.SE_GROUP_USE_FOR_DENY_ONLY != 0:
				return "deny-only"
			case g.Attributes&windows.SE_GROUP_ENABLED != 0:
				return "enabled"
			default:
				return fmt.Sprintf("attributes %#x", g.Attributes)
			}
		}
	}
	return "absent"
}

func readTokenFacts(tok windows.Token) tokenFacts {
	var f tokenFacts
	if u, err := tok.GetTokenUser(); err == nil {
		f.User = u.User.Sid.String()
	}
	if g, err := tok.GetTokenGroups(); err == nil {
		f.Interactive = groupState(g, "S-1-5-4")
		f.Local = groupState(g, "S-1-2-0")
		f.Batch = groupState(g, "S-1-5-3")
	}
	f.Privileges = tokenPrivileges(tok)
	buf := make([]byte, 128)
	var n uint32
	if windows.GetTokenInformation(tok, windows.TokenIntegrityLevel, &buf[0], uint32(len(buf)), &n) == nil {
		l := (*windows.Tokenmandatorylabel)(unsafe.Pointer(&buf[0]))
		if c := l.Label.Sid.SubAuthorityCount(); c > 0 {
			f.Integrity = l.Label.Sid.SubAuthority(uint32(c - 1))
		}
	}
	return f
}

// handleHeld: v names an event this process holds (the sentinels are
// signaled events).
func handleHeld(v uint64) bool {
	if v == 0 {
		return false
	}
	var flags uint32
	if r, _, _ := procGetHandleInformation.Call(uintptr(v), uintptr(unsafe.Pointer(&flags))); r == 0 {
		return false
	}
	ev, err := windows.WaitForSingleObject(windows.Handle(v), 0)
	return err == nil && ev == windows.WAIT_OBJECT_0
}

// programRecord is what a program (or the user32 and dcom children)
// writes.
type programRecord struct {
	Token            tokenFacts        `json:"token"`
	SentinelInherits bool              `json:"launcher_sentinel_inherited"`
	Desktop          string            `json:"desktop,omitempty"`
	Beep             string            `json:"beep,omitempty"`
	DCOM             string            `json:"dcom,omitempty"`
	DCOMs            map[string]string `json:"dcoms,omitempty"`
	OpenLauncher     map[string]string `json:"open_launcher,omitempty"` // right: "ok" or the error
	LauncherRunning  string            `json:"launcher_running,omitempty"`
	// LauncherTokenInteractive: INTERACTIVE in the launcher's token, as
	// read through a handle the program opened.
	LauncherTokenInteractive string            `json:"launcher_token_interactive,omitempty"`
	UI                       map[string]string `json:"ui,omitempty"` // uilimits: call: "ok" or the error
	// TargetIdentity: whether the id opened is still the launcher's
	// ("launcher", "gone: …", "reused: …").
	TargetIdentity string `json:"target_identity,omitempty"`
	// JobProcs: every other process in the program's own job, as the
	// program can reach it.
	JobProcs map[uint32]reachable  `json:"job_procs,omitempty"`
	SelfPID  uint32                `json:"self_pid,omitempty"`
	Extra    map[uint32]extraReach `json:"extra,omitempty"`
}

// childStart is one program the launcher started.
type childStart struct {
	Start     string        `json:"start"`
	Errno     uint32        `json:"errno,omitempty"`
	ImageName string        `json:"image_name"` // read by the launcher while suspended
	Exit      string        `json:"exit"`
	Record    programRecord `json:"record"`
	Output    string        `json:"output,omitempty"` // what it wrote, when it wrote no record
	PID       uint32        `json:"pid,omitempty"`
}

// launcherRecord is what the launcher writes.
type launcherRecord struct {
	Token           tokenFacts `json:"token"`
	ServiceSentinel bool       `json:"service_sentinel_inherited"`
	// LogonSID is the runner's logon SID (S-1-5-5-…), which the service
	// compares with the window station's access list.
	LogonSID string `json:"logon_sid"`
	// Tools are real programs started as the run's program would be.
	Tools            map[string]childStart `json:"tools,omitempty"`
	LauncherUser32   string                `json:"launcher_user32"`
	DefaultDACL      string                `json:"default_dacl,omitempty"`
	LauncherDACL     string                `json:"launcher_dacl,omitempty"`
	ChildRecordPath  string                `json:"child_record_path,omitempty"`
	Restricted       string                `json:"restricted_token"`
	RestrictedFacts  tokenFacts            `json:"restricted_facts"`
	Children         map[string]childStart `json:"children"` // program, user32, dcom, dcom-unrestricted
	WaitingPID       uint32                `json:"waiting_pid"`
	WaitingStartedOK bool                  `json:"waiting_started"`
	// Handoff: the program started suspended, for the service to check
	// and resume once this launcher has exited.
	HandoffPID      uint32     `json:"handoff_pid,omitempty"`
	HandoffTID      uint32     `json:"handoff_tid,omitempty"`
	HandoffImage    string     `json:"handoff_image,omitempty"` // as the launcher read it
	HandoffRecord   string     `json:"handoff_record,omitempty"`
	ThreadDACL      string     `json:"handoff_thread_dacl,omitempty"`
	ThreadID        uint32     `json:"launcher_thread_id,omitempty"`
	Step3           *launcher3 `json:"step3,omitempty"`
	TokenLock       string     `json:"token_lock,omitempty"`        // handoff with -p2-lock-token
	TokenSDDL       string     `json:"token_sddl,omitempty"`        // its token's owner and DACL after the lock
	TokenSDDLBefore string     `json:"token_sddl_before,omitempty"` // and before it
	ProcessLock     string     `json:"process_lock,omitempty"`      // its process DACL, likewise
}

// TestProbe2ChildHelper runs a probe2 child's part; skipped otherwise.
func TestProbe2ChildHelper(t *testing.T) {
	switch *p2Mode {
	case "":
		t.Skip("started by TestRunnerHopProbe's service")
	case "launcher":
		os.Exit(runLauncher())
	case "wait":
		time.Sleep(5 * time.Minute)
		os.Exit(9)
	case "pipeclient":
		os.Exit(runPipeClient())
	default:
		os.Exit(runProgram(*p2Mode))
	}
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

func runProgram(mode string) int {
	var r programRecord
	r.Token = readTokenFacts(windows.GetCurrentProcessToken())
	r.SentinelInherits = handleHeld(*p2Sentinel)
	switch mode {
	case "user32":
		if err := moduser32.Load(); err != nil {
			r.Desktop = "user32.dll: " + err.Error()
			break
		}
		d, _, _ := procGetThreadDesktop.Call(uintptr(windows.GetCurrentThreadId()))
		if d == 0 {
			r.Desktop = "GetThreadDesktop failed"
		} else {
			name := make([]uint16, 256)
			var n uint32
			if ok, _, e := procGetUserObjectInformation.Call(d, 2 /* UOI_NAME */, uintptr(unsafe.Pointer(&name[0])), uintptr(len(name)*2), uintptr(unsafe.Pointer(&n))); ok == 0 {
				r.Desktop = "GetUserObjectInformation: " + e.Error()
			} else {
				r.Desktop = windows.UTF16ToString(name)
			}
		}
		if ok, _, e := procMessageBeep.Call(0); ok == 0 {
			r.Beep = e.Error()
		} else {
			r.Beep = "ok"
		}
	case "dcom":
		// -p2-clsid is name=clsid,…; DCOM keeps the first (the class only
		// INTERACTIVE may launch), DCOMs all.
		r.DCOMs = map[string]string{}
		for i, nc := range strings.Split(*p2CLSID, ",") {
			name, clsid, ok := strings.Cut(nc, "=")
			if !ok {
				name, clsid = "class", nc
			}
			r.DCOMs[name] = activate(clsid)
			if i == 0 {
				r.DCOM = r.DCOMs[name]
			}
		}
	case "openlauncher":
		// Whether the run's program may open its launcher (the same user)
		// with a right that would let it take the launcher over.
		time.Sleep(*p2Delay)
		r.TargetIdentity = targetIdentity(uint32(*p2Target), uint32(*p2Thread), *p2Created)
		r.OpenLauncher = map[string]string{}
		// Whether the launcher is still running (an exited process can still
		// be opened while any handle to it is open, here the service's).
		if p, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(*p2Target)); err != nil {
			r.LauncherRunning = "open: " + err.Error()
		} else {
			ev, _ := windows.WaitForSingleObject(p, 0)
			r.LauncherRunning = strconv.FormatBool(ev == uint32(windows.WAIT_TIMEOUT))
			windows.CloseHandle(p)
		}
		for _, right := range []struct {
			name string
			mask uint32
		}{{"PROCESS_VM_WRITE", windows.PROCESS_VM_WRITE}, {"PROCESS_CREATE_THREAD", windows.PROCESS_CREATE_THREAD}, {"WRITE_DAC", windows.WRITE_DAC}} {
			p, err := windows.OpenProcess(right.mask, false, uint32(*p2Target))
			if err != nil {
				r.OpenLauncher[right.name] = err.Error()
			} else {
				r.OpenLauncher[right.name] = "ok"
				windows.CloseHandle(p)
			}
		}
		// The launcher's thread and token keep the runner's default DACL,
		// whatever the launcher sets on its process.
		if *p2Thread != 0 {
			for _, right := range []struct {
				name string
				mask uint32
			}{{"THREAD_SET_CONTEXT", windows.THREAD_SET_CONTEXT}, {"THREAD_SUSPEND_RESUME", windows.THREAD_SUSPEND_RESUME}} {
				th, err := windows.OpenThread(right.mask, false, uint32(*p2Thread))
				if err != nil {
					r.OpenLauncher[right.name] = err.Error()
				} else {
					r.OpenLauncher[right.name] = "ok"
					windows.CloseHandle(th)
				}
			}
		}
		p, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(*p2Target))
		if err != nil {
			for _, k := range []string{"TOKEN_DUPLICATE", "TOKEN_IMPERSONATE", "TOKEN_READ_CONTROL", "TOKEN_WRITE_DAC", "TOKEN_WRITE_OWNER"} {
				r.OpenLauncher[k] = "the process: " + err.Error()
			}
		} else {
			for _, right := range []struct {
				name string
				mask uint32
			}{{"TOKEN_DUPLICATE", windows.TOKEN_DUPLICATE | windows.TOKEN_QUERY}, {"TOKEN_IMPERSONATE", windows.TOKEN_IMPERSONATE},
				{"TOKEN_READ_CONTROL", windows.READ_CONTROL}, {"TOKEN_WRITE_DAC", windows.WRITE_DAC}, {"TOKEN_WRITE_OWNER", windows.WRITE_OWNER}} {
				var tok windows.Token
				if err := windows.OpenProcessToken(p, right.mask, &tok); err != nil {
					r.OpenLauncher[right.name] = err.Error()
					continue
				}
				r.OpenLauncher[right.name] = "ok"
				if right.name == "TOKEN_DUPLICATE" {
					// What a copy of it would hold: INTERACTIVE enabled is what
					// the program's own token lacks.
					var dup windows.Token
					if err := windows.DuplicateTokenEx(tok, windows.TOKEN_QUERY, nil, windows.SecurityImpersonation, windows.TokenImpersonation, &dup); err != nil {
						r.LauncherTokenInteractive = "DuplicateTokenEx: " + err.Error()
					} else {
						r.LauncherTokenInteractive = readTokenFacts(dup).Interactive
						dup.Close()
					}
				}
				tok.Close()
			}
			windows.CloseHandle(p)
		}
		// Every other process in its own job (conhosts, if any): what the
		// program can reach of each.
		r.SelfPID = windows.GetCurrentProcessId()
		r.JobProcs = map[uint32]reachable{}
		pids := jobPIDs(0)
		if pids == nil {
			r.JobProcs[0] = reachable{Image: "its own job: the process list could not be read"}
		}
		images := imagesOf(pids)
		for _, pid := range pids {
			if pid != r.SelfPID {
				r.JobProcs[pid] = reach(pid, images[pid])
			}
		}
		// Other processes by id (the launcher's conhost, step 3): whether
		// the id still names them, and what the program reaches.
		if ex := extraTargets(); len(ex) > 0 {
			r.Extra = map[uint32]extraReach{}
			for pid, created := range ex {
				r.Extra[pid] = extraReach{Identity: targetIdentity(pid, 0, created), Reach: reach(pid, "")}
			}
		}
	case "uilimits":
		r.UI = uiCalls()
	}
	if writeJSON(*p2Out, r) != nil {
		return 5
	}
	if *p2Say {
		// Its line, to the standard output it was given (step 3).
		fmt.Fprintln(os.Stdout, "program-says-hello")
	}
	return 0
}

// activate tries CoCreateInstance of clsid as a local server and returns
// the HRESULT.
func activate(clsid string) string {
	if err := windows.NewLazySystemDLL("ole32.dll").Load(); err != nil {
		return "ole32.dll: " + err.Error()
	}
	if err := windows.CoInitializeEx(0, windows.COINIT_MULTITHREADED); err != nil {
		return "CoInitializeEx: " + err.Error()
	}
	defer windows.CoUninitialize()
	g, err := windows.GUIDFromString(clsid)
	if err != nil {
		return "GUID: " + err.Error()
	}
	iunknown := windows.GUID{Data4: [8]byte{0xc0, 0, 0, 0, 0, 0, 0, 0x46}}
	var p uintptr
	hr, _, _ := procCoCreateInstance.Call(uintptr(unsafe.Pointer(&g)), 0, 4 /* CLSCTX_LOCAL_SERVER */, uintptr(unsafe.Pointer(&iunknown)), uintptr(unsafe.Pointer(&p)))
	return fmt.Sprintf("HRESULT %#x", uint32(hr))
}

// runLauncher is the launcher: it runs as the runner, started by the
// service.
func runLauncher() int {
	// One thread of the launcher's, for the program to try to open.
	runtime.LockOSThread()
	rec := launcherRecord{Children: map[string]childStart{}}
	self := windows.GetCurrentProcessToken()
	rec.Token = readTokenFacts(self)
	rec.ServiceSentinel = handleHeld(*p2Sentinel)
	// Whether user32 initializes in the launcher itself (its own,
	// unrestricted token, on the run's desktop), before any child.
	rec.LauncherUser32 = errString(moduser32.Load())
	rec.LogonSID = logonSID(self)
	rec.ThreadID = windows.GetCurrentThreadId()
	if *p2Quick {
		var own windows.Token
		if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY|windows.TOKEN_ASSIGN_PRIMARY, &own); err != nil {
			rec.Restricted = "OpenProcessToken: " + err.Error()
			_ = writeJSON(*p2Out, rec)
			return 0
		}
		defer own.Close()
		if r, err := restrictToken(own, "interactive"); err == nil {
			out := filepath.Join(filepath.Dir(*p2Out), "child-quick-"+randHex(4)+".json")
			cs := startChild(r, *p2Exe, fmt.Sprintf(`-test.run=^TestProbe2ChildHelper$ -p2-mode=user32 -p2-out="%s"`, out), "", 60*time.Second)
			if b, err := os.ReadFile(out); err == nil {
				_ = json.Unmarshal(b, &cs.Record)
			}
			rec.Children["user32"] = cs
			r.Close()
		}
		_ = writeJSON(*p2Out, rec)
		return 0
	}
	var own windows.Token
	// ADJUST_DEFAULT: the restricted token takes this handle's access, and
	// the default DACL variant changes it.
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY|windows.TOKEN_ASSIGN_PRIMARY|windows.TOKEN_ADJUST_DEFAULT, &own); err != nil {
		rec.Restricted = "OpenProcessToken: " + err.Error()
		_ = writeJSON(*p2Out, rec)
		return 0
	}
	defer own.Close()
	restricted, err := restrictToken(own, *p2Restrict)
	if err != nil {
		rec.Restricted = err.Error()
		_ = writeJSON(*p2Out, rec)
		return 0
	}
	defer restricted.Close()
	rec.Restricted = "ok"
	rec.RestrictedFacts = readTokenFacts(restricted)
	if *p2SvcSID != "" {
		// The service named in the default DACL of the program's token, so
		// that the program's process grants it SYNCHRONIZE,
		// QUERY_LIMITED_INFORMATION and TERMINATE.
		rec.DefaultDACL = errString(setDefaultDACL(restricted, rec.Token.User, *p2SvcSID))
	}
	if *p2Handoff {
		// The program starts suspended. The service gets, through the
		// token's default DACL, SYNCHRONIZE, QUERY_LIMITED_INFORMATION and
		// TERMINATE on the process; on its thread (set here, since the
		// same mask in the default DACL would mean CREATE_THREAD on the
		// process) SYNCHRONIZE, QUERY_LIMITED_INFORMATION and
		// SUSPEND_RESUME. The launcher reports the ids and exits; the
		// service checks the image and resumes it.
		if *p2LockTok {
			// Its own token and process, each limited to SYSTEM and OWNER
			// RIGHTS (the token: QUERY; the process: SYNCHRONIZE and
			// QUERY_LIMITED_INFORMATION), before the program exists.
			rec.TokenSDDLBefore = ownTokenSDDL()
			rec.TokenLock = errString(lockOwnToken())
			rec.TokenSDDL = ownTokenSDDL()
			rec.ProcessLock = errString(limitOwnDACL())
		}
		// Step 3. The launcher's own conhost (it holds a copy of the
		// launcher's token from before any lock): found, and locked or let
		// go if asked. The restricted token made again after the lock. The
		// standard output it was given, passed to the program.
		l3 := &launcher3{Conhost: findConhost()}
		rec.Step3 = l3
		if *p2LockConhost && l3.Conhost.PID != 0 {
			lockConhost(l3.Conhost)
		}
		if *p2FreeConsole {
			if r, _, e := procFreeConsole.Call(); r == 0 {
				l3.Conhost.FreeConsole = e.Error()
			} else {
				l3.Conhost.FreeConsole = "ok"
			}
			if l3.Conhost.PID != 0 {
				l3.Conhost.Running = stillRunning(l3.Conhost.PID)
			}
		}
		if *p2RestrictAft {
			o := &restrictOrder{}
			var t2 windows.Token
			o.OpenAfterLock = errString(windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY, &t2))
			if t2 != 0 {
				t2.Close()
			}
			// From the handle opened before the lock.
			r2, err := restrictToken(own, *p2Restrict)
			o.RestrictAfterLock = errString(err)
			if err == nil {
				defer r2.Close()
				if *p2SvcSID != "" {
					_ = setDefaultDACL(r2, rec.Token.User, *p2SvcSID)
				}
				o.RestrictedFacts = readTokenFacts(r2)
				restricted = r2
			}
			l3.Order = o
		}
		extra := ""
		if l3.Conhost.PID != 0 && l3.Conhost.Created != 0 {
			extra = fmt.Sprintf(" -p2-extra=%d:%d", l3.Conhost.PID, l3.Conhost.Created)
		}
		if *p2PassStd {
			l3.Std = &stdFacts{}
			if h := launcherStd(l3.Std); h != 0 {
				childStdOut = h
				extra += " -p2-say"
			}
		}
		// The program, once resumed (after this launcher has exited), tries
		// to open this launcher: process, thread and token.
		childDetached = *p2Detach
		var created, exitT, kernelT, userT windows.Filetime
		_ = windows.GetProcessTimes(windows.CurrentProcess(), &created, &exitT, &kernelT, &userT)
		out := filepath.Join(filepath.Dir(*p2Out), "child-handoff-"+randHex(4)+".json")
		pi, err := startSuspended(restricted, *p2Exe, fmt.Sprintf(`-test.run=^TestProbe2ChildHelper$ -p2-mode=openlauncher -p2-out="%s" -p2-target=%d -p2-thread=%d -p2-target-created=%d%s`,
			out, windows.GetCurrentProcessId(), rec.ThreadID, uint64(created.HighDateTime)<<32|uint64(created.LowDateTime), extra), "")
		if l3.Std != nil {
			l3.Std.PassedOn = errString(err)
		}
		if *p2Report != "" {
			l3.Cwd, _ = os.Getwd()
			_, rerr := os.ReadDir(l3.Cwd)
			l3.CwdRead = errString(rerr)
			l3.Report = sendReport(*p2Report, report{Cwd: l3.Cwd, CwdRead: l3.CwdRead, Lock: rec.TokenLock, PID: pi.ProcessId, TID: pi.ThreadId})
		}
		if err != nil {
			rec.Restricted += "; handoff start: " + err.Error()
		} else {
			rec.HandoffPID, rec.HandoffTID, rec.HandoffRecord = pi.ProcessId, pi.ThreadId, out
			buf := make([]uint16, windows.MAX_LONG_PATH)
			nn := uint32(len(buf))
			if err := windows.QueryFullProcessImageName(pi.Process, 0, &buf[0], &nn); err != nil {
				rec.HandoffImage = err.Error()
			} else {
				rec.HandoffImage = windows.UTF16ToString(buf[:nn])
			}
			rec.ThreadDACL = errString(setThreadDACL(pi.Thread, rec.Token.User, *p2SvcSID))
			windows.CloseHandle(pi.Thread)
			windows.CloseHandle(pi.Process)
		}
		_ = writeJSON(*p2Out, rec)
		return 0
	}
	if *p2Exit {
		// Start the program that tries to open this launcher, and exit right
		// after resuming it: by the time it tries, the launcher is gone.
		out := filepath.Join(filepath.Dir(*p2Out), "child-exit-after-"+randHex(4)+".json")
		pi, err := startSuspended(restricted, *p2Exe, fmt.Sprintf(`-test.run=^TestProbe2ChildHelper$ -p2-mode=openlauncher -p2-out="%s" -p2-target=%d -p2-delay=2s`, out, windows.GetCurrentProcessId()), "")
		if err != nil {
			rec.Restricted += "; exit-after start: " + err.Error()
		} else {
			rec.ChildRecordPath = out
			_, _ = windows.ResumeThread(pi.Thread)
			windows.CloseHandle(pi.Thread)
			windows.CloseHandle(pi.Process)
		}
		_ = writeJSON(*p2Out, rec)
		return 0
	}
	// An inheritable handle of the launcher's own, which the program must
	// not get.
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), InheritHandle: 1}
	sentinel, err := windows.CreateEvent(sa, 1, 1, nil)
	if err != nil {
		rec.Restricted += "; sentinel: " + err.Error()
	}
	dir := filepath.Dir(*p2Out)
	for _, c := range []struct {
		name, mode string
		tok        windows.Token
		extra      string
	}{
		{"program", "program", restricted, ""},
		{"user32", "user32", restricted, ""},
		{"dcom", "dcom", restricted, " -p2-clsid=" + *p2CLSID},
		{"uilimits", "uilimits", restricted, uiArgs()},
		// With INTERACTIVE enabled, only the class INTERACTIVE alone may
		// launch: the others then launch a server, which never registers,
		// and the call waits out its timeout.
		{"dcom-unrestricted", "dcom", own, " -p2-clsid=" + strings.SplitN(*p2CLSID, ",", 2)[0]},
	} {
		out := filepath.Join(dir, "child-"+c.name+"-"+randHex(4)+".json")
		args := fmt.Sprintf(`-test.run=^TestProbe2ChildHelper$ -p2-mode=%s -p2-out="%s" -p2-sentinel=%d%s`, c.mode, out, uint64(sentinel), c.extra)
		cs := startChild(c.tok, *p2Exe, args, filepath.Join(dir, "child-"+c.name+"-"+randHex(4)+".log"), 60*time.Second)
		if b, err := os.ReadFile(out); err == nil {
			_ = json.Unmarshal(b, &cs.Record)
		}
		rec.Children[c.name] = cs
	}
	rec.Tools = runTools(restricted, dir)
	// Whether the program may open this launcher (the same user, which
	// holds INTERACTIVE enabled) with a right that takes it over; then
	// again once the launcher has limited its own process's DACL through
	// OWNER RIGHTS.
	openArgs := func(out string) string {
		return fmt.Sprintf(`-test.run=^TestProbe2ChildHelper$ -p2-mode=openlauncher -p2-out="%s" -p2-target=%d -p2-thread=%d`, out, windows.GetCurrentProcessId(), rec.ThreadID)
	}
	for _, step := range []string{"open-launcher", "open-launcher-limited"} {
		if step == "open-launcher-limited" {
			rec.LauncherDACL = errString(limitOwnDACL())
		}
		out := filepath.Join(dir, "child-"+step+"-"+randHex(4)+".json")
		cs := startChild(restricted, *p2Exe, openArgs(out), filepath.Join(dir, "child-"+step+"-"+randHex(4)+".log"), 60*time.Second)
		if b, err := os.ReadFile(out); err == nil {
			_ = json.Unmarshal(b, &cs.Record)
		}
		rec.Children[step] = cs
	}
	// A program that waits: the service finds it in the job and kills it
	// by closing the job.
	pi, err := startSuspended(restricted, *p2Exe, `-test.run=^TestProbe2ChildHelper$ -p2-mode=wait`, "")
	if err == nil {
		_, _ = windows.ResumeThread(pi.Thread)
		rec.WaitingPID = pi.ProcessId
		rec.WaitingStartedOK = true
	}
	_ = writeJSON(*p2Out, rec)
	if err == nil {
		// Until the job kills this launcher and the program.
		_, _ = windows.WaitForSingleObject(pi.Process, windows.INFINITE)
	}
	return 0
}

// restrictToken makes a restricted primary token from tok: every
// privilege but SeChangeNotifyPrivilege removed (DISABLE_MAX_PRIVILEGE),
// INTERACTIVE deny-only, and LOCAL too for "interactive+local".
func restrictToken(tok windows.Token, kind string) (windows.Token, error) {
	interactive, _ := windows.StringToSid("S-1-5-4")
	local, _ := windows.StringToSid("S-1-2-0")
	sids := []windows.SIDAndAttributes{{Sid: interactive}}
	if kind == "interactive+local" {
		sids = append(sids, windows.SIDAndAttributes{Sid: local})
	}
	var r windows.Token
	if ok, _, e := procCreateRestrictedToken2.Call(uintptr(tok), 0x1 /* DISABLE_MAX_PRIVILEGE */, uintptr(len(sids)), uintptr(unsafe.Pointer(&sids[0])),
		0, 0, 0, 0, uintptr(unsafe.Pointer(&r))); ok == 0 {
		return 0, fmt.Errorf("CreateRestrictedToken: %w", e)
	}
	return r, nil
}

// startSuspended starts exe with args as tok's user, suspended, with only
// its standard handles inherited: NUL for input, and logPath (when given)
// for its output, so that a child that fails at start says why.
func startSuspended(tok windows.Token, exe, args, logPath string) (windows.ProcessInformation, error) {
	var pi windows.ProcessInformation
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), InheritHandle: 1}
	nulName, _ := windows.UTF16PtrFromString("NUL")
	nul, err := windows.CreateFile(nulName, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, sa, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return pi, fmt.Errorf("NUL: %w", err)
	}
	defer windows.CloseHandle(nul)
	out := nul
	if logPath != "" {
		lp, _ := windows.UTF16PtrFromString(logPath)
		lh, err := windows.CreateFile(lp, windows.GENERIC_WRITE, windows.FILE_SHARE_READ, sa, windows.CREATE_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL, 0)
		if err != nil {
			return pi, fmt.Errorf("log file: %w", err)
		}
		defer windows.CloseHandle(lh)
		out = lh
	}
	console := uint32(windows.CREATE_NO_WINDOW)
	if childDetached {
		// No console at all (so no conhost): DETACHED_PROCESS, its output
		// to a pipe whose read end stays with this process.
		console = windows.DETACHED_PROCESS
		var r, w windows.Handle
		if err := windows.CreatePipe(&r, &w, sa, 0); err != nil {
			return pi, fmt.Errorf("pipe: %w", err)
		}
		_ = windows.SetHandleInformation(r, windows.HANDLE_FLAG_INHERIT, 0)
		defer windows.CloseHandle(w)
		childPipes = append(childPipes, r)
		out = w
	}
	if childStdOut != 0 {
		// The launcher's own standard output (the service's pipe), step 3.
		out = childStdOut
	}
	al, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		return pi, err
	}
	defer al.Delete()
	handles := []windows.Handle{nul}
	if out != nul {
		handles = append(handles, out)
	}
	if err := al.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&handles[0]), unsafe.Sizeof(handles[0])*uintptr(len(handles))); err != nil {
		return pi, fmt.Errorf("handle list: %w", err)
	}
	si := &windows.StartupInfoEx{ProcThreadAttributeList: al.List()}
	si.Cb = uint32(unsafe.Sizeof(*si))
	si.Flags = windows.STARTF_USESTDHANDLES
	si.StdInput, si.StdOutput, si.StdErr = nul, out, out
	if startDesktop != "" {
		si.Desktop, _ = windows.UTF16PtrFromString(startDesktop)
	}
	cl, _ := windows.UTF16PtrFromString(`"` + exe + `" ` + args)
	err = windows.CreateProcessAsUser(tok, nil, cl, nil, nil, true,
		windows.CREATE_SUSPENDED|console|windows.EXTENDED_STARTUPINFO_PRESENT, nil, nil, &si.StartupInfo, &pi)
	return pi, err
}

func startChild(tok windows.Token, exe, args, logPath string, wait time.Duration) childStart {
	var cs childStart
	pi, err := startSuspended(tok, exe, args, logPath)
	if err != nil {
		cs.Start, cs.Errno = err.Error(), errnoOf(err)
		return cs
	}
	cs.Start, cs.PID = "ok", pi.ProcessId
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(pi.Process, 0, &buf[0], &n); err != nil {
		cs.ImageName = "QueryFullProcessImageName: " + err.Error()
	} else {
		cs.ImageName = windows.UTF16ToString(buf[:n])
	}
	_, _ = windows.ResumeThread(pi.Thread)
	cs.Exit = waitExit(pi, wait)
	if b, err := os.ReadFile(logPath); err == nil && len(b) > 0 {
		if len(b) > 2000 {
			b = b[:2000]
		}
		cs.Output = string(b)
	}
	return cs
}

// The service's side.

// probe2Config is what the test hands the service.
type probe2Config struct {
	Out       string               `json:"out"`
	Exe       string               `json:"exe"`
	CLSID     string               `json:"clsid"`
	Mode      string               `json:"mode"`  // "hop", "shapes"
	Users     map[string]probeUser `json:"users"` // hop: "b"; shapes: the shapes
	Shapes    []string             `json:"shapes,omitempty"`
	ToolsFile string               `json:"tools_file,omitempty"` // real tools for the launcher to start
	ExeGUI    string               `json:"exe_gui,omitempty"`    // the GUI-subsystem copy of Exe (step 3)
	// Required is the service's required privileges (nil: ChangeNotify only).
	Required []string `json:"-"`
}

// hopResult is one launcher run.
type hopResult struct {
	Start            string            `json:"start"`
	Errno            uint32            `json:"errno,omitempty"`
	Job              string            `json:"job"`
	UILimits         string            `json:"ui_limits"`
	Launcher         launcherRecord    `json:"launcher"`
	JobPIDs          []uint32          `json:"job_pids"`
	JobImages        map[uint32]string `json:"job_images"`
	JobExits         []uint32          `json:"job_exits"` // from the job's messages, after it was closed
	Took             string            `json:"took"`
	ExitAfter        programRecord     `json:"exit_after_program"` // exit-after: the program's record
	Desktop          string            `json:"desktop"`            // the launcher's, as asked ("": seclogon's choice)
	ServiceOpen      string            `json:"service_opens_program"`
	ServiceName      string            `json:"service_reads_image_name"`
	Kill             string            `json:"job_kill"`
	Report           *reportPipe       `json:"report,omitempty"`
	Output           *outputPipe       `json:"output,omitempty"`
	Handoff          *handoffResult    `json:"handoff,omitempty"`
	ServiceSeesAtomB string            `json:"service_sees_program_atom,omitempty"`
}

// probe2Result is what the service records.
type probe2Result struct {
	WindowStation string `json:"window_station"`
	// The fallback, when the service can make no window station: a
	// desktop in the service's own, with the runner added to it.
	ServiceWindowStation string               `json:"service_window_station,omitempty"`
	WindowStationACE     string               `json:"window_station_ace,omitempty"`
	NullDesktop          string               `json:"null_desktop,omitempty"`
	WindowStationSDDL    string               `json:"window_station_and_desktop_sddl,omitempty"`
	Desktop              string               `json:"desktop"`
	DesktopName          string               `json:"desktop_name"`
	Hops                 map[string]hopResult `json:"hops"`   // "interactive", "interactive+local"
	Shapes               map[string]string    `json:"shapes"` // shape: "ok" or "errno N: text"
	RouteA               *routeAResult        `json:"route_a,omitempty"`
	// Step 3: whether this service may read the runner's account rights.
	RunnerRights         string                `json:"runner_rights_read,omitempty"`
	RunnerRightsList     []string              `json:"runner_rights,omitempty"`
	Masks                map[string]maskResult `json:"window_station_masks,omitempty"`
	UnnamedWindowStation string                `json:"unnamed_window_station"`
	UnnamedHop           *maskResult           `json:"unnamed_window_station_hop,omitempty"`
}

// TestRunnerHopProbeHelper is the service, run by the SCM.
func TestRunnerHopProbeHelper(t *testing.T) {
	inService, err := svc.IsWindowsService()
	if err != nil || !inService {
		t.Skip("run by TestRunnerHopProbe, as a service")
	}
	exe, _ := os.Executable()
	b, err := os.ReadFile(filepath.Join(filepath.Dir(exe), "probe2.json"))
	if err != nil {
		os.Exit(3)
	}
	var c probe2Config
	if json.Unmarshal(b, &c) != nil {
		os.Exit(3)
	}
	_ = svc.Run("", &probe2Service{c: c})
	os.Exit(0)
}

type probe2Service struct{ c probe2Config }

func (p *probe2Service) Execute(_ []string, _ <-chan svc.ChangeRequest, s chan<- svc.Status) (bool, uint32) {
	s <- svc.Status{State: svc.Running}
	var res probe2Result
	if p.c.Mode == "route-a" {
		res.RouteA = runRouteA(p.c)
	} else if p.c.Mode == "shapes" {
		res.Shapes = map[string]string{}
		for _, shape := range p.c.Shapes {
			st := startWithLogon(p.c.Exe, p.c.Users[shape], 0)
			if st.Start == "ok" && st.ChildUser == p.c.Users[shape].SID {
				res.Shapes[shape] = "ok"
			} else if st.Start == "ok" {
				res.Shapes[shape] = "started; child user " + st.ChildUser
			} else {
				res.Shapes[shape] = fmt.Sprintf("errno %d: %s", st.Errno, st.Start)
			}
		}
	} else {
		res = runHops(p.c)
	}
	_ = writeJSON(p.c.Out, res)
	s <- svc.Status{State: svc.StopPending}
	return false, 0
}

// userObjectSD is a security descriptor for a window station or desktop:
// full access for the service's account (its owner) and the runner.
func userObjectSA(runner string) (*windows.SecurityAttributes, error) {
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;GA;;;SY)(A;;GA;;;OW)(A;;GA;;;" + runner + ")")
	if err != nil {
		return nil, err
	}
	return &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}, nil
}

func runHops(c probe2Config) probe2Result {
	res := probe2Result{Hops: map[string]hopResult{}}
	b := c.Users["b"]
	sa, err := userObjectSA(b.SID)
	if err != nil {
		res.WindowStation = err.Error()
		return res
	}
	// A window station with no name (Chromium's pattern): whether the
	// service may make one where a named one is refused, and whether a
	// run can use a desktop in it. A station of the run's own would keep
	// Step 3: whether this service (ChangeNotify only) may read the
	// runner's account rights, to re-check its denied logons.
	res.RunnerRights, res.RunnerRightsList = accountRights(b.SID)
	// runs off the connector's.
	res.UnnamedWindowStation, res.UnnamedHop = tryUnnamedStation(c, b, sa)
	deskName := "run-" + randHex(4)
	wsName := "vettid-run-" + randHex(4)
	wn, _ := windows.UTF16PtrFromString(wsName)
	dn, _ := windows.UTF16PtrFromString(deskName)
	ws, _, e := procCreateWindowStationW.Call(uintptr(unsafe.Pointer(wn)), 0, uintptr(windows.MAXIMUM_ALLOWED), uintptr(unsafe.Pointer(sa)))
	var desk uintptr
	if ws != 0 {
		res.WindowStation = "ok: " + wsName
		defer procCloseWindowStation.Call(ws)
		// The desktop is made in the new window station: switch to it for
		// the call, then back.
		old, _, _ := procGetProcessWindowStation.Call()
		if r, _, e := procSetProcessWindowStation.Call(ws); r == 0 {
			res.Desktop = "SetProcessWindowStation: " + e.Error()
			return res
		}
		desk, _, e = procCreateDesktopW.Call(uintptr(unsafe.Pointer(dn)), 0, 0, 0, uintptr(windows.MAXIMUM_ALLOWED), uintptr(unsafe.Pointer(sa)))
		procSetProcessWindowStation.Call(old)
	} else {
		// No window station of its own: a desktop of the run's own in the
		// service's window station, which the runner is added to.
		res.WindowStation = "CreateWindowStation: " + e.Error()
		cur, _, _ := procGetProcessWindowStation.Call()
		name := make([]uint16, 256)
		var n uint32
		if ok, _, e := procGetUserObjectInformation.Call(cur, 2 /* UOI_NAME */, uintptr(unsafe.Pointer(&name[0])), uintptr(len(name)*2), uintptr(unsafe.Pointer(&n))); ok == 0 {
			res.Desktop = "the service's window station's name: " + e.Error()
			return res
		}
		wsName = windows.UTF16ToString(name)
		res.ServiceWindowStation = wsName
		// The station's access list is put back when the service is done.
		if restore, err := keepStationDACL(windows.Handle(cur)); err == nil {
			defer restore()
		} else {
			res.WindowStationACE = "keeping its access list: " + err.Error()
		}
		if res.WindowStationACE == "" {
			res.WindowStationACE = errString(grantWindowStation(windows.Handle(cur), b.SID))
		}
		desk, _, e = procCreateDesktopW.Call(uintptr(unsafe.Pointer(dn)), 0, 0, 0, uintptr(windows.MAXIMUM_ALLOWED), uintptr(unsafe.Pointer(sa)))
	}
	if desk == 0 {
		res.Desktop = "CreateDesktop: " + e.Error()
		return res
	}
	defer procCloseDesktop.Call(desk)
	res.Desktop = "ok"
	res.DesktopName = wsName + `\` + deskName

	// An inheritable handle of the service's, open while the launcher
	// starts.
	isa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), InheritHandle: 1}
	sentinel, err := windows.CreateEvent(isa, 1, 1, nil)
	if err == nil {
		defer windows.CloseHandle(sentinel)
	}
	// Contrasts, to tell what stops user32 starting: a second desktop in
	// the same window station with a NULL DACL (anyone: the access entries
	// can't be the cause), and seclogon's own choice (lpDesktop null,
	// which the plan rules out; measured only).
	nullName := "open-" + randHex(4)
	nn, _ := windows.UTF16PtrFromString(nullName)
	var nullDesk uintptr
	if nsd, err := windows.SecurityDescriptorFromString("D:NO_ACCESS_CONTROL"); err == nil {
		nsa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: nsd}
		nullDesk, _, e = procCreateDesktopW.Call(uintptr(unsafe.Pointer(nn)), 0, 0, 0, uintptr(windows.MAXIMUM_ALLOWED), uintptr(unsafe.Pointer(nsa)))
		if nullDesk != 0 {
			defer procCloseDesktop.Call(nullDesk)
		} else {
			res.NullDesktop = "CreateDesktop: " + e.Error()
		}
	}
	// What the runner may do with the window station and desktop, as
	// their access lists say (the runner's logon SID is in each
	// launcher's record).
	wsh := ws
	if wsh == 0 {
		wsh, _, _ = procGetProcessWindowStation.Call()
	}
	res.WindowStationSDDL = objectSDDL(windows.Handle(wsh), windows.Handle(desk))
	for _, v := range []hopOpts{
		{key: "interactive", restrict: "interactive", desktop: res.DesktopName, uiLimits: true, tools: true},
		{key: "interactive-no-ui-limits", restrict: "interactive", desktop: res.DesktopName},
		{key: "interactive+local", restrict: "interactive+local", desktop: res.DesktopName, uiLimits: true},
		{key: "null-dacl-desktop", restrict: "interactive", desktop: wsName + `\` + nullName, uiLimits: true},
		{key: "seclogon-default-desktop", restrict: "interactive", uiLimits: true},
		// No job at all, and CREATE_NO_WINDOW left out: whether either
		// is what stops user32.
		{key: "no-job-with-window", restrict: "interactive", desktop: res.DesktopName, noJob: true, withWindow: true},
		// The launcher exits right after resuming the program, which then
		// tries to open it.
		{key: "exit-after", restrict: "interactive", desktop: res.DesktopName, uiLimits: true, exitAfter: true},
		// The design's shape: the launcher starts the program suspended,
		// hands it to the service and exits; the service checks the image
		// and resumes it.
		{key: "handoff", restrict: "interactive", desktop: res.DesktopName, uiLimits: true, handoff: true},
		// The same, with the launcher locking its own token and process
		// first: which of the two is what keeps the program out.
		{key: "handoff-locked", restrict: "interactive", desktop: res.DesktopName, uiLimits: true, handoff: true, lockToken: true},
		// With no console for the program (DETACHED_PROCESS, pipes for its
		// output), and for the launcher too: no conhost to reach.
		// Step 3, each on the design's shape (locked, the program with no
		// console): the launcher's conhost reached by id; freed; locked;
		// the launcher a GUI-subsystem copy (no console at all), with the
		// output through seclogon and the report pipe; the output pipes
		// inheritable or not; the restricted token made after the lock.
		{key: "s3-conhost", restrict: "interactive", desktop: res.DesktopName, uiLimits: true, handoff: true, lockToken: true, detachedProgram: true},
		{key: "s3-freeconsole", restrict: "interactive", desktop: res.DesktopName, uiLimits: true, handoff: true, lockToken: true, detachedProgram: true, freeConsole: true},
		{key: "s3-lockconhost", restrict: "interactive", desktop: res.DesktopName, uiLimits: true, handoff: true, lockToken: true, detachedProgram: true, lockConhost: true},
		{key: "s3-gui", restrict: "interactive", desktop: res.DesktopName, uiLimits: true, handoff: true, lockToken: true, detachedProgram: true, gui: true, outPipe: "inheritable", passStd: true, report: true},
		{key: "s3-pipes-inheritable", restrict: "interactive", desktop: res.DesktopName, uiLimits: true, handoff: true, lockToken: true, detachedProgram: true, outPipe: "inheritable", passStd: true, report: true},
		{key: "s3-pipes-not-inheritable", restrict: "interactive", desktop: res.DesktopName, uiLimits: true, handoff: true, lockToken: true, detachedProgram: true, outPipe: "not-inheritable", passStd: true},
		{key: "s3-restrict-after-lock", restrict: "interactive", desktop: res.DesktopName, uiLimits: true, handoff: true, lockToken: true, detachedProgram: true, restrictAfterLock: true},
		{key: "handoff-locked-detached-program", restrict: "interactive", desktop: res.DesktopName, uiLimits: true, handoff: true, lockToken: true, detachedProgram: true},
		{key: "handoff-locked-detached", restrict: "interactive", desktop: res.DesktopName, uiLimits: true, handoff: true, lockToken: true, detachedProgram: true, detachedLauncher: true},
		// The service named in the program's token's default DACL: whether
		// it may then open the program.
		{key: "service-in-default-dacl", restrict: "interactive", desktop: res.DesktopName, uiLimits: true, svcDACL: true},
	} {
		if v.key == "null-dacl-desktop" && nullDesk == 0 {
			continue
		}
		res.Hops[v.key] = runHop(c, b, v, uint64(sentinel))
	}
	// The narrowest entry on the window station that user32 needs: the
	// runner's entry is set (not added to) to each mask in turn, and a
	// quick launcher checks user32 in itself and in a restricted child.
	res.Masks = map[string]maskResult{}
	for _, mask := range probeMasks {
		key := fmt.Sprintf("%#x", mask)
		mr := maskResult{Set: errString(setWindowStationEntry(windows.Handle(wsh), b.SID, mask, windows.SET_ACCESS))}
		if mr.Set == "ok" {
			h := runHop(c, b, hopOpts{key: "mask " + key, restrict: "interactive", desktop: res.DesktopName, uiLimits: true, quick: true}, 0)
			mr.Start, mr.Launcher = h.Start, h.Launcher.LauncherUser32
			mr.Child = h.Launcher.Children["user32"].Record.Desktop
		}
		res.Masks[key] = mr
	}
	return res
}

// winstaWithout is WINSTA_ALL_ACCESS (0x37F) with READ_CONTROL (0x20000)
// and without the rights given.
func winstaWithout(drop uint32) uint32 { return 0x2037f &^ drop }

// probeMasks: the specific rights alone (0x37F, which fails), with each
// standard right on its own, with READ_CONTROL less each of the specific
// rights the plan may not need, and less all of them.
var probeMasks = []uint32{
	0x37f, 0x1037f, 0x2037f, 0x4037f, 0x8037f, 0x6037f,
	winstaWithout(0x4),   // WINSTA_ACCESSCLIPBOARD
	winstaWithout(0x1),   // WINSTA_ENUMDESKTOPS
	winstaWithout(0x100), // WINSTA_ENUMERATE
	winstaWithout(0x200), // WINSTA_READSCREEN
	winstaWithout(0x40),  // WINSTA_EXITWINDOWS
	winstaWithout(0x4 | 0x1 | 0x100 | 0x200 | 0x40),
	// The four the measurement found may each go, together
	// (EXITWINDOWS stays): 0x2007A.
	winstaWithout(0x4 | 0x1 | 0x100 | 0x200),
	// 0x2007A less each of its specific rights in turn:
	// READATTRIBUTES, CREATEDESKTOP, WRITEATTRIBUTES, ACCESSGLOBALATOMS.
	0x20078, 0x20072, 0x2006a, 0x2005a,
	// READATTRIBUTES, CREATEDESKTOP and WRITEATTRIBUTES each may go: all
	// three (0x20060), and each pair of them.
	0x20060, 0x20070, 0x20068, 0x20062,
}

// maskResult is one window station entry tried.
type maskResult struct {
	Set      string `json:"set"`
	Start    string `json:"start,omitempty"`
	Launcher string `json:"launcher_user32,omitempty"`
	Child    string `json:"child_desktop,omitempty"` // the desktop's name, or why user32 failed
}

// hopOpts is one way of starting the launcher.
type hopOpts struct {
	key, restrict, desktop string // desktop "": seclogon's own choice (a contrast only)
	uiLimits               bool
	noJob, withWindow      bool
	tools                  bool // the launcher also starts the real tools
	quick                  bool // the launcher checks user32 only (the mask variants)
	exitAfter              bool // the launcher exits right after resuming the program
	svcDACL                bool // the service is named in the program's default DACL
	handoff                bool // the launcher hands the suspended program to the service and exits
	lockToken              bool // handoff: the launcher locks its own token and process first
	detachedProgram        bool // handoff: the program has no console
	detachedLauncher       bool // the launcher has no console (DETACHED_PROCESS to seclogon)
	// Step 3.
	gui               bool   // the launcher is the GUI-subsystem copy
	outPipe           string // "inheritable", "not-inheritable": the service's pipe as the launcher's output
	passStd           bool   // the launcher gives the program its own output
	report            bool   // the launcher reports on a per-run named pipe
	freeConsole       bool   // the launcher frees its console before starting the program
	lockConhost       bool   // the launcher locks its conhost's process and token
	restrictAfterLock bool   // the launcher makes the restricted token after the lock
}

// objectSDDL is the window station's (and desktop's) access list in SDDL.
func objectSDDL(ws, desk windows.Handle) string {
	s := ""
	for _, o := range []struct {
		name string
		h    windows.Handle
	}{{"window station", ws}, {"desktop", desk}} {
		if o.h == 0 {
			continue
		}
		sd, err := windows.GetSecurityInfo(o.h, windows.SE_WINDOW_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			s += o.name + ": " + err.Error() + "; "
			continue
		}
		s += o.name + ": " + sd.String() + "; "
	}
	return s
}

func runHop(c probe2Config, u probeUser, o hopOpts, sentinel uint64) (h hopResult) {
	h = hopResult{Desktop: o.desktop}
	started := time.Now()
	defer func() { h.Took = time.Since(started).Round(time.Second).String() }()
	desktop, restrict := o.desktop, o.restrict
	out := filepath.Join(u.OutDir, "launcher-"+randHex(4)+".json")
	args := fmt.Sprintf(`-test.run=^TestProbe2ChildHelper$ -p2-mode=launcher -p2-out="%s" -p2-exe="%s" -p2-restrict=%s -p2-sentinel=%d -p2-clsid=%s`,
		out, c.Exe, restrict, sentinel, c.CLSID)
	if o.detachedProgram {
		args += " -p2-detached"
	}
	if o.lockToken {
		args += " -p2-lock-token"
	}
	if o.handoff {
		args += " -p2-handoff"
		if u, err := windows.GetCurrentProcessToken().GetTokenUser(); err == nil {
			args += " -p2-svcsid=" + u.User.Sid.String()
		}
	}
	if o.uiLimits {
		args += " -p2-ui-limits"
	}
	// A global atom the service adds (the program should not see it
	// under the UI limits), and one the program adds (the service should
	// not see it).
	atomA, atomB := "vettid-p2-a-"+randHex(4), "vettid-p2-b-"+randHex(4)
	if !o.quick {
		an, _ := windows.UTF16PtrFromString(atomA)
		if a, _, _ := procGlobalAddAtomW.Call(uintptr(unsafe.Pointer(an))); a != 0 {
			defer procGlobalDeleteAtom.Call(a)
		}
		args += " -p2-atom-a=" + atomA + " -p2-atom-b=" + atomB
		defer func() {
			bn, _ := windows.UTF16PtrFromString(atomB)
			if a, _, e := procGlobalFindAtomW.Call(uintptr(unsafe.Pointer(bn))); a == 0 {
				h.ServiceSeesAtomB = e.Error()
			} else {
				h.ServiceSeesAtomB = "found"
				procGlobalDeleteAtom.Call(a)
			}
		}()
	}
	if o.exitAfter {
		args += " -p2-exit-after"
	}
	if o.svcDACL {
		if u, err := windows.GetCurrentProcessToken().GetTokenUser(); err == nil {
			args += " -p2-svcsid=" + u.User.Sid.String()
		}
	}
	if o.quick {
		args += " -p2-quick"
	}
	if o.tools && c.ToolsFile != "" {
		args += fmt.Sprintf(` -p2-tools="%s"`, c.ToolsFile)
	}
	n, _ := windows.UTF16PtrFromString(u.Name)
	dot, _ := windows.UTF16PtrFromString(".")
	pw, _ := windows.UTF16PtrFromString(u.Password)
	// Step 3: the launcher's report pipe, the run's output pipe, and the
	// launcher as a GUI-subsystem copy of the binary.
	if o.report {
		h.Report = makeReportPipe(serviceSIDString(), u.SID)
		args += " -p2-report=" + h.Report.Name
		// Other accounts try it first: another runner, and a plain user.
		h.Report.Other = map[string]string{}
		for _, k := range []string{"c", "m"} {
			if ou, ok := c.Users[k]; ok {
				h.Report.Other[k] = tryPipeAs(c.Exe, ou, h.Report.Name)
			}
		}
	}
	if o.passStd {
		args += " -p2-passstd"
	}
	if o.freeConsole {
		args += " -p2-freeconsole"
	}
	if o.lockConhost {
		args += " -p2-lockconhost"
	}
	if o.restrictAfterLock {
		args += " -p2-restrict-after-lock"
	}
	launcherExe := c.Exe
	if o.gui {
		launcherExe = c.ExeGUI
	}
	cl, _ := windows.UTF16FromString(`"` + launcherExe + `" ` + args)
	dir, _ := windows.UTF16PtrFromString(filepath.Dir(c.Exe))
	var dsk *uint16 // null: seclogon's own choice (a contrast only)
	if desktop != "" {
		dsk, _ = windows.UTF16PtrFromString(desktop)
	}
	si := &windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfo{})), Desktop: dsk}
	if o.outPipe != "" {
		h.Output = makeOutputPipe(o.outPipe == "inheritable")
		if h.Output.Make == "ok" {
			si.Flags |= windows.STARTF_USESTDHANDLES
			si.StdOutput, si.StdErr = h.Output.w, h.Output.w
		}
	}
	flags := uintptr(windows.CREATE_SUSPENDED)
	if !o.withWindow {
		if o.detachedLauncher {
			flags |= windows.DETACHED_PROCESS
		} else {
			flags |= windows.CREATE_NO_WINDOW
		}
	}
	var pi windows.ProcessInformation
	if r, _, e := procCreateProcessWithLogonW.Call(uintptr(unsafe.Pointer(n)), uintptr(unsafe.Pointer(dot)), uintptr(unsafe.Pointer(pw)),
		0, 0, uintptr(unsafe.Pointer(&cl[0])), flags, 0,
		uintptr(unsafe.Pointer(dir)), uintptr(unsafe.Pointer(si)), uintptr(unsafe.Pointer(&pi))); r == 0 {
		h.Start, h.Errno = e.Error(), errnoOf(e)
		return h
	}
	h.Start = "ok"
	if h.Output != nil {
		// The launcher has its copy; the service's goes, so the read ends
		// when the run's processes are done.
		h.Output.closeWrite()
	}
	var job, port windows.Handle
	err := errors.New("no job (this variant)")
	if !o.noJob {
		job, err = killOnCloseJob()
		if err == nil {
			// The job's own messages say which processes ended, as the
			// service may not open them (measured below).
			port, err = windows.CreateIoCompletionPort(windows.InvalidHandle, 0, 0, 1)
		}
		if err == nil {
			defer windows.CloseHandle(port)
			cp := struct {
				key  uintptr
				port windows.Handle
			}{1, port}
			_, err = windows.SetInformationJobObject(job, windows.JobObjectAssociateCompletionPortInformation, uintptr(unsafe.Pointer(&cp)), uint32(unsafe.Sizeof(cp)))
		}
		if err == nil {
			err = windows.AssignProcessToJobObject(job, pi.Process)
		}
	}
	h.Job = errString(err)
	h.UILimits = "not set"
	if err == nil && o.uiLimits {
		ui := windows.JOBOBJECT_BASIC_UI_RESTRICTIONS{UIRestrictionsClass: windows.JOB_OBJECT_UILIMIT_HANDLES | windows.JOB_OBJECT_UILIMIT_GLOBALATOMS |
			windows.JOB_OBJECT_UILIMIT_DESKTOP | windows.JOB_OBJECT_UILIMIT_READCLIPBOARD | windows.JOB_OBJECT_UILIMIT_WRITECLIPBOARD |
			windows.JOB_OBJECT_UILIMIT_EXITWINDOWS | windows.JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS | windows.JOB_OBJECT_UILIMIT_DISPLAYSETTINGS}
		_, uerr := windows.SetInformationJobObject(job, windows.JobObjectBasicUIRestrictions, uintptr(unsafe.Pointer(&ui)), uint32(unsafe.Sizeof(ui)))
		h.UILimits = errString(uerr)
	}
	_, _ = windows.ResumeThread(pi.Thread)
	// Wait for the launcher's record (written once the waiting program
	// runs).
	for end := time.Now().Add(4 * time.Minute); time.Now().Before(end); time.Sleep(200 * time.Millisecond) {
		if b, err := os.ReadFile(out); err == nil && json.Unmarshal(b, &h.Launcher) == nil && (h.Launcher.WaitingStartedOK || h.Launcher.Restricted != "ok" || o.quick) {
			break
		}
		if ev, _ := windows.WaitForSingleObject(pi.Process, 0); ev == windows.WAIT_OBJECT_0 {
			if b, err := os.ReadFile(out); err == nil {
				_ = json.Unmarshal(b, &h.Launcher)
			}
			break
		}
	}
	if o.handoff {
		h.Handoff = handoff(h.Launcher, &pi, job, c.Exe)
		if h.Report != nil {
			h.Report.collect(h.Launcher.Step3 != nil && h.Launcher.Step3.Report == "ok")
		}
		if h.Output != nil {
			// The program has ended (handoff waits for it): its output, and the
			// launcher's, are in the pipe.
			h.Output.wait(15 * time.Second)
		}
	}
	if o.exitAfter && h.Launcher.ChildRecordPath != "" {
		// The program, started by a launcher that has since exited, says
		// whether it could still open it.
		for end := time.Now().Add(30 * time.Second); time.Now().Before(end); time.Sleep(200 * time.Millisecond) {
			if b, err := os.ReadFile(h.Launcher.ChildRecordPath); err == nil && json.Unmarshal(b, &h.ExitAfter) == nil {
				break
			}
		}
	}
	if job != 0 {
		h.JobPIDs = jobPIDs(job)
		h.JobImages = imagesOf(h.JobPIDs)
		if h.Launcher.WaitingPID != 0 {
			// Whether the service may open the run's program at all.
			p, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE|windows.PROCESS_TERMINATE, false, h.Launcher.WaitingPID)
			if err != nil {
				h.ServiceOpen = err.Error()
			} else {
				h.ServiceOpen = "ok"
				buf := make([]uint16, windows.MAX_LONG_PATH)
				nn := uint32(len(buf))
				if err := windows.QueryFullProcessImageName(p, 0, &buf[0], &nn); err != nil {
					h.ServiceName = err.Error()
				} else {
					h.ServiceName = windows.UTF16ToString(buf[:nn])
				}
				windows.CloseHandle(p)
			}
		}
		// Closing the job (its last handle) kills what is in it: the job's
		// messages say which processes ended.
		windows.CloseHandle(job)
		// Two proofs, as the service may not open the program: the job's
		// exit messages (recorded), and whether the processes are still
		// there. The launcher: through the service's own handle to it. The
		// program: whether a process snapshot (which needs no handle) still
		// lists it.
		h.JobExits = jobExits(port, 3*time.Second)
		// The handoff closed its handle once it saw the launcher end.
		launcherEnded := pi.Process == 0 && h.Handoff != nil && h.Handoff.LauncherGone == "true"
		if pi.Process != 0 {
			if ev, _ := windows.WaitForSingleObject(pi.Process, 10000); ev == windows.WAIT_OBJECT_0 {
				launcherEnded = true
			}
		}
		programEnded := h.Launcher.WaitingPID == 0
		for end := time.Now().Add(10 * time.Second); !programEnded && time.Now().Before(end); time.Sleep(200 * time.Millisecond) {
			programEnded = len(imagesOf([]uint32{h.Launcher.WaitingPID})) == 0
		}
		switch {
		case launcherEnded && programEnded && h.Launcher.WaitingPID != 0:
			h.Kill = "ok"
		case launcherEnded && programEnded:
			h.Kill = "ok (the launcher)"
		default:
			h.Kill = fmt.Sprintf("not all ended: launcher %d ended %v, program %d ended %v (job messages %v)", pi.ProcessId, launcherEnded, h.Launcher.WaitingPID, programEnded, h.JobExits)
		}
	}
	if o.noJob {
		// No job: the service ends the waiting program and the launcher
		// itself.
		if h.Launcher.WaitingPID != 0 {
			// Without a job the service can only end the program itself: as
			// the program's own access list allows, recorded.
			p, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, h.Launcher.WaitingPID)
			if err != nil {
				h.Kill = "no job; the service may not end the program: " + err.Error()
			} else {
				h.Kill = "no job; " + errString(windows.TerminateProcess(p, 1))
				windows.CloseHandle(p)
			}
		}
		_ = windows.TerminateProcess(pi.Process, 1)
	}
	if pi.Process != 0 {
		if ev, _ := windows.WaitForSingleObject(pi.Process, 10000); ev != windows.WAIT_OBJECT_0 {
			_ = windows.TerminateProcess(pi.Process, 1)
			h.Kill += "; the launcher still ran"
		}
		windows.CloseHandle(pi.Process)
		windows.CloseHandle(pi.Thread)
	}
	return h
}

// jobPIDs lists the processes in job.
func jobPIDs(job windows.Handle) []uint32 {
	buf := make([]uint64, 64)
	if err := windows.QueryInformationJobObject(job, windows.JobObjectBasicProcessIdList, uintptr(unsafe.Pointer(&buf[0])), uint32(len(buf)*8), nil); err != nil {
		return nil
	}
	// JOBOBJECT_BASIC_PROCESS_ID_LIST: two DWORDs, then ULONG_PTRs.
	n := uint32(buf[0] >> 32)
	var out []uint32
	for i := uint32(0); i < n && int(i+1) < len(buf); i++ {
		out = append(out, uint32(buf[i+1]))
	}
	return out
}

// The test's side.

// newShapedUser makes a throwaway local user with exactly these rights
// granted and denied, a folder only it (and the service, to read) can
// write, and, if mustChange, a password to be changed at next logon.
func newShapedUser(t *testing.T, dir, svcSID string, grants, denies []string, mustChange bool) probeUser {
	t.Helper()
	u := newProbeUser(t, dir, svcSID, grants, denies)
	if mustChange {
		// "Password never expires" (set for every probe user) overrides
		// "must change at next logon": it is turned off first.
		if out, err := exec.Command("powershell", "-NoProfile", "-Command", "Set-LocalUser -Name '"+u.Name+"' -PasswordNeverExpires $false").CombinedOutput(); err != nil {
			t.Fatalf("Set-LocalUser: %v %s", err, out)
		}
		if out, err := exec.Command("net", "user", u.Name, "/logonpasswordchg:yes").CombinedOutput(); err != nil {
			t.Fatalf("net user: %v %s", err, out)
		}
		// What Windows records for the user, as the measurement's context.
		if out, err := exec.Command("net", "user", u.Name).CombinedOutput(); err == nil {
			for _, l := range strings.Split(string(out), "\n") {
				if strings.Contains(l, "assword") {
					t.Logf("%s: %s", u.Name, strings.TrimSpace(l))
				}
			}
		}
	}
	return u
}

// registerClass registers a throwaway class whose AppID runs as the
// Interactive User. launch is its LaunchPermission and AccessPermission in
// SDDL, or "" for none (the machine's default applies). Its server is
// exe, which exits. The keys' removal is registered before they are
// written, so a failure part way leaves nothing.
func registerClass(t *testing.T, exe, launch string) string {
	t.Helper()
	guid := func() string {
		return "{" + strings.ToUpper(fmt.Sprintf("%s-%s-%s-%s-%s", randHex(4), randHex(2), randHex(2), randHex(2), randHex(6))) + "}"
	}
	clsid, appid := guid(), guid()
	appKey := `SOFTWARE\Classes\AppID\` + appid
	clsKey := `SOFTWARE\Classes\CLSID\` + clsid
	t.Cleanup(func() {
		for _, k := range []string{clsKey + `\LocalServer32`, clsKey, appKey} {
			if err := registry.DeleteKey(registry.LOCAL_MACHINE, k); err != nil && !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
				t.Errorf("removing %s: %v", k, err)
			}
		}
	})
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, appKey, registry.ALL_ACCESS)
	if err != nil {
		t.Fatal(err)
	}
	errs := []error{k.SetStringValue("RunAs", "Interactive User")}
	if launch != "" {
		sd, err := windows.SecurityDescriptorFromString(launch)
		if err != nil {
			t.Fatal(err)
		}
		// SecurityDescriptorFromString gives a self-relative descriptor, the
		// form the registry values take, as it is.
		perm := unsafe.Slice((*byte)(unsafe.Pointer(sd)), sd.Length())
		errs = append(errs, k.SetBinaryValue("LaunchPermission", perm), k.SetBinaryValue("AccessPermission", perm))
	}
	k.Close()
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	k, _, err = registry.CreateKey(registry.LOCAL_MACHINE, clsKey, registry.ALL_ACCESS)
	if err != nil {
		t.Fatal(err)
	}
	err = k.SetStringValue("AppID", appid)
	k.Close()
	if err != nil {
		t.Fatal(err)
	}
	ls, _, err := registry.CreateKey(registry.LOCAL_MACHINE, clsKey+`\LocalServer32`, registry.ALL_ACCESS)
	if err != nil {
		t.Fatal(err)
	}
	err = ls.SetStringValue("", `"`+exe+`" -test.run=^$`)
	ls.Close()
	if err != nil {
		t.Fatal(err)
	}
	return clsid
}

// probe2Service sets up the cut1 service with cfg and returns its record.
func runProbe2Service(t *testing.T, m *mgr.Mgr, name string, svcSID *windows.SID, dir, exe string, cfg probe2Config) probe2Result {
	t.Helper()
	cfgPath := filepath.Join(dir, "probe2.json")
	cfg.Out = filepath.Join(dir, "result2.json")
	b, _ := json.Marshal(cfg)
	if err := os.WriteFile(cfgPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	protectDir(t, cfgPath, "D:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;FR;;;"+svcSID.String()+")")
	if err := os.WriteFile(cfgPath, b, 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(cfg.Out)
	s, err := m.CreateService(name, exe, mgr.Config{
		DisplayName: name, StartType: mgr.StartManual, ServiceStartName: `NT SERVICE\` + name,
		SidType: windows.SERVICE_SID_TYPE_UNRESTRICTED,
	}, "-test.run=^TestRunnerHopProbeHelper$")
	if err != nil {
		t.Fatalf("CreateService: %v", err)
	}
	t.Cleanup(func() { removeService(t, m, s, name, svcSID.String()) })
	privs := []uint16{}
	req := cfg.Required
	if req == nil {
		req = []string{"SeChangeNotifyPrivilege"}
	}
	for _, r := range strings.Join(req, "\x00") + "\x00\x00" {
		privs = append(privs, uint16(r))
	}
	type requiredPrivilegesInfo struct{ privileges *uint16 }
	rp := requiredPrivilegesInfo{&privs[0]}
	if err := windows.ChangeServiceConfig2(s.Handle, windows.SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO, (*byte)(unsafe.Pointer(&rp))); err != nil {
		t.Fatalf("required privileges: %v", err)
	}
	if err := s.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	var rec []byte
	for end := time.Now().Add(15 * time.Minute); ; time.Sleep(500 * time.Millisecond) {
		if rec, err = os.ReadFile(cfg.Out); err == nil && len(rec) > 0 {
			break
		}
		if time.Now().After(end) {
			t.Fatal("no record from the service")
		}
	}
	// Wait for the service to stop before its successor is registered.
	for end := time.Now().Add(30 * time.Second); time.Now().Before(end); time.Sleep(200 * time.Millisecond) {
		if st, err := s.Query(); err == nil && st.State == svc.Stopped {
			break
		}
	}
	t.Logf("%s (%s):\n%s", cfg.Mode, name, rec)
	var res probe2Result
	if err := json.Unmarshal(rec, &res); err != nil {
		t.Fatal(err)
	}
	return res
}

// TestRunnerHopProbe: see the file's comment.
func TestRunnerHopProbe(t *testing.T) {
	if os.Getenv(otherUserEnv) != "1" {
		t.Skipf("set %s=1 to register a test service and users (CI only)", otherUserEnv)
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Fatalf("%s=1 needs an elevated (administrator) process", otherUserEnv)
	}
	m, err := mgr.Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer m.Disconnect()
	sl, err := m.OpenService("seclogon")
	if err != nil {
		t.Fatal(err)
	}
	defer sl.Close()
	c0, err := sl.Config()
	if err != nil {
		t.Fatal(err)
	}
	st0, _ := sl.Query()
	defer func() {
		c, err := sl.Config()
		if err == nil && c.StartType != c0.StartType {
			c.StartType = c0.StartType
			err = sl.UpdateConfig(c)
		}
		if err != nil {
			t.Errorf("restoring seclogon: %v", err)
		}
		// As found: running, or stopped.
		switch st0.State {
		case svc.Running:
			if err := sl.Start(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
				t.Errorf("restarting seclogon: %v", err)
			}
		case svc.Stopped:
			if _, err := sl.Control(svc.Stop); err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) && !errors.Is(err, windows.ERROR_INVALID_SERVICE_CONTROL) {
				t.Errorf("stopping seclogon again: %v", err)
			}
		}
	}()
	if c0.StartType != mgr.StartManual {
		c := c0
		c.StartType = mgr.StartManual
		if err := sl.UpdateConfig(c); err != nil {
			t.Fatal(err)
		}
	}

	name := "vettid-p2-" + randHex(4)
	pd, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(pd, name)
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// Any process still running from the folder (a child the test
		// lost track of) is named and ended, then the folder removed; an
		// image that just ended may be held a moment longer.
		endProcessesUnder(t, dir)
		var err error
		for end := time.Now().Add(20 * time.Second); ; time.Sleep(500 * time.Millisecond) {
			if err = os.RemoveAll(dir); err == nil || time.Now().After(end) {
				break
			}
		}
		if err != nil {
			t.Errorf("removing %s: %v", dir, err)
		}
	})
	// The three services (hop, shapes, seclogon disabled) may read and
	// write here; Users may read the binary.
	hSID, sSID, dSID, aSID := channel.ServiceSID(name+"h"), channel.ServiceSID(name+"s"), channel.ServiceSID(name+"d"), channel.ServiceSID(name+"a")
	protectDir(t, dir, "D:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;0x1301bf;;;"+hSID+")(A;OICI;0x1301bf;;;"+sSID+")(A;OICI;0x1301bf;;;"+dSID+")(A;OICI;0x1301bf;;;"+aSID+")(A;OICI;0x1200a9;;;BU)")
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(dir, "probe.exe")
	b, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(exe, b, 0o755); err != nil {
		t.Fatal(err)
	}
	// Three classes run as the Interactive User: one only INTERACTIVE may
	// launch (first: the plan's case), one with no launch permission of
	// its own (the machine's default), one Authenticated Users may launch.
	clsid := "interactive-only=" + registerClass(t, exe, "O:BAG:BAD:(A;;0xb;;;IU)(A;;0xb;;;SY)(A;;0xb;;;BA)") +
		",machine-default=" + registerClass(t, exe, "") +
		",authenticated-users=" + registerClass(t, exe, "O:BAG:BAD:(A;;0xb;;;AU)(A;;0xb;;;SY)(A;;0xb;;;BA)")
	bDenies := []string{"SeDenyRemoteInteractiveLogonRight", "SeDenyNetworkLogonRight"}
	bGrants := []string{"SeInteractiveLogonRight"}

	// First, while no process the secondary logon service started runs
	// (it does not stop while one does).
	t.Run("seclogon-disabled", func(t *testing.T) {
		// seclogon does not stop while a process it started runs. This
		// subtest runs first, so there must be none.
		if n := endProcessesUnder(t, dir); n != 0 {
			t.Errorf("%d processes from the probe's folder already running", n)
		}
		users := map[string]probeUser{"b": newShapedUser(t, dir, dSID, bGrants, bDenies, false)}
		c := c0
		c.StartType = mgr.StartDisabled
		if err := sl.UpdateConfig(c); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			c := c0
			c.StartType = mgr.StartManual
			if err := sl.UpdateConfig(c); err != nil {
				t.Errorf("seclogon back to Manual: %v", err)
			}
		})
		// 1052 (not valid now): seclogon is already stopping.
		if _, err := sl.Control(svc.Stop); err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) && !errors.Is(err, windows.ERROR_INVALID_SERVICE_CONTROL) {
			t.Fatalf("stopping seclogon: %v", err)
		}
		// Until it has stopped: a stop asked while seclogon is busy is
		// refused (1052), so it is asked again.
		for end := time.Now().Add(90 * time.Second); ; time.Sleep(time.Second) {
			if st, err := sl.Query(); err == nil && st.State == svc.Stopped {
				break
			}
			if time.Now().After(end) {
				t.Fatal("seclogon did not stop; nothing measured")
			}
			_, _ = sl.Control(svc.Stop)
		}
		res := runProbe2Service(t, m, name+"d", mustSID(t, dSID), dir, exe,
			probe2Config{Exe: exe, Mode: "shapes", Users: users, Shapes: []string{"b"}})
		t.Logf("seclogon disabled: %v", res.Shapes)
		if !strings.HasPrefix(res.Shapes["b"], "errno 1058:") {
			t.Errorf("with seclogon disabled: %s, want errno 1058 (the service is disabled)", res.Shapes["b"])
		}
	})
	t.Run("hop", func(t *testing.T) {
		// Step 3 adds another runner ("c") and a plain user ("m"), who try
		// the report pipe, and the GUI-subsystem copy of the binary.
		users := map[string]probeUser{
			"b": newShapedUser(t, dir, hSID, bGrants, bDenies, false),
			"c": newShapedUser(t, dir, hSID, bGrants, bDenies, false),
			"m": newShapedUser(t, dir, hSID, nil, nil, false),
		}
		exeGUI := filepath.Join(dir, "probe-gui.exe")
		if err := guiCopy(exe, exeGUI); err != nil {
			t.Fatalf("the GUI-subsystem copy: %v", err)
		}
		res := runProbe2Service(t, m, name+"h", mustSID(t, hSID), dir, exe,
			probe2Config{Exe: exe, ExeGUI: exeGUI, CLSID: clsid, Mode: "hop", Users: users, ToolsFile: writeTools(t, dir)})
		probe2ExpectHop(t, res, users["b"], exe)
		probe3Expect(t, res, users["b"], exe)
		// The no-job hop's program outlives its hop (the service may not end
		// it): the test, an administrator, ends it here.
		if pid := res.Hops["no-job-with-window"].Launcher.WaitingPID; pid == 0 {
			t.Errorf("no-job hop: no waiting program recorded")
		} else if img := imagesOf([]uint32{pid})[pid]; !strings.EqualFold(img, filepath.Base(exe)) && !strings.EqualFold(img, exe) {
			t.Errorf("no-job hop: program %d is %q, not running as %s", pid, img, filepath.Base(exe))
		} else {
			p, err := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, pid)
			if err == nil {
				err = windows.TerminateProcess(p, 1)
				if err == nil {
					if ev, _ := windows.WaitForSingleObject(p, 10000); ev != windows.WAIT_OBJECT_0 {
						err = errors.New("did not end")
					}
				}
				windows.CloseHandle(p)
			}
			if err != nil {
				t.Errorf("ending the no-job hop's program %d: %v", pid, err)
			}
		}
	})
	// Route A, as a contrast: the service holds SeAssignPrimaryTokenPrivilege
	// and starts the user32 child itself with CreateProcessAsUser.
	t.Run("route-a", func(t *testing.T) {
		users := map[string]probeUser{"a": newShapedUser(t, dir, aSID, []string{"SeBatchLogonRight"}, bDenies, false)}
		sid := mustSID(t, aSID)
		if err := lsaRight(sid, "SeAssignPrimaryTokenPrivilege", true); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := lsaRight(sid, "SeAssignPrimaryTokenPrivilege", false); err != nil {
				t.Errorf("removing SeAssignPrimaryTokenPrivilege: %v", err)
			}
		})
		res := runProbe2Service(t, m, name+"a", sid, dir, exe, probe2Config{Exe: exe, Mode: "route-a", Users: users,
			Required: []string{"SeChangeNotifyPrivilege", "SeAssignPrimaryTokenPrivilege"}})
		if res.RouteA == nil {
			t.Fatal("no route A record")
		}
		t.Logf("route A: assign %s, station entry %s, desktop %s, logon %s", res.RouteA.EnableAssign, res.RouteA.WindowStationACE, res.RouteA.Desktop, res.RouteA.Logon)
		if res.RouteA.EnableAssign != "ok" || res.RouteA.WindowStationACE != "ok" || res.RouteA.Desktop != "ok" || res.RouteA.Logon != "ok" {
			t.Errorf("route A's setup: %+v", res.RouteA)
		}
		// Measured: user32 initializes for route A's child on an explicit
		// desktop of the run's own and on the service's own (Default).
		for key, prefix := range map[string]string{"explicit-desktop": "runa-", "inherited-desktop": "Default"} {
			s, ok := res.RouteA.Starts[key]
			t.Logf("route A %s: start %s, exit %s, desktop %q, beep %q, output %.300s", key, s.Start, s.Exit, s.Record.Desktop, s.Record.Beep, s.Output)
			if !ok || s.Start != "ok" || s.Exit != "exit 0x0" || !strings.HasPrefix(s.Record.Desktop, prefix) || s.Record.Beep != "ok" {
				t.Errorf("route A %s: %+v, measured user32 working there", key, s)
			}
		}
	})
	t.Run("shapes", func(t *testing.T) {
		users := map[string]probeUser{
			"b":              newShapedUser(t, dir, sSID, bGrants, bDenies, false),
			"b-no-grant":     newShapedUser(t, dir, sSID, nil, bDenies, false),
			"b-deny-console": newShapedUser(t, dir, sSID, bGrants, append([]string{"SeDenyInteractiveLogonRight"}, bDenies...), false),
			"b-must-change":  newShapedUser(t, dir, sSID, bGrants, bDenies, true),
		}
		res := runProbe2Service(t, m, name+"s", mustSID(t, sSID), dir, exe,
			probe2Config{Exe: exe, Mode: "shapes", Users: users, Shapes: []string{"b", "b-no-grant", "b-deny-console", "b-must-change"}})
		t.Logf("shapes: %v", res.Shapes)
		if res.Shapes["b"] != "ok" {
			t.Errorf("B's runner: %s", res.Shapes["b"])
		}
		// The Users group holds the interactive logon right here, so B's
		// runner works without its explicit grant too.
		if !strings.HasPrefix(res.Shapes["b-must-change"], "errno 1907:") {
			t.Errorf("B's runner whose password must change: %s, want errno 1907", res.Shapes["b-must-change"])
		}
		if res.Shapes["b-no-grant"] != "ok" {
			t.Errorf("B's runner without its grant: %s", res.Shapes["b-no-grant"])
		}
		if !strings.HasPrefix(res.Shapes["b-deny-console"], "errno 1385:") {
			t.Errorf("B's runner denied the console: %s, want errno 1385", res.Shapes["b-deny-console"])
		}
	})
}

func mustSID(t *testing.T, s string) *windows.SID {
	t.Helper()
	sid, err := windows.StringToSid(s)
	if err != nil {
		t.Fatal(err)
	}
	return sid
}

// probe2Hops are the hops runHops makes; each must be in the record.
var probe2Hops = []string{"interactive", "interactive-no-ui-limits", "interactive+local", "null-dacl-desktop",
	"seclogon-default-desktop", "no-job-with-window", "exit-after", "service-in-default-dacl", "handoff", "handoff-locked", "handoff-locked-detached-program", "handoff-locked-detached"}

// probe2ExpectHop checks each recorded value against what was measured
// (no check depends on another step having worked); what a run measures
// for the first time is logged, then pinned.
func probe2ExpectHop(t *testing.T, r probe2Result, u probeUser, exe string) {
	t.Helper()
	// The cut1 account may not make a named window station; a desktop of
	// the run's own in the service's station, with the runner added to it,
	// works.
	if !strings.HasPrefix(r.WindowStation, "CreateWindowStation: Access is denied") {
		t.Errorf("named window station: %q, measured denied", r.WindowStation)
	}
	if r.WindowStationACE != "ok" || r.Desktop != "ok" {
		t.Errorf("the runner's entry on the service's station %q, desktop %q", r.WindowStationACE, r.Desktop)
	}
	// Measured: with no name, CreateWindowStation gives the service's own
	// station (the one named after its logon session), not a new one.
	if r.UnnamedWindowStation != "ok: "+r.ServiceWindowStation {
		t.Errorf("window station with no name: %q, measured the service's own (%s)", r.UnnamedWindowStation, r.ServiceWindowStation)
	}
	t.Logf("a hop on it (before the runner's entry is added): %+v", r.UnnamedHop)
	t.Logf("window station and desktop access: %s", r.WindowStationSDDL)

	for _, key := range probe2Hops {
		h, ok := r.Hops[key]
		if !ok {
			t.Errorf("hop %s: missing from the record", key)
			continue
		}
		where := "hop " + key
		noJob := key == "no-job-with-window"
		wantLimits, wantJob := "ok", "ok"
		if key == "interactive-no-ui-limits" || noJob {
			wantLimits = "not set"
		}
		if noJob {
			wantJob = "no job (this variant)"
		}
		if key == "handoff-locked-detached" {
			// Measured: seclogon does not take DETACHED_PROCESS for the
			// launcher. The launcher keeps CREATE_NO_WINDOW; its conhost
			// ends with it, before the program runs.
			if h.Start != "The parameter is incorrect." {
				t.Errorf("%s: CreateProcessWithLogonW with DETACHED_PROCESS: %q, measured The parameter is incorrect.", where, h.Start)
			}
			continue
		}
		if h.Start != "ok" || h.Job != wantJob || h.UILimits != wantLimits {
			t.Errorf("%s: start %q, job %q, UI limits %q", where, h.Start, h.Job, h.UILimits)
			continue
		}
		l := h.Launcher
		if l.Token.User != u.SID || l.ServiceSentinel || l.Restricted != "ok" {
			t.Errorf("%s: launcher as %s (want %s), service handle inherited %v, restricted token %s", where, l.Token.User, u.SID, l.ServiceSentinel, l.Restricted)
			continue
		}
		if strings.HasPrefix(key, "handoff") {
			// The design's shape, each step asserted: the launcher gone, and
			// every handle of the service's to it closed, before the resume;
			// the service opens the suspended program and its thread, reads
			// the image, finds it in the job, checks the thread is the
			// program's, resumes it. The program then tries to open its
			// launcher (process, thread, token) and runs to exit 0.
			locked := strings.HasPrefix(key, "handoff-locked")
			detached := strings.Contains(key, "detached")
			hr := h.Handoff
			if hr == nil {
				t.Errorf("%s: no handoff record (launcher: %s)", where, l.Restricted)
				continue
			}
			t.Logf("%s: %+v; the launcher read %q, set the thread's DACL: %s; its token before the lock %s, lock %q (after: %s), process lock %q", where,
				*hr, l.HandoffImage, l.ThreadDACL, l.TokenSDDLBefore, l.TokenLock, l.TokenSDDL, l.ProcessLock)
			t.Logf("%s: the other processes in the program's job, as it reaches them: %+v", where, hr.Program.JobProcs)
			if l.ThreadDACL != "ok" || l.DefaultDACL != "ok" || !strings.EqualFold(l.HandoffImage, exe) {
				t.Errorf("%s: launcher: default DACL %q, thread DACL %q, image %q", where, l.DefaultDACL, l.ThreadDACL, l.HandoffImage)
			}
			if locked && (l.TokenLock != "ok" || l.ProcessLock != "ok") {
				t.Errorf("%s: the launcher locking its token %q, its process %q", where, l.TokenLock, l.ProcessLock)
			}
			if hr.LauncherGone != "true" || hr.Open != "ok" || hr.OpenThread != "ok" || !strings.EqualFold(hr.Image, exe) ||
				hr.InJob != "true" || hr.Resume != "ok (was suspended 1)" || hr.Exit != "exit 0x0" {
				t.Errorf("%s: %+v", where, *hr)
			}
			if pt := hr.Program.Token; pt.User != u.SID || pt.Interactive != "deny-only" || pt.Local != "absent" ||
				!sameSet(pt.Privileges, []string{"SeChangeNotifyPrivilege+"}) {
				t.Errorf("%s: the program's token %+v", where, pt)
			}
			// The program opening its exited launcher. Measured: with every
			// handle of the service's closed, the launcher's process object is
			// still there (the same process, by its creation time: something
			// besides the service holds it), its threads are gone.
			// - Closed handles alone: the program opens the process and the
			//   token with each right, and a copy of the token holds
			//   INTERACTIVE enabled.
			// - With the launcher's token and process locked as well: every
			//   open refused. The lock is what keeps the program out.
			// With no console for the program as well, the process object is
			// still there: a conhost is not what holds it.
			ol := hr.Program.OpenLauncher
			if hr.Program.TargetIdentity != "launcher" {
				t.Errorf("%s: the launcher's id when the program ran: %q, measured still the launcher", where, hr.Program.TargetIdentity)
			}
			// The launcher's token before the lock: owned by the runner, so the
			// lock's OWNER RIGHTS entry applies to the runner.
			if locked && !strings.HasPrefix(l.TokenSDDLBefore, "O:"+u.SID+"D:") {
				t.Errorf("%s: the launcher's token before the lock: %q, measured owned by the runner", where, l.TokenSDDLBefore)
			}
			want, wantCopy := "ok", "enabled"
			if locked {
				want, wantCopy = "Access is denied.", ""
				// The lock holds against the launcher itself: it may no longer
				// read its own token's access list.
				if l.TokenSDDL != "OpenProcessToken: Access is denied." {
					t.Errorf("%s: the launcher reading its locked token: %q, measured Access is denied.", where, l.TokenSDDL)
				}
			}
			rights := []string{"PROCESS_VM_WRITE", "PROCESS_CREATE_THREAD", "WRITE_DAC", "TOKEN_DUPLICATE", "TOKEN_IMPERSONATE"}
			if locked {
				// The locked token's own access list may not be read or changed
				// either, nor its owner.
				rights = append(rights, "TOKEN_READ_CONTROL", "TOKEN_WRITE_DAC", "TOKEN_WRITE_OWNER")
			}
			if !locked {
				// Unlocked, the token's own access list may be read and
				// changed, and its owner too.
				rights = append(rights, "TOKEN_READ_CONTROL", "TOKEN_WRITE_DAC", "TOKEN_WRITE_OWNER")
			}
			for _, right := range rights {
				if v := ol[right]; v != want {
					t.Errorf("%s: the program opening its launcher with %s: %q, measured %q", where, right, v, want)
				}
			}
			for _, right := range []string{"THREAD_SET_CONTEXT", "THREAD_SUSPEND_RESUME"} {
				if v := ol[right]; v != "The parameter is incorrect." {
					t.Errorf("%s: the program opening its launcher's thread with %s: %q, measured gone (The parameter is incorrect.)", where, right, v)
				}
			}
			if hr.Program.LauncherTokenInteractive != wantCopy {
				t.Errorf("%s: INTERACTIVE in a copy of the launcher's token: %q, measured %q", where, hr.Program.LauncherTokenInteractive, wantCopy)
			}
			// The other processes in the program's job. Measured: with no
			// console, none. With one, only the program's own conhost (the
			// launcher's ended with it), which the program may open and whose
			// token it may open, but which runs with the program's own
			// restricted token (INTERACTIVE deny-only): nothing more to gain.
			if detached {
				if len(hr.Program.JobProcs) != 0 {
					t.Errorf("%s: other processes in the program's job: %+v, measured none", where, hr.Program.JobProcs)
				}
			} else {
				if len(hr.Program.JobProcs) != 1 {
					t.Errorf("%s: other processes in the program's job: %+v, measured its conhost only", where, hr.Program.JobProcs)
				}
				for pid, rp := range hr.Program.JobProcs {
					if rp.Image != "conhost.exe" || rp.VMWrite != "ok" || rp.Token != "ok" || rp.TokenUser != u.SID || rp.Interactive != "deny-only" {
						t.Errorf("%s: process %d in the program's job: %+v, measured its conhost with the program's own token", where, pid, rp)
					}
				}
			}
			if h.Kill != "ok (the launcher)" {
				t.Errorf("%s: closing the job: %s", where, h.Kill)
			}
			continue
		}
		if key == "exit-after" {
			// The contrast for the handoff's closed handles. Measured: the
			// launcher has exited, but the service's handle to it keeps its
			// process object and its token alive, and the program opens both
			// with each right; a copy of the token holds INTERACTIVE enabled.
			if h.ExitAfter.LauncherRunning != "false" {
				t.Errorf("%s: the launcher running when the program checked: %q, measured false", where, h.ExitAfter.LauncherRunning)
			}
			for _, right := range []string{"PROCESS_VM_WRITE", "PROCESS_CREATE_THREAD", "WRITE_DAC", "TOKEN_DUPLICATE", "TOKEN_IMPERSONATE"} {
				if v := h.ExitAfter.OpenLauncher[right]; v != "ok" {
					t.Errorf("%s: the program opening its exited launcher with %s: %q, measured ok", where, right, v)
				}
			}
			if v := h.ExitAfter.LauncherTokenInteractive; v != "enabled" {
				t.Errorf("%s: INTERACTIVE in a copy of the exited launcher's token: %q, measured enabled", where, v)
			}
			continue
		}

		// The program: its token, its image, no inheritance.
		p, ok := l.Children["program"]
		if !ok || p.Start != "ok" || p.Exit != "exit 0x0" || !strings.EqualFold(p.ImageName, exe) {
			t.Errorf("%s: program %+v", where, p)
		}
		if p.Record.Token.User != u.SID || p.Record.Token.Interactive != "deny-only" || p.Record.Token.Batch != "absent" ||
			p.Record.SentinelInherits || !sameSet(p.Record.Token.Privileges, []string{"SeChangeNotifyPrivilege+"}) {
			t.Errorf("%s: program's token %+v, launcher handle inherited %v", where, p.Record.Token, p.Record.SentinelInherits)
		}
		// LOCAL: absent from the runner's token on a desktop of the run's
		// own; seclogon's own desktop gives it, enabled.
		wantLocal := "absent"
		if h.Desktop == "" {
			wantLocal = "enabled"
		}
		if l.Token.Local != wantLocal || p.Record.Token.Local != wantLocal {
			t.Errorf("%s: LOCAL: launcher %s, program %s, measured %s", where, l.Token.Local, p.Record.Token.Local, wantLocal)
		}

		// The service and the program: the service may not open it (the
		// runner's default DACL) unless it is named there (measured, then
		// pinned); without a job it may not end it; with one, closing the
		// job ends the launcher and the program (the job's messages).
		switch {
		case key == "service-in-default-dacl":
			if l.DefaultDACL != "ok" {
				t.Errorf("%s: setting the program's default DACL: %s", where, l.DefaultDACL)
			}
			// Measured: named there, the service may open the program, and so
			// end it and read its image itself.
			if h.ServiceOpen != "ok" || !strings.EqualFold(h.ServiceName, exe) {
				t.Errorf("%s: the service opening the program: %q, image %q; measured ok, %s", where, h.ServiceOpen, h.ServiceName, exe)
			}
		case h.Desktop == "":
			if h.ServiceOpen != "ok" {
				t.Errorf("%s: the service opening the program on seclogon's desktop: %q, measured ok", where, h.ServiceOpen)
			}
		case noJob:
			if h.ServiceOpen != "" {
				t.Errorf("%s: open tried without a job: %q", where, h.ServiceOpen)
			}
		default:
			if h.ServiceOpen != "Access is denied." {
				t.Errorf("%s: the service opening the program: %q, measured Access is denied.", where, h.ServiceOpen)
			}
		}
		if noJob {
			if !strings.Contains(h.Kill, "may not end the program: Access is denied.") {
				t.Errorf("%s: %s, measured: the service may not end the program", where, h.Kill)
			}
		} else {
			if !slicesContain(h.JobPIDs, l.WaitingPID) {
				t.Errorf("%s: the waiting program %d not in the job %v", where, l.WaitingPID, h.JobPIDs)
			}
			if h.Kill != "ok" {
				t.Errorf("%s: closing the job: %s", where, h.Kill)
			}
			t.Logf("%s: in the job: %v; ended when it closed: %v", where, h.JobImages, h.JobExits)
		}

		// user32 and DCOM.
		u32 := l.Children["user32"]
		if h.Desktop == "" {
			// seclogon's own desktop (lpDesktop null; the plan rules it
			// out): user32 does not initialize there.
			if !strings.Contains(l.LauncherUser32, "initialization routine failed") {
				t.Errorf("%s: user32 on seclogon's own desktop: %s, measured the DLL initialization failure", where, l.LauncherUser32)
			}
		} else {
			want := h.Desktop[strings.LastIndex(h.Desktop, `\`)+1:]
			if l.LauncherUser32 != "ok" || u32.Exit != "exit 0x0" || u32.Record.Desktop != want || u32.Record.Beep != "ok" {
				t.Errorf("%s: user32: launcher %s; child %+v, want it on %q", where, l.LauncherUser32, u32, want)
			}
			// The class only INTERACTIVE may launch: refused with INTERACTIVE
			// deny-only, past the launch check with it enabled (its throwaway
			// server never registers).
			if d := l.Children["dcom"].Record.DCOM; d != "HRESULT 0x80070005" {
				t.Errorf("%s: DCOM with INTERACTIVE deny-only: %q, measured HRESULT 0x80070005", where, d)
			}
			if d := l.Children["dcom-unrestricted"].Record.DCOM; d != "HRESULT 0x80080005" {
				t.Errorf("%s: DCOM with INTERACTIVE enabled: %q, measured HRESULT 0x80080005", where, d)
			}
			// By class, with INTERACTIVE deny-only. Measured: the machine's
			// default refuses it too; a class Authenticated Users may launch
			// passes the launch check (its server then never registers).
			for class, want := range map[string]string{"interactive-only": "HRESULT 0x80070005", "machine-default": "HRESULT 0x80070005", "authenticated-users": "HRESULT 0x80080005"} {
				if got := l.Children["dcom"].Record.DCOMs[class]; got != want {
					t.Errorf("%s: DCOM class %s with INTERACTIVE deny-only: %q, measured %s", where, class, got, want)
				}
			}
		}

		// The program opening its launcher (the same user): as it is, and
		// after the launcher limits its own DACL (logged, then pinned).
		// Measured: as it is, the program may open its launcher with each
		// right; after the launcher's OWNER RIGHTS DACL, with none.
		open, limited := l.Children["open-launcher"].Record.OpenLauncher, l.Children["open-launcher-limited"].Record.OpenLauncher
		if l.LauncherDACL != "ok" {
			t.Errorf("%s: the launcher's own DACL: %s", where, l.LauncherDACL)
		}
		for _, right := range []string{"PROCESS_VM_WRITE", "PROCESS_CREATE_THREAD", "WRITE_DAC"} {
			if open[right] != "ok" || limited[right] != "Access is denied." {
				t.Errorf("%s: the program opening its launcher with %s: %q, after the launcher's DACL %q; measured ok, then Access is denied.", where, right, open[right], limited[right])
			}
		}

		// Contrast for the handoff. While the launcher waits, the program
		// may open its thread and its token, before and after the
		// launcher's process DACL (which guards the process object only);
		// a copy of the token holds INTERACTIVE enabled. Measured.
		for _, right := range []string{"THREAD_SET_CONTEXT", "THREAD_SUSPEND_RESUME", "TOKEN_DUPLICATE", "TOKEN_IMPERSONATE"} {
			if open[right] != "ok" || limited[right] != "ok" {
				t.Errorf("%s: the program opening its launcher's %s: %q, after the launcher's DACL %q; measured ok both", where, right, open[right], limited[right])
			}
		}
		for step, c := range map[string]childStart{"before": l.Children["open-launcher"], "after": l.Children["open-launcher-limited"]} {
			if c.Record.LauncherTokenInteractive != "enabled" {
				t.Errorf("%s: INTERACTIVE in a copy of the launcher's token (%s its DACL): %q, measured enabled", where, step, c.Record.LauncherTokenInteractive)
			}
		}

		// The job's UI limits, from the program. Measured, with the hop
		// without them as the contrast:
		// - CreateDesktop: refused under them, ok without;
		// - global atoms: separate both ways under them, shared without;
		// - SwitchDesktop: refused either way (not a test of the limit);
		// - ExitWindowsEx (tried under them only): fails, with last error 0.
		ui := l.Children["uilimits"].Record.UI
		const notFound = "The system cannot find the file specified."
		var want map[string]string
		switch {
		case h.Desktop == "":
			want = map[string]string{"user32": "A dynamic link library (DLL) initialization routine failed."}
		case h.UILimits == "ok":
			want = map[string]string{"CreateDesktop": "Access is denied.", "SwitchDesktop": "Access is denied.",
				"ExitWindowsEx": "The operation completed successfully.", "GlobalFindAtom(the service's)": notFound, "GlobalAddAtom": "ok"}
		default:
			want = map[string]string{"CreateDesktop": "ok", "SwitchDesktop": "Access is denied.", "GlobalFindAtom(the service's)": "found", "GlobalAddAtom": "ok"}
		}
		if !maps.Equal(ui, want) {
			t.Errorf("%s: UI calls from the program: %v, measured %v", where, ui, want)
		}
		wantAtom := notFound
		if h.UILimits != "ok" {
			wantAtom = "found"
		}
		if h.ServiceSeesAtomB != wantAtom {
			t.Errorf("%s: the service finding the program's atom: %q, measured %q", where, h.ServiceSeesAtomB, wantAtom)
		}

		if key == "interactive" {
			if len(l.Tools) == 0 {
				t.Errorf("%s: no tools were started", where)
			}
			for name, tl := range l.Tools {
				if tl.Start != "ok" || tl.Exit != "exit 0x0" {
					t.Errorf("%s: %s as the run's program: %+v", where, name, tl)
				}
			}
		}
	}

	// The runner's entry on the window station, mask by mask.
	for _, mask := range probeMasks {
		key := fmt.Sprintf("%#x", mask)
		m, ok := r.Masks[key]
		if !ok {
			t.Errorf("window station entry %s: missing from the record", key)
			continue
		}
		t.Logf("window station entry %s: set %s, start %s, launcher user32 %s, child %q", key, m.Set, m.Start, m.Launcher, m.Child)
	}
	// Measured: READ_CONTROL is the standard right needed, and
	// WINSTA_EXITWINDOWS is needed; WINSTA_ALL_ACCESS alone fails.
	// 0x2007A works; without EXITWINDOWS (0x2003A) or ACCESSGLOBALATOMS
	// (0x2005A) it fails, and without any one of the other three it works.
	// So do all three together: 0x20060 (READ_CONTROL, EXITWINDOWS,
	// ACCESSGLOBALATOMS) is the narrowest, as each of the three is missing
	// from a mask that fails holding the other two (0x37F, 0x2003A,
	// 0x2005A).
	for key, works := range map[string]bool{"0x37f": false, "0x2037f": true, "0x6037f": true, "0x2033f": false, "0x2007a": true, "0x2003a": false,
		"0x20078": true, "0x20072": true, "0x2006a": true, "0x2005a": false,
		"0x20060": true, "0x20070": true, "0x20068": true, "0x20062": true} {
		// In the launcher and in its restricted child alike.
		m := r.Masks[key]
		launcherOK, childOK := m.Launcher == "ok", strings.HasPrefix(m.Child, "run-")
		if launcherOK != works || childOK != works {
			t.Errorf("window station entry %s: user32 in the launcher %v, in the restricted child %v (%q); measured %v", key, launcherOK, childOK, m.Child, works)
		}
	}
}

func slicesContain(s []uint32, v uint32) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// grantWindowStation adds an entry for the runner to the window station's
// access list (it needs the window station to use a desktop in it).
func grantWindowStation(ws windows.Handle, runner string) error {
	return setWindowStationEntry(ws, runner, 0xf037f, windows.GRANT_ACCESS)
}

// setWindowStationEntry sets (SET_ACCESS) or adds to (GRANT_ACCESS) the
// runner's entry on the window station's access list.
func setWindowStationEntry(ws windows.Handle, runner string, mask uint32, mode windows.ACCESS_MODE) error {
	sd, err := windows.GetSecurityInfo(ws, windows.SE_WINDOW_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("reading its access: %w", err)
	}
	old, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("reading its access: %w", err)
	}
	sid, err := windows.StringToSid(runner)
	if err != nil {
		return err
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.ACCESS_MASK(mask),
		AccessMode:        mode,
		Trustee:           windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_USER, TrusteeValue: windows.TrusteeValueFromSID(sid)},
	}}, old)
	if err != nil {
		return err
	}
	if err := windows.SetSecurityInfo(ws, windows.SE_WINDOW_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		return fmt.Errorf("setting its access: %w", err)
	}
	return nil
}

// probeTool is a real program to start as the run's program would be.
type probeTool struct {
	Name string `json:"name"`
	Exe  string `json:"exe"`
	Args string `json:"args"`
}

// runTools starts each tool of the -p2-tools file with the restricted
// token, as the run's program, and records how it ended (0xC0000142: a
// DLL, user32 or ole32, could not initialize).
func runTools(tok windows.Token, dir string) map[string]childStart {
	if *p2Tools == "" {
		return nil
	}
	b, err := os.ReadFile(*p2Tools)
	if err != nil {
		return map[string]childStart{"(tools)": {Start: err.Error()}}
	}
	var tools []probeTool
	if err := json.Unmarshal(b, &tools); err != nil {
		return map[string]childStart{"(tools)": {Start: err.Error()}}
	}
	out := map[string]childStart{}
	for _, tl := range tools {
		out[tl.Name] = startChild(tok, tl.Exe, tl.Args, filepath.Join(dir, "tool-"+tl.Name+"-"+randHex(4)+".log"), 60*time.Second)
	}
	return out
}

// logonSID is the token's logon SID (the group with SE_GROUP_LOGON_ID).
func logonSID(tok windows.Token) string {
	g, err := tok.GetTokenGroups()
	if err != nil {
		return err.Error()
	}
	for _, x := range g.AllGroups() {
		if x.Attributes&windows.SE_GROUP_LOGON_ID != 0 {
			return x.Sid.String()
		}
	}
	return "none"
}

// startDesktop, when set, is the desktop startSuspended starts on
// (route A's explicit desktop).
var startDesktop string

// routeAResult is route A: the service holding SeAssignPrimaryTokenPrivilege
// starts the user32 child with CreateProcessAsUser and a batch logon token,
// as a contrast with the secondary logon route.
type routeAResult struct {
	EnableAssign     string                `json:"enable_assign_primary_token"`
	WindowStationACE string                `json:"window_station_ace"`
	Desktop          string                `json:"desktop"`
	Logon            string                `json:"batch_logon"`
	Starts           map[string]childStart `json:"starts"` // explicit-desktop, inherited-desktop
}

func runRouteA(c probe2Config) *routeAResult {
	r := &routeAResult{Starts: map[string]childStart{}}
	var proc windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &proc); err != nil {
		r.EnableAssign = err.Error()
		return r
	}
	defer proc.Close()
	r.EnableAssign = errString(setPrivilege(proc, "SeAssignPrimaryTokenPrivilege", true))
	a := c.Users["a"]
	cur, _, _ := procGetProcessWindowStation.Call()
	name := make([]uint16, 256)
	var n uint32
	procGetUserObjectInformation.Call(cur, 2, uintptr(unsafe.Pointer(&name[0])), uintptr(len(name)*2), uintptr(unsafe.Pointer(&n)))
	ws := windows.UTF16ToString(name)
	if restore, err := keepStationDACL(windows.Handle(cur)); err == nil {
		defer restore()
	}
	r.WindowStationACE = errString(grantWindowStation(windows.Handle(cur), a.SID))
	sa, err := userObjectSA(a.SID)
	if err != nil {
		r.Desktop = err.Error()
		return r
	}
	deskName := "runa-" + randHex(4)
	dn, _ := windows.UTF16PtrFromString(deskName)
	desk, _, e := procCreateDesktopW.Call(uintptr(unsafe.Pointer(dn)), 0, 0, 0, uintptr(windows.MAXIMUM_ALLOWED), uintptr(unsafe.Pointer(sa)))
	if desk == 0 {
		r.Desktop = "CreateDesktop: " + e.Error()
		return r
	}
	defer procCloseDesktop.Call(desk)
	r.Desktop = "ok"
	var tok windows.Token
	un, _ := windows.UTF16PtrFromString(a.Name)
	dot, _ := windows.UTF16PtrFromString(".")
	pw, _ := windows.UTF16PtrFromString(a.Password)
	if ok, _, e := procLogonUserW.Call(uintptr(unsafe.Pointer(un)), uintptr(unsafe.Pointer(dot)), uintptr(unsafe.Pointer(pw)),
		4 /* LOGON32_LOGON_BATCH */, 0, uintptr(unsafe.Pointer(&tok))); ok == 0 {
		r.Logon = e.Error()
		return r
	}
	defer tok.Close()
	r.Logon = "ok"
	for _, d := range []struct{ key, desktop string }{{"explicit-desktop", ws + `\` + deskName}, {"inherited-desktop", ""}} {
		out := filepath.Join(a.OutDir, "routea-"+randHex(4)+".json")
		startDesktop = d.desktop
		cs := startChild(tok, c.Exe, fmt.Sprintf(`-test.run=^TestProbe2ChildHelper$ -p2-mode=user32 -p2-out="%s"`, out),
			filepath.Join(filepath.Dir(c.Exe), "routea-"+randHex(4)+".log"), 60*time.Second)
		startDesktop = ""
		if b, err := os.ReadFile(out); err == nil {
			_ = json.Unmarshal(b, &cs.Record)
		}
		r.Starts[d.key] = cs
	}
	return r
}

// writeTools writes the real tools this runner has (git, node, npm, ssh,
// python), for the launcher to start as the run's program; npm's .cmd
// through cmd.exe, as a batch run would be.
func writeTools(t *testing.T, dir string) string {
	t.Helper()
	var tools []probeTool
	for _, c := range []struct{ name, file, args string }{
		{"git", "git.exe", "--version"},
		{"node", "node.exe", "-e 0"},
		{"npm", "npm.cmd", "--version"},
		{"ssh", "ssh.exe", "-V"},
		{"python", "python.exe", "-c 0"},
	} {
		p, err := exec.LookPath(c.file)
		if err != nil {
			// The runner has each of these: a missing one is a change to know of.
			t.Errorf("no %s on this runner", c.file)
			continue
		}
		if strings.HasSuffix(strings.ToLower(p), ".cmd") {
			cmdExe := filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe")
			tools = append(tools, probeTool{Name: c.name, Exe: cmdExe, Args: `/d /c ""` + p + `" ` + c.args + `"`})
			continue
		}
		tools = append(tools, probeTool{Name: c.name, Exe: p, Args: c.args})
	}
	path := filepath.Join(dir, "tools.json")
	b, _ := json.Marshal(tools)
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("tools: %s", b)
	return path
}

// endProcessesUnder ends, and names, every process whose image is under
// dir: one still running when the test ends is a finding (it was not
// ended by its job or its parent), recorded here.
func endProcessesUnder(t *testing.T, dir string) int {
	found := 0
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		t.Logf("process snapshot: %v", err)
		return 0
	}
	defer windows.CloseHandle(snap)
	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	for err = windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		p, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, e.ProcessID)
		if err != nil {
			continue
		}
		buf := make([]uint16, windows.MAX_LONG_PATH)
		n := uint32(len(buf))
		if windows.QueryFullProcessImageName(p, 0, &buf[0], &n) == nil {
			img := windows.UTF16ToString(buf[:n])
			if strings.HasPrefix(strings.ToLower(img), strings.ToLower(dir)+`\`) {
				var user string
				var tok windows.Token
				if windows.OpenProcessToken(p, windows.TOKEN_QUERY, &tok) == nil {
					if u, err := tok.GetTokenUser(); err == nil {
						user = u.User.Sid.String()
					}
					tok.Close()
				}
				found++
				t.Logf("still running: pid %d, %s, as %s; ended", e.ProcessID, img, user)
				_ = windows.TerminateProcess(p, 1)
				_, _ = windows.WaitForSingleObject(p, 5000)
			}
		}
		windows.CloseHandle(p)
	}
	return found
}

// jobExits collects, for up to d, the job's messages that a process
// ended (JOB_OBJECT_MSG_EXIT_PROCESS, _ABNORMAL_EXIT_PROCESS), until the
// job says it has none left (JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO), and
// returns the ended processes' ids.
func jobExits(port windows.Handle, d time.Duration) []uint32 {
	var pids []uint32
	for end := time.Now().Add(d); time.Now().Before(end); {
		var msg uint32
		var key uintptr
		var ov *windows.Overlapped
		if err := windows.GetQueuedCompletionStatus(port, &msg, &key, &ov, uint32(time.Until(end).Milliseconds())); err != nil {
			break
		}
		switch msg {
		case 7, 8: // JOB_OBJECT_MSG_EXIT_PROCESS, JOB_OBJECT_MSG_ABNORMAL_EXIT_PROCESS
			pids = append(pids, uint32(uintptr(unsafe.Pointer(ov))))
		case 4: // JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO
			return pids
		}
	}
	return pids
}

// imagesOf names each process by its image (from a process snapshot,
// which needs no handle to the process).
func imagesOf(pids []uint32) map[uint32]string {
	out := map[uint32]string{}
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return out
	}
	defer windows.CloseHandle(snap)
	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	for err = windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		if slices.Contains(pids, e.ProcessID) {
			out[e.ProcessID] = windows.UTF16ToString(e.ExeFile[:])
		}
	}
	return out
}

// setDefaultDACL sets tok's default DACL (that of the processes it
// creates): full access for user and SYSTEM, and SYNCHRONIZE,
// QUERY_LIMITED_INFORMATION and TERMINATE for the service.
func setDefaultDACL(tok windows.Token, user, service string) error {
	sd, err := windows.SecurityDescriptorFromString("D:(A;;GA;;;" + user + ")(A;;GA;;;SY)(A;;0x101001;;;" + service + ")")
	if err != nil {
		return err
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	dd := struct{ acl *windows.ACL }{acl}
	return windows.SetTokenInformation(tok, windows.TokenDefaultDacl, (*byte)(unsafe.Pointer(&dd)), uint32(unsafe.Sizeof(dd)))
}

// limitOwnDACL gives this process a DACL whose OWNER RIGHTS entry
// replaces the owner's implicit rights: its own user (the owner) gets
// SYNCHRONIZE and QUERY_LIMITED_INFORMATION only, SYSTEM all.
func limitOwnDACL() error {
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;0x1fffff;;;SY)(A;;0x101000;;;OW)")
	if err != nil {
		return err
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetSecurityInfo(windows.CurrentProcess(), windows.SE_KERNEL_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}

// tryUnnamedStation makes a window station with no name and, if that
// works, a desktop in it for the runner, and runs a quick hop there.
func tryUnnamedStation(c probe2Config, b probeUser, sa *windows.SecurityAttributes) (string, *maskResult) {
	ws, _, e := procCreateWindowStationW.Call(0, 0, uintptr(windows.MAXIMUM_ALLOWED), uintptr(unsafe.Pointer(sa)))
	if ws == 0 {
		return "CreateWindowStation(no name): " + e.Error(), nil
	}
	defer procCloseWindowStation.Call(ws)
	name := make([]uint16, 256)
	var n uint32
	if ok, _, e := procGetUserObjectInformation.Call(ws, 2, uintptr(unsafe.Pointer(&name[0])), uintptr(len(name)*2), uintptr(unsafe.Pointer(&n))); ok == 0 {
		return "made, but its name: " + e.Error(), nil
	}
	wsName := windows.UTF16ToString(name)
	old, _, _ := procGetProcessWindowStation.Call()
	if r, _, e := procSetProcessWindowStation.Call(ws); r == 0 {
		return "ok: " + wsName + "; SetProcessWindowStation: " + e.Error(), nil
	}
	dn, _ := windows.UTF16PtrFromString("run")
	desk, _, de := procCreateDesktopW.Call(uintptr(unsafe.Pointer(dn)), 0, 0, 0, uintptr(windows.MAXIMUM_ALLOWED), uintptr(unsafe.Pointer(sa)))
	procSetProcessWindowStation.Call(old)
	if desk == 0 {
		return "ok: " + wsName + "; CreateDesktop: " + de.Error(), nil
	}
	defer procCloseDesktop.Call(desk)
	h := runHop(c, b, hopOpts{key: "unnamed station", restrict: "interactive", desktop: wsName + `\run`, uiLimits: true, quick: true}, 0)
	return "ok: " + wsName, &maskResult{Set: "ok", Start: h.Start, Launcher: h.Launcher.LauncherUser32, Child: h.Launcher.Children["user32"].Record.Desktop}
}

// keepStationDACL reads the window station's access list and returns a
// function that puts it back.
func keepStationDACL(ws windows.Handle) (func(), error) {
	sd, err := windows.GetSecurityInfo(ws, windows.SE_WINDOW_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return nil, err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return nil, err
	}
	return func() {
		_ = windows.SetSecurityInfo(ws, windows.SE_WINDOW_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
	}, nil
}

// uiCalls tries, from the run's program, what the job's UI limits are
// to refuse: a desktop of its own, switching to its desktop,
// ExitWindowsEx (only with -p2-exitwindows, so only where the limits
// are set), and the window station's global atoms (one the service
// added, which it should not see; one it adds, which the service
// should not see).
func uiCalls() map[string]string {
	out := map[string]string{}
	if err := moduser32.Load(); err != nil {
		out["user32"] = err.Error()
		return out
	}
	dn, _ := windows.UTF16PtrFromString("p2-own-" + randHex(4))
	if d, _, e := procCreateDesktopW.Call(uintptr(unsafe.Pointer(dn)), 0, 0, 0, uintptr(windows.MAXIMUM_ALLOWED), 0); d == 0 {
		out["CreateDesktop"] = e.Error()
	} else {
		out["CreateDesktop"] = "ok"
		procCloseDesktop.Call(d)
	}
	// Its own desktop, by name, with DESKTOP_SWITCHDESKTOP.
	cur, _, _ := procGetThreadDesktop.Call(uintptr(windows.GetCurrentThreadId()))
	name := make([]uint16, 256)
	var n uint32
	procGetUserObjectInformation.Call(cur, 2, uintptr(unsafe.Pointer(&name[0])), uintptr(len(name)*2), uintptr(unsafe.Pointer(&n)))
	if d, _, e := procOpenDesktopW.Call(uintptr(unsafe.Pointer(&name[0])), 0, 0, 0x100 /* DESKTOP_SWITCHDESKTOP */); d == 0 {
		out["SwitchDesktop"] = "OpenDesktop: " + e.Error()
	} else {
		if r, _, e := procSwitchDesktop.Call(d); r == 0 {
			out["SwitchDesktop"] = e.Error()
		} else {
			out["SwitchDesktop"] = "ok"
		}
		procCloseDesktop.Call(d)
	}
	if *p2ExitWin {
		// EWX_LOGOFF: the job's limit is to refuse it before anything else.
		if r, _, e := procExitWindowsEx.Call(0, 0); r == 0 {
			out["ExitWindowsEx"] = e.Error()
		} else {
			out["ExitWindowsEx"] = "ok"
		}
	}
	if *p2AtomA != "" {
		a, _ := windows.UTF16PtrFromString(*p2AtomA)
		if r, _, e := procGlobalFindAtomW.Call(uintptr(unsafe.Pointer(a))); r == 0 {
			out["GlobalFindAtom(the service's)"] = e.Error()
		} else {
			out["GlobalFindAtom(the service's)"] = "found"
		}
	}
	if *p2AtomB != "" {
		b, _ := windows.UTF16PtrFromString(*p2AtomB)
		if r, _, e := procGlobalAddAtomW.Call(uintptr(unsafe.Pointer(b))); r == 0 {
			out["GlobalAddAtom"] = e.Error()
		} else {
			out["GlobalAddAtom"] = "ok"
		}
	}
	return out
}

// setThreadDACL gives the program's thread a DACL: full access for its
// user and SYSTEM, and for the service SYNCHRONIZE,
// THREAD_QUERY_LIMITED_INFORMATION and THREAD_SUSPEND_RESUME.
func setThreadDACL(th windows.Handle, user, service string) error {
	sd, err := windows.SecurityDescriptorFromString("D:(A;;GA;;;" + user + ")(A;;GA;;;SY)(A;;0x100802;;;" + service + ")")
	if err != nil {
		return err
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetSecurityInfo(th, windows.SE_KERNEL_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}

// uiArgs passes the launcher's UI-limit flags on to the uilimits child.
func uiArgs() string {
	s := fmt.Sprintf(` -p2-atom-a=%s -p2-atom-b=%s`, *p2AtomA, *p2AtomB)
	if *p2UI {
		s += " -p2-exitwindows"
	}
	return s
}

// handoffResult is the service's side of the handoff.
type handoffResult struct {
	LauncherGone string        `json:"launcher_gone_before_resume"` // "true", or what was seen
	Open         string        `json:"open_process"`                // QUERY_LIMITED|SYNCHRONIZE|TERMINATE
	OpenThread   string        `json:"open_thread"`                 // SUSPEND_RESUME|SYNCHRONIZE
	Image        string        `json:"image"`                       // as the service read it
	InJob        string        `json:"in_job"`
	Resume       string        `json:"resume"` // "ok (was suspended N)" or the error
	Exit         string        `json:"exit"`
	Program      programRecord `json:"program"`
}

// handoff is the service's part: once the launcher has exited, open the
// suspended program and its thread, check its image and job, resume it
// and wait for it to end.
func handoff(l launcherRecord, pi *windows.ProcessInformation, job windows.Handle, exe string) *handoffResult {
	r := &handoffResult{}
	if l.HandoffPID == 0 {
		r.Open = "no program handed over"
		return r
	}
	if ev, _ := windows.WaitForSingleObject(pi.Process, 30000); ev == windows.WAIT_OBJECT_0 {
		r.LauncherGone = "true"
	} else {
		r.LauncherGone = fmt.Sprintf("still running (wait %d)", ev)
	}
	// No handle of the service's may keep the launcher's process object,
	// and so its token, alive once the program runs.
	windows.CloseHandle(pi.Process)
	windows.CloseHandle(pi.Thread)
	pi.Process, pi.Thread = 0, 0
	p, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE|windows.PROCESS_TERMINATE, false, l.HandoffPID)
	if err != nil {
		r.Open = err.Error()
		return r
	}
	defer windows.CloseHandle(p)
	r.Open = "ok"
	th, err := windows.OpenThread(windows.THREAD_SUSPEND_RESUME|windows.SYNCHRONIZE|windows.THREAD_QUERY_LIMITED_INFORMATION, false, l.HandoffTID)
	if err != nil {
		r.OpenThread = err.Error()
		return r
	}
	defer windows.CloseHandle(th)
	r.OpenThread = "ok"
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(p, 0, &buf[0], &n); err != nil {
		r.Image = err.Error()
		return r
	}
	r.Image = windows.UTF16ToString(buf[:n])
	if !strings.EqualFold(r.Image, exe) {
		// Not the program: end it unresumed.
		_ = windows.TerminateProcess(p, 1)
		return r
	}
	var in int32
	if ok, _, e := procIsProcessInJob.Call(uintptr(p), uintptr(job), uintptr(unsafe.Pointer(&in))); ok == 0 {
		r.InJob = e.Error()
	} else {
		r.InJob = strconv.FormatBool(in != 0)
	}
	// The thread is the program's, not another process's under a reused id.
	if owner, _, e := procGetProcessIdOfThread.Call(uintptr(th)); uint32(owner) != l.HandoffPID {
		r.Resume = fmt.Sprintf("the thread is process %d's (%v), not the program's; not resumed", owner, e)
		_ = windows.TerminateProcess(p, 1)
		return r
	}
	prev, err := windows.ResumeThread(th)
	if err != nil {
		r.Resume = err.Error()
		return r
	}
	r.Resume = fmt.Sprintf("ok (was suspended %d)", prev)
	if ev, _ := windows.WaitForSingleObject(p, 60000); ev != windows.WAIT_OBJECT_0 {
		r.Exit = "did not end within 1m"
		_ = windows.TerminateProcess(p, 1)
	} else {
		var code uint32
		_ = windows.GetExitCodeProcess(p, &code)
		r.Exit = fmt.Sprintf("exit %#x", code)
	}
	if b, err := os.ReadFile(l.HandoffRecord); err == nil {
		_ = json.Unmarshal(b, &r.Program)
	}
	return r
}

// lockOwnToken gives this process's token a DACL whose OWNER RIGHTS
// entry replaces the owner's implicit rights: SYSTEM all, the owner
// TOKEN_QUERY only.
func lockOwnToken() error {
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.WRITE_DAC|windows.READ_CONTROL, &tok); err != nil {
		return fmt.Errorf("OpenProcessToken: %w", err)
	}
	defer tok.Close()
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;GA;;;SY)(A;;0x8;;;OW)")
	if err != nil {
		return err
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetSecurityInfo(windows.Handle(tok), windows.SE_KERNEL_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}

// ownTokenSDDL is this process's token's owner and DACL, in SDDL.
func ownTokenSDDL() string {
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.READ_CONTROL, &tok); err != nil {
		return "OpenProcessToken: " + err.Error()
	}
	defer tok.Close()
	sd, err := windows.GetSecurityInfo(windows.Handle(tok), windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err.Error()
	}
	return sd.String()
}

// targetIdentity says whether the process id (and thread id) the
// program was given are still the launcher's, or now another
// process's: an exited process's ids may be reused.
func targetIdentity(pid, tid uint32, created uint64) string {
	p, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err == nil {
		var c, e, k, u windows.Filetime
		err = windows.GetProcessTimes(p, &c, &e, &k, &u)
		windows.CloseHandle(p)
		if err == nil && created != 0 && uint64(c.HighDateTime)<<32|uint64(c.LowDateTime) != created {
			return "reused: process " + strconv.Itoa(int(pid)) + " is another process"
		}
	}
	if tid != 0 {
		if th, terr := windows.OpenThread(windows.THREAD_QUERY_LIMITED_INFORMATION, false, tid); terr == nil {
			owner, _, _ := procGetProcessIdOfThread.Call(uintptr(th))
			windows.CloseHandle(th)
			if uint32(owner) != pid {
				return fmt.Sprintf("reused: thread %d is process %d's", tid, owner)
			}
		}
	}
	if err != nil {
		return "gone: " + err.Error()
	}
	return "launcher"
}

// reachable is what the run's program can do to another process in its
// job.
type reachable struct {
	Image       string `json:"image"`
	VMWrite     string `json:"vm_write"`        // OpenProcess(PROCESS_VM_WRITE)
	Token       string `json:"token_duplicate"` // OpenProcessToken(TOKEN_DUPLICATE|TOKEN_QUERY)
	TokenUser   string `json:"token_user,omitempty"`
	Interactive string `json:"interactive,omitempty"` // in that token
}

func reach(pid uint32, image string) reachable {
	r := reachable{Image: image}
	if p, err := windows.OpenProcess(windows.PROCESS_VM_WRITE, false, pid); err != nil {
		r.VMWrite = err.Error()
	} else {
		r.VMWrite = "ok"
		windows.CloseHandle(p)
	}
	p, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		r.Token = "the process: " + err.Error()
		return r
	}
	defer windows.CloseHandle(p)
	var tok windows.Token
	if err := windows.OpenProcessToken(p, windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY, &tok); err != nil {
		r.Token = err.Error()
		return r
	}
	defer tok.Close()
	r.Token = "ok"
	facts := readTokenFacts(tok)
	r.TokenUser, r.Interactive = facts.User, facts.Interactive
	return r
}

// childDetached makes startSuspended start its programs with no console
// (the launcher's -p2-detached); childPipes keeps their pipes' read ends.
var (
	childDetached bool
	childPipes    []windows.Handle
)
