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
	"os"
	"os/exec"
	"path/filepath"
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
)

// The children's flags.
var (
	p2Mode     = flag.String("p2-mode", "", "probe2 child: launcher, program, user32, dcom, wait")
	p2Out      = flag.String("p2-out", "", "probe2 child: where to write its record")
	p2Exe      = flag.String("p2-exe", "", "probe2 launcher: the program to start")
	p2Restrict = flag.String("p2-restrict", "", "probe2 launcher: interactive, interactive+local")
	p2Sentinel = flag.Uint64("p2-sentinel", 0, "probe2 child: a handle value to check for")
	p2CLSID    = flag.String("p2-clsid", "", "probe2 dcom: the class to activate")
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
	Token            tokenFacts `json:"token"`
	SentinelInherits bool       `json:"launcher_sentinel_inherited"`
	Desktop          string     `json:"desktop,omitempty"`
	Beep             string     `json:"beep,omitempty"`
	DCOM             string     `json:"dcom,omitempty"`
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
	Token            tokenFacts            `json:"token"`
	ServiceSentinel  bool                  `json:"service_sentinel_inherited"`
	Restricted       string                `json:"restricted_token"`
	RestrictedFacts  tokenFacts            `json:"restricted_facts"`
	Children         map[string]childStart `json:"children"` // program, user32, dcom, dcom-unrestricted
	WaitingPID       uint32                `json:"waiting_pid"`
	WaitingStartedOK bool                  `json:"waiting_started"`
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
		r.DCOM = activate(*p2CLSID)
	}
	if writeJSON(*p2Out, r) != nil {
		return 5
	}
	return 0
}

// activate tries CoCreateInstance of clsid as a local server and returns
// the HRESULT.
func activate(clsid string) string {
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
	rec := launcherRecord{Children: map[string]childStart{}}
	self := windows.GetCurrentProcessToken()
	rec.Token = readTokenFacts(self)
	rec.ServiceSentinel = handleHeld(*p2Sentinel)
	var own windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY|windows.TOKEN_ASSIGN_PRIMARY, &own); err != nil {
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
		{"dcom-unrestricted", "dcom", own, " -p2-clsid=" + *p2CLSID},
	} {
		out := filepath.Join(dir, "child-"+c.name+"-"+randHex(4)+".json")
		args := fmt.Sprintf(`-test.run=^TestProbe2ChildHelper$ -p2-mode=%s -p2-out="%s" -p2-sentinel=%d%s`, c.mode, out, uint64(sentinel), c.extra)
		cs := startChild(c.tok, *p2Exe, args, filepath.Join(dir, "child-"+c.name+"-"+randHex(4)+".log"), 60*time.Second)
		if b, err := os.ReadFile(out); err == nil {
			_ = json.Unmarshal(b, &cs.Record)
		}
		rec.Children[c.name] = cs
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
	cl, _ := windows.UTF16PtrFromString(`"` + exe + `" ` + args)
	err = windows.CreateProcessAsUser(tok, nil, cl, nil, nil, true,
		windows.CREATE_SUSPENDED|windows.CREATE_NO_WINDOW|windows.EXTENDED_STARTUPINFO_PRESENT, nil, nil, &si.StartupInfo, &pi)
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
	Out    string               `json:"out"`
	Exe    string               `json:"exe"`
	CLSID  string               `json:"clsid"`
	Mode   string               `json:"mode"`  // "hop", "shapes"
	Users  map[string]probeUser `json:"users"` // hop: "b"; shapes: the shapes
	Shapes []string             `json:"shapes,omitempty"`
}

// hopResult is one launcher run.
type hopResult struct {
	Start       string         `json:"start"`
	Errno       uint32         `json:"errno,omitempty"`
	Job         string         `json:"job"`
	UILimits    string         `json:"ui_limits"`
	Launcher    launcherRecord `json:"launcher"`
	JobPIDs     []uint32       `json:"job_pids"`
	ServiceOpen string         `json:"service_opens_program"`
	ServiceName string         `json:"service_reads_image_name"`
	Kill        string         `json:"job_kill"`
}

// probe2Result is what the service records.
type probe2Result struct {
	WindowStation string `json:"window_station"`
	// The fallback, when the service can make no window station: a
	// desktop in the service's own, with the runner added to it.
	ServiceWindowStation string               `json:"service_window_station,omitempty"`
	WindowStationACE     string               `json:"window_station_ace,omitempty"`
	Desktop              string               `json:"desktop"`
	DesktopName          string               `json:"desktop_name"`
	Hops                 map[string]hopResult `json:"hops"`   // "interactive", "interactive+local"
	Shapes               map[string]string    `json:"shapes"` // shape: "ok" or "errno N: text"
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
	if p.c.Mode == "shapes" {
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
		res.WindowStationACE = errString(grantWindowStation(windows.Handle(cur), b.SID))
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
	for _, restrict := range []string{"interactive", "interactive+local"} {
		res.Hops[restrict] = runHop(c, b, res.DesktopName, restrict, uint64(sentinel))
	}
	return res
}

func runHop(c probe2Config, u probeUser, desktop, restrict string, sentinel uint64) hopResult {
	var h hopResult
	out := filepath.Join(u.OutDir, "launcher-"+randHex(4)+".json")
	args := fmt.Sprintf(`-test.run=^TestProbe2ChildHelper$ -p2-mode=launcher -p2-out="%s" -p2-exe="%s" -p2-restrict=%s -p2-sentinel=%d -p2-clsid=%s`,
		out, c.Exe, restrict, sentinel, c.CLSID)
	n, _ := windows.UTF16PtrFromString(u.Name)
	dot, _ := windows.UTF16PtrFromString(".")
	pw, _ := windows.UTF16PtrFromString(u.Password)
	cl, _ := windows.UTF16FromString(`"` + c.Exe + `" ` + args)
	dir, _ := windows.UTF16PtrFromString(filepath.Dir(c.Exe))
	dsk, _ := windows.UTF16PtrFromString(desktop)
	si := &windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfo{})), Desktop: dsk}
	var pi windows.ProcessInformation
	if r, _, e := procCreateProcessWithLogonW.Call(uintptr(unsafe.Pointer(n)), uintptr(unsafe.Pointer(dot)), uintptr(unsafe.Pointer(pw)),
		0, 0, uintptr(unsafe.Pointer(&cl[0])), uintptr(windows.CREATE_NO_WINDOW|windows.CREATE_SUSPENDED), 0,
		uintptr(unsafe.Pointer(dir)), uintptr(unsafe.Pointer(si)), uintptr(unsafe.Pointer(&pi))); r == 0 {
		h.Start, h.Errno = e.Error(), errnoOf(e)
		return h
	}
	h.Start = "ok"
	job, err := killOnCloseJob()
	if err == nil {
		err = windows.AssignProcessToJobObject(job, pi.Process)
	}
	h.Job = errString(err)
	if err == nil {
		ui := windows.JOBOBJECT_BASIC_UI_RESTRICTIONS{UIRestrictionsClass: windows.JOB_OBJECT_UILIMIT_HANDLES | windows.JOB_OBJECT_UILIMIT_GLOBALATOMS |
			windows.JOB_OBJECT_UILIMIT_DESKTOP | windows.JOB_OBJECT_UILIMIT_READCLIPBOARD | windows.JOB_OBJECT_UILIMIT_WRITECLIPBOARD}
		_, uerr := windows.SetInformationJobObject(job, windows.JobObjectBasicUIRestrictions, uintptr(unsafe.Pointer(&ui)), uint32(unsafe.Sizeof(ui)))
		h.UILimits = errString(uerr)
	}
	_, _ = windows.ResumeThread(pi.Thread)
	// Wait for the launcher's record (written once the waiting program
	// runs).
	for end := time.Now().Add(4 * time.Minute); time.Now().Before(end); time.Sleep(200 * time.Millisecond) {
		if b, err := os.ReadFile(out); err == nil && json.Unmarshal(b, &h.Launcher) == nil && (h.Launcher.WaitingStartedOK || h.Launcher.Restricted != "ok") {
			break
		}
		if ev, _ := windows.WaitForSingleObject(pi.Process, 0); ev == windows.WAIT_OBJECT_0 {
			if b, err := os.ReadFile(out); err == nil {
				_ = json.Unmarshal(b, &h.Launcher)
			}
			break
		}
	}
	if job != 0 {
		h.JobPIDs = jobPIDs(job)
		if h.Launcher.WaitingPID != 0 {
			p, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, h.Launcher.WaitingPID)
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
				windows.CloseHandle(job)
				job = 0
				if ev, _ := windows.WaitForSingleObject(p, 10000); ev == windows.WAIT_OBJECT_0 {
					h.Kill = "ok"
				} else {
					h.Kill = "the program still ran 10 s after its job was closed"
				}
				windows.CloseHandle(p)
			}
		}
		if job != 0 {
			windows.CloseHandle(job)
			if h.Kill == "" {
				h.Kill = "not observed (the service could not open the program)"
			}
		}
	}
	if ev, _ := windows.WaitForSingleObject(pi.Process, 10000); ev != windows.WAIT_OBJECT_0 {
		_ = windows.TerminateProcess(pi.Process, 1)
		h.Kill += "; the launcher still ran"
	}
	windows.CloseHandle(pi.Process)
	windows.CloseHandle(pi.Thread)
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

// registerInteractiveClass registers a throwaway class whose AppID runs as
// the Interactive User and lets only INTERACTIVE (and SYSTEM and
// administrators) launch and activate it; its server is exe, which exits.
func registerInteractiveClass(t *testing.T, exe string) string {
	t.Helper()
	clsid := "{" + strings.ToUpper(fmt.Sprintf("%s-%s-%s-%s-%s", randHex(4), randHex(2), randHex(2), randHex(2), randHex(6))) + "}"
	appid := "{" + strings.ToUpper(fmt.Sprintf("%s-%s-%s-%s-%s", randHex(4), randHex(2), randHex(2), randHex(2), randHex(6))) + "}"
	sd, err := windows.SecurityDescriptorFromString("O:BAG:BAD:(A;;0xb;;;IU)(A;;0xb;;;SY)(A;;0xb;;;BA)")
	if err != nil {
		t.Fatal(err)
	}
	// SecurityDescriptorFromString gives a self-relative descriptor, the
	// form the registry values take, as it is.
	perm := unsafe.Slice((*byte)(unsafe.Pointer(sd)), sd.Length())
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, `SOFTWARE\Classes\AppID\`+appid, registry.ALL_ACCESS)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = registry.DeleteKey(registry.LOCAL_MACHINE, `SOFTWARE\Classes\AppID\`+appid) })
	for _, err := range []error{k.SetStringValue("RunAs", "Interactive User"), k.SetBinaryValue("LaunchPermission", perm), k.SetBinaryValue("AccessPermission", perm)} {
		if err != nil {
			t.Fatal(err)
		}
	}
	k.Close()
	k, _, err = registry.CreateKey(registry.LOCAL_MACHINE, `SOFTWARE\Classes\CLSID\`+clsid, registry.ALL_ACCESS)
	if err != nil {
		t.Fatal(err)
	}
	if err := k.SetStringValue("AppID", appid); err != nil {
		t.Fatal(err)
	}
	k.Close()
	ls, _, err := registry.CreateKey(registry.LOCAL_MACHINE, `SOFTWARE\Classes\CLSID\`+clsid+`\LocalServer32`, registry.ALL_ACCESS)
	if err != nil {
		t.Fatal(err)
	}
	if err := ls.SetStringValue("", `"`+exe+`" -test.run=^$`); err != nil {
		t.Fatal(err)
	}
	ls.Close()
	t.Cleanup(func() {
		_ = registry.DeleteKey(registry.LOCAL_MACHINE, `SOFTWARE\Classes\CLSID\`+clsid+`\LocalServer32`)
		_ = registry.DeleteKey(registry.LOCAL_MACHINE, `SOFTWARE\Classes\CLSID\`+clsid)
	})
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
	for _, r := range "SeChangeNotifyPrivilege\x00\x00" {
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
	for end := time.Now().Add(9 * time.Minute); ; time.Sleep(500 * time.Millisecond) {
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
		if st0.State == svc.Running {
			if err := sl.Start(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
				t.Errorf("restarting seclogon: %v", err)
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
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("removing %s: %v", dir, err)
		}
	})
	// The three services (hop, shapes, seclogon disabled) may read and
	// write here; Users may read the binary.
	hSID, sSID, dSID := channel.ServiceSID(name+"h"), channel.ServiceSID(name+"s"), channel.ServiceSID(name+"d")
	protectDir(t, dir, "D:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;0x1301bf;;;"+hSID+")(A;OICI;0x1301bf;;;"+sSID+")(A;OICI;0x1301bf;;;"+dSID+")(A;OICI;0x1200a9;;;BU)")
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
	clsid := registerInteractiveClass(t, exe)
	bDenies := []string{"SeDenyRemoteInteractiveLogonRight", "SeDenyNetworkLogonRight"}
	bGrants := []string{"SeInteractiveLogonRight"}

	t.Run("hop", func(t *testing.T) {
		users := map[string]probeUser{"b": newShapedUser(t, dir, hSID, bGrants, bDenies, false)}
		res := runProbe2Service(t, m, name+"h", mustSID(t, hSID), dir, exe,
			probe2Config{Exe: exe, CLSID: clsid, Mode: "hop", Users: users})
		probe2ExpectHop(t, res, users["b"], exe)
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
		if res.Shapes["b-no-grant"] != "ok" {
			t.Errorf("B's runner without its grant: %s", res.Shapes["b-no-grant"])
		}
		if !strings.HasPrefix(res.Shapes["b-deny-console"], "errno 1385:") {
			t.Errorf("B's runner denied the console: %s, want errno 1385", res.Shapes["b-deny-console"])
		}
	})
	t.Run("seclogon-disabled", func(t *testing.T) {
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
		if _, err := sl.Control(svc.Stop); err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
			t.Fatalf("stopping seclogon: %v", err)
		}
		for end := time.Now().Add(30 * time.Second); time.Now().Before(end); time.Sleep(200 * time.Millisecond) {
			if st, err := sl.Query(); err == nil && st.State == svc.Stopped {
				break
			}
		}
		res := runProbe2Service(t, m, name+"d", mustSID(t, dSID), dir, exe,
			probe2Config{Exe: exe, Mode: "shapes", Users: users, Shapes: []string{"b"}})
		t.Logf("seclogon disabled: %v", res.Shapes)
		if !strings.HasPrefix(res.Shapes["b"], "errno 1058:") {
			t.Errorf("with seclogon disabled: %s, want errno 1058 (the service is disabled)", res.Shapes["b"])
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

// probe2ExpectHop checks what the plan relies on; the rest is recorded.
func probe2ExpectHop(t *testing.T, r probe2Result, u probeUser, exe string) {
	t.Helper()
	// A window station of the run's own, or (measured: the cut1 account
	// may not make one) a desktop of its own in the service's window
	// station, with the runner added to that.
	if r.Desktop != "ok" || !(strings.HasPrefix(r.WindowStation, "ok") || r.WindowStationACE == "ok") {
		t.Errorf("window station %q (fallback %q, entry %q), desktop %q", r.WindowStation, r.ServiceWindowStation, r.WindowStationACE, r.Desktop)
	}

	for restrict, h := range r.Hops {
		where := "hop " + restrict
		if h.Start != "ok" || h.Job != "ok" || h.UILimits != "ok" {
			t.Errorf("%s: start %q, job %q, UI limits %q", where, h.Start, h.Job, h.UILimits)
			continue
		}
		l := h.Launcher
		if l.Token.User != u.SID || l.ServiceSentinel {
			t.Errorf("%s: launcher as %s (want %s), service handle inherited %v", where, l.Token.User, u.SID, l.ServiceSentinel)
		}
		if l.Restricted != "ok" {
			t.Errorf("%s: restricted token: %s", where, l.Restricted)
			continue
		}
		p := l.Children["program"]
		if p.Start != "ok" || p.Exit != "exit 0x0" || !strings.EqualFold(p.ImageName, exe) {
			t.Errorf("%s: program %+v", where, p)
		}
		if p.Record.Token.User != u.SID || p.Record.Token.Interactive != "deny-only" || p.Record.SentinelInherits ||
			!sameSet(p.Record.Token.Privileges, []string{"SeChangeNotifyPrivilege+"}) {
			t.Errorf("%s: program's token %+v, launcher handle inherited %v", where, p.Record.Token, p.Record.SentinelInherits)
		}
		// LOCAL can only be made deny-only if the runner's token holds it.
		if restrict == "interactive+local" && l.Token.Local != "absent" && p.Record.Token.Local != "deny-only" {
			t.Errorf("%s: LOCAL %s (the launcher's: %s)", where, p.Record.Token.Local, l.Token.Local)
		}
		if p.Record.Token.Batch != "absent" {
			t.Errorf("%s: BATCH %s", where, p.Record.Token.Batch)
		}
		u32 := l.Children["user32"]
		if u32.Exit != "exit 0x0" || u32.Record.Desktop != r.DesktopName[strings.LastIndex(r.DesktopName, `\`)+1:] {
			t.Errorf("%s: user32 child %+v", where, u32)
		}
		if !slicesContain(h.JobPIDs, l.WaitingPID) {
			t.Errorf("%s: the waiting program %d not in the job %v", where, l.WaitingPID, h.JobPIDs)
		}
		if h.ServiceOpen == "ok" && h.Kill != "ok" {
			t.Errorf("%s: job kill: %s", where, h.Kill)
		}
		d := l.Children["dcom"].Record.DCOM
		if d == "" || d == "HRESULT 0x0" {
			t.Errorf("%s: DCOM with INTERACTIVE deny-only: %q, want refused", where, d)
		}
	}
	_ = strconv.Itoa
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
		AccessPermissions: 0x37f, // WINSTA_ALL_ACCESS
		AccessMode:        windows.GRANT_ACCESS,
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
