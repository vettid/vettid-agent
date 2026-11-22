//go:build windows

package service

// A3.10b, the probe's third step: the launcher's console host, the run's
// output through seclogon, the launcher's report channel, the order of
// the token lock, and whether the connector's service may read the
// runners' denied logon rights. These are hops of TestRunnerHopProbe's
// "hop" service (runHops), and one reading at its start.

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	p2Extra       = flag.String("p2-extra", "", "probe2 openlauncher: more processes to try, as pid:created,…")
	p2FreeConsole = flag.Bool("p2-freeconsole", false, "probe2 launcher, handoff: FreeConsole before starting the program")
	p2LockConhost = flag.Bool("p2-lockconhost", false, "probe2 launcher, handoff: lock its conhost's process and token before starting the program")
	p2PassStd     = flag.Bool("p2-passstd", false, "probe2 launcher, handoff: give the program its own standard output and error (the service's pipe)")
	p2Report      = flag.String("p2-report", "", "probe2 launcher: a named pipe to report to")
	p2RestrictAft = flag.Bool("p2-restrict-after-lock", false, "probe2 launcher, handoff: lock the token first, then make the restricted token from a handle opened before")
	p2Say         = flag.Bool("p2-say", false, "probe2 program: write a line to its standard output")
	p2PipeName    = flag.String("p2-pipe", "", "probe2 pipeclient: the named pipe to open")
)

// conhostFacts is what the launcher finds of its own conhost.
type conhostFacts struct {
	PID         uint32 `json:"pid,omitempty"`
	Created     uint64 `json:"created,omitempty"`
	Token       string `json:"token"`                 // opening its token: "ok" or the error
	Interactive string `json:"interactive,omitempty"` // INTERACTIVE in that token
	FreeConsole string `json:"free_console,omitempty"`
	Running     string `json:"running_after_free,omitempty"` // after FreeConsole: is it still running
	LockProcess string `json:"lock_process,omitempty"`
	LockToken   string `json:"lock_token,omitempty"`
}

// stdFacts is what the launcher finds of the standard handles it was
// given.
type stdFacts struct {
	Output      string `json:"output"`            // "none", or the handle's type
	Inheritable string `json:"inheritable"`       // its HANDLE_FLAG_INHERIT
	Made        string `json:"made_inheritable"`  // when it was not: setting it
	Write       string `json:"launcher_write"`    // the launcher writing its line
	PassedOn    string `json:"passed_to_program"` // the program started with it
}

// restrictOrder is the token lock's order (step 4).
type restrictOrder struct {
	OpenAfterLock     string     `json:"open_after_lock"`     // OpenProcessToken after the lock
	RestrictAfterLock string     `json:"restrict_after_lock"` // CreateRestrictedToken from the earlier handle
	RestrictedFacts   tokenFacts `json:"restricted_facts"`
}

// launcher3 is the launcher's part of step 3.
type launcher3 struct {
	Conhost *conhostFacts  `json:"conhost,omitempty"`
	Std     *stdFacts      `json:"std,omitempty"`
	Report  string         `json:"report,omitempty"` // connecting and writing to the report pipe
	Cwd     string         `json:"cwd,omitempty"`
	CwdRead string         `json:"cwd_read,omitempty"` // listing it
	Order   *restrictOrder `json:"order,omitempty"`
}

// report is what the launcher writes to the report pipe.
type report struct {
	Cwd     string `json:"cwd"`
	CwdRead string `json:"cwd_read"`
	Lock    string `json:"lock"`
	PID     uint32 `json:"pid"`
	TID     uint32 `json:"tid"`
}

// findConhost returns the conhost started for this process (its child
// conhost.exe), with what may be read of it.
func findConhost() *conhostFacts {
	f := &conhostFacts{}
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		f.Token = "snapshot: " + err.Error()
		return f
	}
	defer windows.CloseHandle(snap)
	self := windows.GetCurrentProcessId()
	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	for err = windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		if e.ParentProcessID == self && strings.EqualFold(windows.UTF16ToString(e.ExeFile[:]), "conhost.exe") {
			f.PID = e.ProcessID
			break
		}
	}
	if f.PID == 0 {
		f.Token = "no conhost"
		return f
	}
	p, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, f.PID)
	if err != nil {
		f.Token = "the process: " + err.Error()
		return f
	}
	defer windows.CloseHandle(p)
	var c, x, k, u windows.Filetime
	if windows.GetProcessTimes(p, &c, &x, &k, &u) == nil {
		f.Created = uint64(c.HighDateTime)<<32 | uint64(c.LowDateTime)
	}
	var tok windows.Token
	if err := windows.OpenProcessToken(p, windows.TOKEN_QUERY, &tok); err != nil {
		f.Token = err.Error()
		return f
	}
	f.Token = "ok"
	f.Interactive = readTokenFacts(tok).Interactive
	tok.Close()
	return f
}

// lockConhost gives the conhost's process and token the launcher's own
// locks: SYSTEM all, and OWNER RIGHTS with SYNCHRONIZE and
// QUERY_LIMITED_INFORMATION (the process) or TOKEN_QUERY (the token).
func lockConhost(f *conhostFacts) {
	p, err := windows.OpenProcess(windows.WRITE_DAC|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, f.PID)
	if err != nil {
		f.LockProcess, f.LockToken = "open: "+err.Error(), "the process: "+err.Error()
		return
	}
	defer windows.CloseHandle(p)
	var tok windows.Token
	if err := windows.OpenProcessToken(p, windows.WRITE_DAC, &tok); err != nil {
		f.LockToken = "open: " + err.Error()
	} else {
		f.LockToken = errString(setDACL(windows.Handle(tok), "D:P(A;;GA;;;SY)(A;;0x8;;;OW)"))
		tok.Close()
	}
	f.LockProcess = errString(setDACL(p, "D:P(A;;0x1fffff;;;SY)(A;;0x101000;;;OW)"))
}

func setDACL(h windows.Handle, sddl string) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetSecurityInfo(h, windows.SE_KERNEL_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}

// stillRunning says whether the process is still running.
func stillRunning(pid uint32) string {
	p, err := windows.OpenProcess(windows.SYNCHRONIZE, false, pid)
	if err != nil {
		return "open: " + err.Error()
	}
	defer windows.CloseHandle(p)
	ev, _ := windows.WaitForSingleObject(p, 2000)
	return strconv.FormatBool(ev == uint32(windows.WAIT_TIMEOUT))
}

// launcherStd checks the standard output the launcher was given, writes
// its line to it, and returns it (made inheritable) for the program, or 0.
func launcherStd(f *stdFacts) windows.Handle {
	h, err := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE)
	if err != nil || h == 0 || h == windows.InvalidHandle {
		f.Output = "none"
		return 0
	}
	t, _ := windows.GetFileType(h)
	f.Output = map[uint32]string{windows.FILE_TYPE_PIPE: "pipe", windows.FILE_TYPE_DISK: "file", windows.FILE_TYPE_CHAR: "char"}[t]
	if f.Output == "" {
		f.Output = fmt.Sprintf("type %d", t)
	}
	var flags uint32
	if r, _, e := procGetHandleInformation.Call(uintptr(h), uintptr(unsafe.Pointer(&flags))); r == 0 {
		f.Inheritable = "GetHandleInformation: " + e.Error()
	} else {
		f.Inheritable = strconv.FormatBool(flags&windows.HANDLE_FLAG_INHERIT != 0)
	}
	if f.Inheritable == "false" {
		f.Made = errString(windows.SetHandleInformation(h, windows.HANDLE_FLAG_INHERIT, windows.HANDLE_FLAG_INHERIT))
	}
	var n uint32
	f.Write = errString(windows.WriteFile(h, []byte("launcher-says-hello\n"), &n, nil))
	return h
}

// sendReport connects to the report pipe and writes the report.
func sendReport(name string, r report) string {
	n, _ := windows.UTF16PtrFromString(name)
	h, err := windows.CreateFile(n, windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return "connect: " + err.Error()
	}
	defer windows.CloseHandle(h)
	b, _ := json.Marshal(r)
	var w uint32
	if err := windows.WriteFile(h, b, &w, nil); err != nil {
		return "write: " + err.Error()
	}
	return "ok"
}

// runPipeClient is a process of another user trying the report pipe.
func runPipeClient() int {
	n, _ := windows.UTF16PtrFromString(*p2PipeName)
	res := map[string]string{}
	for _, a := range []struct {
		name string
		mask uint32
	}{{"write", windows.GENERIC_WRITE}, {"read", windows.GENERIC_READ}} {
		h, err := windows.CreateFile(n, a.mask, 0, nil, windows.OPEN_EXISTING, 0, 0)
		if err != nil {
			res[a.name] = err.Error()
			continue
		}
		res[a.name] = "ok"
		windows.CloseHandle(h)
	}
	if writeJSON(*p2Out, res) != nil {
		return 5
	}
	return 0
}

// extraTargets parses -p2-extra.
func extraTargets() map[uint32]uint64 {
	out := map[uint32]uint64{}
	for _, s := range strings.Split(*p2Extra, ",") {
		pid, created, ok := strings.Cut(s, ":")
		if !ok {
			continue
		}
		p, err1 := strconv.ParseUint(pid, 10, 32)
		c, err2 := strconv.ParseUint(created, 10, 64)
		if err1 == nil && err2 == nil {
			out[uint32(p)] = c
		}
	}
	return out
}

// extraReach is what the program reaches of another process, by its id,
// after its launcher has gone: whether the id still names that process,
// and the opens.
type extraReach struct {
	Identity string    `json:"identity"`
	Reach    reachable `json:"reach"`
}

// reportPipe is the service's side of the report channel: a per-run
// named pipe that only the service and the runner may open.
type reportPipe struct {
	Name  string `json:"name"`
	Make  string `json:"make"`
	h     windows.Handle
	Read  string            `json:"read"`
	Got   *report           `json:"got,omitempty"`
	Other map[string]string `json:"other_users,omitempty"` // user: their pipeclient's record
}

func makeReportPipe(serviceSID, runnerSID string) *reportPipe {
	r := &reportPipe{Name: `\\.\pipe\vettid-run-` + randHex(6)}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;GA;;;" + serviceSID + ")(A;;0x12019f;;;" + runnerSID + ")")
	if err != nil {
		r.Make = err.Error()
		return r
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	n, _ := windows.UTF16PtrFromString(r.Name)
	h, err := windows.CreateNamedPipe(n, windows.PIPE_ACCESS_INBOUND|windows.FILE_FLAG_FIRST_PIPE_INSTANCE,
		windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT|windows.PIPE_REJECT_REMOTE_CLIENTS, 1, 0, 4096, 0, sa)
	if err != nil {
		r.Make = err.Error()
		return r
	}
	r.h, r.Make = h, "ok"
	return r
}

// collect reads the launcher's report, once it says it connected.
func (r *reportPipe) collect(connected bool) {
	if r.h == 0 {
		return
	}
	defer windows.CloseHandle(r.h)
	if !connected {
		r.Read = "the launcher did not connect"
		return
	}
	if err := windows.ConnectNamedPipe(r.h, nil); err != nil && !errors.Is(err, windows.ERROR_PIPE_CONNECTED) && !errors.Is(err, windows.ERROR_NO_DATA) {
		r.Read = "ConnectNamedPipe: " + err.Error()
		return
	}
	var buf []byte
	b := make([]byte, 4096)
	for {
		var n uint32
		err := windows.ReadFile(r.h, b, &n, nil)
		buf = append(buf, b[:n]...)
		if err != nil || n == 0 {
			break
		}
	}
	var got report
	if err := json.Unmarshal(buf, &got); err != nil {
		r.Read = fmt.Sprintf("%d bytes, not a report: %v", len(buf), err)
		return
	}
	r.Read, r.Got = "ok", &got
}

// outputPipe is the service's pipe for the run's output: its write end
// is given to seclogon as the launcher's standard output and error.
type outputPipe struct {
	Inheritable bool   `json:"inheritable"`
	Make        string `json:"make"`
	r, w        windows.Handle
	Got         string `json:"got"` // what came through, after the run
	done        chan struct{}
}

func makeOutputPipe(inheritable bool) *outputPipe {
	o := &outputPipe{Inheritable: inheritable, done: make(chan struct{})}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{}))}
	if inheritable {
		sa.InheritHandle = 1
	}
	if err := windows.CreatePipe(&o.r, &o.w, sa, 0); err != nil {
		o.Make = err.Error()
		close(o.done)
		return o
	}
	_ = windows.SetHandleInformation(o.r, windows.HANDLE_FLAG_INHERIT, 0)
	o.Make = "ok"
	go func() {
		defer close(o.done)
		var buf []byte
		b := make([]byte, 4096)
		for len(buf) < 8192 {
			var n uint32
			err := windows.ReadFile(o.r, b, &n, nil)
			buf = append(buf, b[:n]...)
			if err != nil {
				break
			}
		}
		o.Got = string(buf)
	}()
	return o
}

// closeWrite drops the service's own copy of the write end, once the
// launcher has it, so the read ends when the run's processes are done.
func (o *outputPipe) closeWrite() {
	if o.w != 0 {
		windows.CloseHandle(o.w)
		o.w = 0
	}
}

// wait waits for the output to end, up to d.
func (o *outputPipe) wait(d time.Duration) {
	select {
	case <-o.done:
	case <-time.After(d):
		o.Got += " [did not end within " + d.String() + "]"
	}
	if o.r != 0 {
		windows.CloseHandle(o.r)
		o.r = 0
	}
}

// accountRights is LsaEnumerateAccountRights for sid, as this process
// may read it (POLICY_LOOKUP_NAMES).
func accountRights(sid string) (string, []string) {
	s, err := windows.StringToSid(sid)
	if err != nil {
		return err.Error(), nil
	}
	var attrs [12]uintptr
	var policy uintptr
	if st, _, _ := procLsaOpenPolicy.Call(0, uintptr(unsafe.Pointer(&attrs[0])), 0x00000800 /* POLICY_LOOKUP_NAMES */, uintptr(unsafe.Pointer(&policy))); st != 0 {
		return fmt.Sprintf("LsaOpenPolicy: NTSTATUS %#x", st), nil
	}
	defer procLsaClose.Call(policy)
	var rights *lsaUnicode
	var n uint32
	if st, _, _ := procLsaEnumerateAccountRights.Call(policy, uintptr(unsafe.Pointer(s)), uintptr(unsafe.Pointer(&rights)), uintptr(unsafe.Pointer(&n))); st != 0 {
		return fmt.Sprintf("LsaEnumerateAccountRights: NTSTATUS %#x", st), nil
	}
	defer procLsaFreeMemory.Call(uintptr(unsafe.Pointer(rights)))
	var out []string
	for _, r := range unsafe.Slice(rights, n) {
		out = append(out, windows.UTF16ToString(unsafe.Slice(r.Buffer, r.Length/2)))
	}
	return "ok", out
}

var (
	procLsaEnumerateAccountRights = modadvapi32.NewProc("LsaEnumerateAccountRights")
	procLsaFreeMemory             = modadvapi32.NewProc("LsaFreeMemory")
	procFreeConsole               = windows.NewLazySystemDLL("kernel32.dll").NewProc("FreeConsole")
)

// guiCopy writes a copy of exe whose PE header names the Windows GUI
// subsystem (2) instead of the console one (3): the same code, started
// with no console.
func guiCopy(exe, to string) error {
	b, err := os.ReadFile(exe)
	if err != nil {
		return err
	}
	if len(b) < 0x40 || string(b[:2]) != "MZ" {
		return errors.New("not a PE file")
	}
	pe := binary.LittleEndian.Uint32(b[0x3c:])
	// The optional header follows the 4-byte signature and the 20-byte
	// file header; Subsystem is at offset 68 in it (PE32 and PE32+).
	off := int(pe) + 4 + 20 + 68
	if off+2 > len(b) || string(b[pe:pe+4]) != "PE\x00\x00" {
		return errors.New("no PE header")
	}
	if sub := binary.LittleEndian.Uint16(b[off:]); sub != 3 {
		return fmt.Errorf("subsystem %d, not the console's", sub)
	}
	binary.LittleEndian.PutUint16(b[off:], 2)
	return os.WriteFile(to, b, 0o755)
}

// childStdOut, when set, is the standard output and error startSuspended
// gives its programs (the launcher's own, -p2-passstd).
var childStdOut windows.Handle

// tryPipeAs starts, as user u (by seclogon, on its own desktop), a
// process that tries to open the report pipe, and returns its record.
func tryPipeAs(exe string, u probeUser, pipe string) string {
	out := filepath.Join(u.OutDir, "pipeclient-"+randHex(4)+".json")
	n, _ := windows.UTF16PtrFromString(u.Name)
	dot, _ := windows.UTF16PtrFromString(".")
	pw, _ := windows.UTF16PtrFromString(u.Password)
	cl, _ := windows.UTF16FromString(fmt.Sprintf(`"%s" -test.run=^TestProbe2ChildHelper$ -p2-mode=pipeclient -p2-out="%s" -p2-pipe=%s`, exe, out, pipe))
	dir, _ := windows.UTF16PtrFromString(filepath.Dir(exe))
	si := &windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfo{}))}
	var pi windows.ProcessInformation
	if r, _, e := procCreateProcessWithLogonW.Call(uintptr(unsafe.Pointer(n)), uintptr(unsafe.Pointer(dot)), uintptr(unsafe.Pointer(pw)),
		0, 0, uintptr(unsafe.Pointer(&cl[0])), uintptr(windows.CREATE_NO_WINDOW), 0,
		uintptr(unsafe.Pointer(dir)), uintptr(unsafe.Pointer(si)), uintptr(unsafe.Pointer(&pi))); r == 0 {
		return "start: " + e.Error()
	}
	defer windows.CloseHandle(pi.Process)
	defer windows.CloseHandle(pi.Thread)
	if ev, _ := windows.WaitForSingleObject(pi.Process, 60000); ev != windows.WAIT_OBJECT_0 {
		_ = windows.TerminateProcess(pi.Process, 1)
		return "did not end within 1m"
	}
	b, err := os.ReadFile(out)
	if err != nil {
		return "no record: " + err.Error()
	}
	return string(b)
}

// serviceSIDString is this process's user: the service's own SID when it
// runs as the service.
func serviceSIDString() string {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return ""
	}
	return u.User.Sid.String()
}

// probe3Hops are step 3's hops.
var probe3Hops = []string{"s3-conhost", "s3-freeconsole", "s3-lockconhost", "s3-gui", "s3-pipes-inheritable", "s3-pipes-not-inheritable", "s3-restrict-after-lock"}

// probe3Expect checks step 3. This first round records each value
// (logged, then pinned); the handoff itself is asserted as in step 2.
func probe3Expect(t *testing.T, r probe2Result, u probeUser, exe string) {
	t.Helper()
	t.Logf("step 3: the service reading the runner's account rights: %s %v", r.RunnerRights, r.RunnerRightsList)
	for _, key := range probe3Hops {
		h, ok := r.Hops[key]
		if !ok {
			t.Errorf("hop %s: missing from the record", key)
			continue
		}
		where := "hop " + key
		show := func(label string, v any) {
			b, _ := json.Marshal(v)
			t.Logf("%s: %s: %s", where, label, b)
		}
		show("start", map[string]string{"start": h.Start, "job": h.Job, "kill": h.Kill})
		show("launcher step 3", h.Launcher.Step3)
		show("launcher", map[string]string{"restricted": h.Launcher.Restricted, "token_lock": h.Launcher.TokenLock, "process_lock": h.Launcher.ProcessLock, "default_dacl": h.Launcher.DefaultDACL, "thread_dacl": h.Launcher.ThreadDACL})
		if h.Handoff != nil {
			show("handoff", map[string]string{"launcher_gone": h.Handoff.LauncherGone, "open": h.Handoff.Open, "image": h.Handoff.Image, "in_job": h.Handoff.InJob, "resume": h.Handoff.Resume, "exit": h.Handoff.Exit})
			show("program's token", h.Handoff.Program.Token)
			show("program: launcher", map[string]any{"identity": h.Handoff.Program.TargetIdentity, "opens": h.Handoff.Program.OpenLauncher})
			show("program: by id", h.Handoff.Program.Extra)
			show("program: its job", h.Handoff.Program.JobProcs)
		} else {
			t.Errorf("%s: no handoff record", where)
		}
		show("report pipe", h.Report)
		show("output pipe", h.Output)
	}
}
