//go:build windows

package run

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// platProgram holds the file open (AGENT-PLAN §4.9, "Run exactly what
// was hashed", Windows): with sharing that allows reading only, so while
// it is held no one can write, rename or delete the file, and its identity
// (volume serial number and file index) for the image check.
type platProgram struct {
	f  *os.File
	id fileIdentity
}

// fileIdentity is what names a file on its volume: the volume serial
// number and file index of GetFileInformationByHandle, and the 128-bit
// FILE_ID_INFO where the volume gives one (ReFS's file ids are 128 bits,
// of which the file index is only a part; chosen, not in the spec).
type fileIdentity struct {
	serial uint32
	index  uint64
	has128 bool
	vol128 uint64
	id128  [16]byte
}

// fileIDInfo is FILE_ID_INFO.
type fileIDInfo struct {
	VolumeSerialNumber uint64
	FileID             [16]byte
}

// The file systems a program may be run from (owner decision,
// 2026-11-05): those where the held handle's sharing is enforced and file
// indexes are stable.
func allowedFileSystem(name string) bool {
	return strings.EqualFold(name, "NTFS") || strings.EqualFold(name, "ReFS")
}

// Prepare opens the resolved program path once and holds it. It refuses
// anything but a regular file the operator may run (a directory, a
// reparse point, a name without a program extension, a stream name, a
// network path), a file on a volume that is not NTFS or ReFS, a file that
// another process has open for writing or deleting (the open with
// read-only sharing fails then), and a script (#!). It hashes the file
// through the held handle. binDir is not used on Windows.
func Prepare(path, _ string) (*Program, error) {
	if path == "" || !filepath.IsAbs(path) || isUNC(path) || !canExecute(path, nil) {
		return nil, notFound("%s is not a program the connector runs", path)
	}
	p16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, notFound("the program path is invalid")
	}
	// FILE_SHARE_READ alone: no writing, renaming or deleting while held.
	// FILE_FLAG_OPEN_REPARSE_POINT: a link at the path is opened as
	// itself, and refused below, not followed.
	h, err := windows.CreateFile(p16, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	// A file someone else holds for writing is refused as
	// program_not_found. (chosen; not in the spec)
	if errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
		return nil, notFound("%s is open for writing or deleting by another process, so it can't be held unchanged; the run is refused", path)
	}
	if err != nil {
		return nil, notFound("%s can't be opened: %v", path, err)
	}
	f := os.NewFile(uintptr(h), path)
	prog, err := prepareHeld(f, h, path)
	if err != nil {
		f.Close()
		return nil, err
	}
	return prog, nil
}

func prepareHeld(f *os.File, h windows.Handle, path string) (*Program, error) {
	if t, err := windows.GetFileType(h); err != nil || t != windows.FILE_TYPE_DISK {
		return nil, notFound("%s is not a file on a disk", path)
	}
	id, attrs, err := identityOf(h)
	if err != nil {
		return nil, notFound("%s can't be checked: %v", path, err)
	}
	if attrs&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
		return nil, notFound("%s is a directory", path)
	}
	if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return nil, notFound("%s is a link or other reparse point", path)
	}
	fs, err := volumeFileSystem(h)
	if err != nil {
		return nil, notFound("%s: its volume can't be checked: %v", path, err)
	}
	if !allowedFileSystem(fs) {
		return nil, notFound("%s is on a %s volume; programs are run only from NTFS or ReFS volumes", path, fs)
	}
	sum, err := hashingCopy(nil, f, path, 0)
	if err != nil {
		return nil, err
	}
	return &Program{Path: path, SHA256: sum, plat: platProgram{f: f, id: id}}, nil
}

// volumeFileSystem is the file system name of the held file's volume
// (GetVolumeInformationByHandleW).
func volumeFileSystem(h windows.Handle) (string, error) {
	var name [windows.MAX_PATH + 1]uint16
	if err := windows.GetVolumeInformationByHandle(h, nil, 0, nil, nil, nil, &name[0], uint32(len(name))); err != nil {
		return "", err
	}
	return windows.UTF16ToString(name[:]), nil
}

// identityOf returns a file's identity and attributes.
func identityOf(h windows.Handle) (fileIdentity, uint32, error) {
	var bi windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &bi); err != nil {
		return fileIdentity{}, 0, err
	}
	id := fileIdentity{
		serial: bi.VolumeSerialNumber,
		index:  uint64(bi.FileIndexHigh)<<32 | uint64(bi.FileIndexLow),
	}
	var fi fileIDInfo
	if windows.GetFileInformationByHandleEx(h, windows.FileIdInfo, (*byte)(unsafe.Pointer(&fi)), uint32(unsafe.Sizeof(fi))) == nil {
		id.has128, id.vol128, id.id128 = true, fi.VolumeSerialNumber, fi.FileID
	}
	return id, bi.FileAttributes, nil
}

// Close releases the held file. Call it after Start, or when the run is
// refused.
func (p *Program) Close() error {
	if p.plat.f == nil {
		return nil
	}
	err := p.plat.f.Close()
	p.plat.f = nil
	return err
}

// The child's variable that keeps programs it starts from being looked
// up in its current directory (AGENT-PLAN §4.9).
const noCwdExeName = "NoDefaultCurrentDirectoryInExePath"

// Start starts the held program (AGENT-PLAN §4.9, Windows): it resolves
// argv[0] again (program_not_found if the path changed), creates the
// process suspended from the resolved path as lpApplicationName, checks
// that the started image is the held file, and only then resumes it; on a
// mismatch it ends the process and refuses the run (program_not_found;
// chosen, not in the spec, as for a changed path). The held file stays
// held until Close.
//
// The process limits (a job object that ends its processes, the timeout)
// and the output handling come with the process limits: a job is to be
// assigned between the image check and the resume, which the suspended
// start allows.
func (p *Program) Start(s StartSpec) (*Process, error) {
	if p.plat.f == nil {
		return nil, runFailed("the program is no longer held")
	}
	if err := p.recheck(s); err != nil {
		return nil, err
	}
	if s.Dir == "" || !filepath.IsAbs(s.Dir) {
		return nil, badRequest("cwd is not an absolute path")
	}
	app, err := windows.UTF16PtrFromString(p.Path)
	if err != nil {
		return nil, notFound("the program path is invalid")
	}
	cmd, err := windows.UTF16FromString(makeCmdLine(s.Argv))
	if err != nil {
		return nil, badRequest("an argument holds a NUL byte")
	}
	// CreateProcess takes at most 32,767 characters, the ending NUL
	// included; quoting can take an argv within the request's limits past
	// that.
	if len(cmd) > maxCmdLine {
		return nil, badRequest("the command line is %d characters once quoted, at most %d", len(cmd)-1, maxCmdLine-1)
	}
	env, err := envBlock(setVar(s.Env, noCwdExeName, "1"))
	if err != nil {
		return nil, err
	}
	dir, err := windows.UTF16PtrFromString(s.Dir)
	if err != nil {
		return nil, badRequest("cwd is invalid")
	}

	std, cleanup, err := inheritableStdio(s)
	if err != nil {
		return nil, runFailed("the program's standard files can't be set up: %v", err)
	}
	defer cleanup()
	// Only the three standard handles are inherited, whatever else this
	// process holds as inheritable. (chosen; not in the spec)
	al, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		return nil, runFailed("the program can't be started: %v", err)
	}
	defer al.Delete()
	handles := uniqueHandles(std[:])
	if err := al.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&handles[0]),
		uintptr(len(handles))*unsafe.Sizeof(handles[0])); err != nil {
		return nil, runFailed("the program can't be started: %v", err)
	}
	si := new(windows.StartupInfoEx)
	si.Cb = uint32(unsafe.Sizeof(*si))
	si.Flags = windows.STARTF_USESTDHANDLES
	si.StdInput, si.StdOutput, si.StdErr = std[0], std[1], std[2]
	si.ProcThreadAttributeList = al.List()

	var pi windows.ProcessInformation
	// CREATE_NO_WINDOW: a console program gets a console of its own,
	// without a window, never the connector's (AGENT-PLAN §4.9, "The
	// process": no terminal); programs it starts share that hidden one.
	flags := uint32(windows.CREATE_SUSPENDED | windows.CREATE_UNICODE_ENVIRONMENT |
		windows.EXTENDED_STARTUPINFO_PRESENT | windows.CREATE_NO_WINDOW)
	if err := windows.CreateProcess(app, &cmd[0], nil, nil, true, flags, &env[0], dir, &si.StartupInfo, &pi); err != nil {
		return nil, runFailed("the program can't be started: %v", err)
	}
	hook("created")
	if err := p.verifyImage(pi.Process); err != nil {
		endSuspended(pi)
		return nil, err
	}
	hook("checked")
	// The process limits assign the job here, before the resume.
	if _, err := windows.ResumeThread(pi.Thread); err != nil {
		endSuspended(pi)
		return nil, runFailed("the program can't be resumed: %v", err)
	}
	hook("resumed")
	windows.CloseHandle(pi.Thread)
	return &Process{Pid: int(pi.ProcessId), plat: platProcess{h: pi.Process}}, nil
}

// startHook, set by tests only, is told each stage of Start.
var startHook func(stage string)

func hook(stage string) {
	if startHook != nil {
		startHook(stage)
	}
}

// verifyImage checks that the suspended process's image is the held file:
// it opens the path QueryFullProcessImageNameW gives and compares its
// identity with the held handle's. The reopen is by path, which is sound
// only while nothing can move the held file or its folders: the held file
// can't be renamed, and on NTFS renaming a folder above it is refused
// too (TestHeldProgramParentRename; ReFS not yet tried).
//
// The path is the native one (PROCESS_NAME_NATIVE, \Device\...), reopened
// through \\?\GLOBALROOT, so no drive letter is involved in the check: a
// letter redefined between the start and the check can't point the check
// at the held file. (chosen; not in the spec) The start itself uses the
// resolved drive-letter path, since programs read their own path and may
// not handle a native one. That relies on a standard user being unable to
// redefine an existing letter such as C: in its own session
// (TestDriveLetterCantBeRedefined), as the --run-path check does.
func (p *Program) verifyImage(proc windows.Handle) error {
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(proc, windows.PROCESS_NAME_NATIVE, &buf[0], &n); err != nil {
		return runFailed("the started program can't be checked: %v", err)
	}
	img := windows.UTF16ToString(buf[:n])
	if !strings.HasPrefix(img, `\Device\`) {
		return notFound("the started program's name %s is not a device path; the run is refused", img)
	}
	i16, err := windows.UTF16PtrFromString(globalRoot + img)
	if err != nil {
		return runFailed("the started program can't be checked")
	}
	// Attributes only: no data access, so the open needs no sharing from
	// the held handle.
	h, err := windows.CreateFile(i16, windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return notFound("the started program %s can't be opened to check it: %v; the run is refused", img, err)
	}
	defer windows.CloseHandle(h)
	got, _, err := identityOf(h)
	if err != nil {
		return notFound("the started program %s can't be checked: %v; the run is refused", img, err)
	}
	if !p.plat.id.same(got) {
		return notFound("the started program %s is not the file that was checked; the run is refused", img)
	}
	return nil
}

func (a fileIdentity) same(b fileIdentity) bool {
	if a.serial != b.serial || a.index != b.index {
		return false
	}
	if a.has128 && b.has128 {
		return a.vol128 == b.vol128 && a.id128 == b.id128
	}
	return a.has128 == b.has128
}

// globalRoot, before a native path such as \Device\HarddiskVolume3\x.exe,
// opens it through the Win32 file functions.
const globalRoot = `\\?\GLOBALROOT`

// maxCmdLine is CreateProcess's limit on lpCommandLine, in UTF-16 units
// with the ending NUL.
const maxCmdLine = 32767

// endSuspended ends a process that was never resumed.
func endSuspended(pi windows.ProcessInformation) {
	windows.TerminateProcess(pi.Process, 1)
	windows.WaitForSingleObject(pi.Process, 5000)
	windows.CloseHandle(pi.Thread)
	windows.CloseHandle(pi.Process)
}

// makeCmdLine quotes argv for CreateProcess as Go's os/exec does
// (syscall.EscapeArg, which follows the rules of CommandLineToArgvW).
func makeCmdLine(argv []string) string {
	q := make([]string, len(argv))
	for i, a := range argv {
		q[i] = syscall.EscapeArg(a)
	}
	return strings.Join(q, " ")
}

// setVar sets name=value in env, replacing an entry of the same name
// (without case).
func setVar(env []string, name, value string) []string {
	out := make([]string, 0, len(env)+1)
	for _, kv := range env {
		k, _, _ := strings.Cut(kv, "=")
		if !strings.EqualFold(k, name) {
			out = append(out, kv)
		}
	}
	return append(out, name+"="+value)
}

// envBlock is a CREATE_UNICODE_ENVIRONMENT block: each NAME=VALUE ended
// by a NUL, then one more NUL, sorted by name without case as
// CreateProcess documents.
func envBlock(env []string) ([]uint16, error) {
	env = append([]string(nil), env...)
	sort.SliceStable(env, func(i, j int) bool {
		a, _, _ := strings.Cut(env[i], "=")
		b, _, _ := strings.Cut(env[j], "=")
		return strings.ToUpper(a) < strings.ToUpper(b)
	})
	var b []uint16
	for _, kv := range env {
		if i := strings.IndexByte(kv, '='); i <= 0 || strings.IndexByte(kv, 0) >= 0 {
			return nil, badRequest("an environment entry is invalid")
		}
		b = append(b, windows.StringToUTF16(kv)...)
	}
	if len(b) == 0 {
		b = append(b, 0)
	}
	return append(b, 0), nil
}

// inheritableStdio returns inheritable duplicates of the standard files
// (the null device for a nil one) and a function that closes them, and the
// null device files, once the process is created.
func inheritableStdio(s StartSpec) ([3]windows.Handle, func(), error) {
	var out [3]windows.Handle
	var opened []*os.File
	var dups []windows.Handle
	cleanup := func() {
		for _, h := range dups {
			windows.CloseHandle(h)
		}
		for _, f := range opened {
			f.Close()
		}
	}
	cur := windows.CurrentProcess()
	for i, f := range []*os.File{s.Stdin, s.Stdout, s.Stderr} {
		if f == nil {
			flag := os.O_RDONLY
			if i > 0 {
				flag = os.O_WRONLY
			}
			nf, err := os.OpenFile(os.DevNull, flag, 0)
			if err != nil {
				cleanup()
				return out, nil, err
			}
			opened = append(opened, nf)
			f = nf
		}
		var d windows.Handle
		if err := windows.DuplicateHandle(cur, windows.Handle(f.Fd()), cur, &d, 0, true, windows.DUPLICATE_SAME_ACCESS); err != nil {
			cleanup()
			return out, nil, err
		}
		dups = append(dups, d)
		out[i] = d
	}
	return out, cleanup, nil
}

func uniqueHandles(hs []windows.Handle) []windows.Handle {
	var out []windows.Handle
	for _, h := range hs {
		dup := false
		for _, o := range out {
			dup = dup || o == h
		}
		if !dup {
			out = append(out, h)
		}
	}
	return out
}

// platProcess is the process handle from CreateProcess.
type platProcess struct{ h windows.Handle }

func (p *platProcess) wait() (int, error) {
	if p.h == 0 {
		return -1, errors.New("already waited for")
	}
	if _, err := windows.WaitForSingleObject(p.h, windows.INFINITE); err != nil {
		return -1, err
	}
	var code uint32
	err := windows.GetExitCodeProcess(p.h, &code)
	windows.CloseHandle(p.h)
	p.h = 0
	if err != nil {
		return -1, err
	}
	return int(code), nil
}

func (p *platProcess) kill() error {
	if p.h == 0 {
		return nil
	}
	return windows.TerminateProcess(p.h, 1)
}

// checkFormat accepts a Windows program only: an MZ header. Anything else
// (a .jar, a script without #!) would be run by whatever the system has
// registered for it, not by the file that was hashed. (chosen; not in the
// spec)
func checkFormat(head []byte) error {
	if len(head) >= 2 && head[0] == 'M' && head[1] == 'Z' {
		return nil
	}
	return errors.New("is not a Windows program (no MZ header)")
}
