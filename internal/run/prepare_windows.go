//go:build windows

package run

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"unicode/utf16"
	"unicode/utf8"
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

	// For a batch file: System32's cmd.exe, held the same way, which is
	// the image the image check expects (batch_windows.go).
	cmd   *os.File
	cmdID fileIdentity
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
//
// A batch file (.cmd, .bat) is held and hashed the same way (it must not
// be a Windows program), and System32's cmd.exe, which runs it, is
// checked like any program and held too.
func Prepare(path, _ string) (*Program, error) {
	if path == "" || !filepath.IsAbs(path) || isUNC(path) || !canExecute(path, nil) {
		return nil, notFound("%s is not a program the connector runs", path)
	}
	f, h, err := holdFile(path)
	if err != nil {
		return nil, err
	}
	prog, err := prepareHeld(f, h, path)
	if err != nil {
		f.Close()
		return nil, err
	}
	if isBatch(path) {
		if err := batchMayRun(path); err != nil {
			prog.Close()
			return nil, err
		}
		if err := prog.holdCmd(); err != nil {
			prog.Close()
			return nil, err
		}
	}
	return prog, nil
}

// holdFile opens path to hold it unchanged.
func holdFile(path string) (*os.File, windows.Handle, error) {
	p16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, 0, notFound("the program path is invalid")
	}
	// FILE_SHARE_READ alone: no writing, renaming or deleting while held.
	// FILE_FLAG_OPEN_REPARSE_POINT: a link at the path is opened as
	// itself, and refused below, not followed.
	h, err := windows.CreateFile(p16, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	// A file someone else holds for writing is refused as
	// program_not_found. (chosen; not in the spec)
	if errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
		return nil, 0, notFound("%s is open for writing or deleting by another process, so it can't be held unchanged; the run is refused", path)
	}
	if err != nil {
		return nil, 0, notFound("%s can't be opened: %v", path, err)
	}
	// The file held must be the one the path names, through no link or
	// junction above it: its final name is the path, exactly. (chosen;
	// not in the spec)
	if name, err := finalDosName(h); err != nil || name != path {
		windows.CloseHandle(h)
		if err != nil {
			return nil, 0, notFound("%s can't be checked: %v", path, err)
		}
		return nil, 0, notFound("%s is reached through a link or junction (it is %s); the run is refused", path, name)
	}
	return os.NewFile(uintptr(h), path), h, nil
}

// finalDosName is a handle's file name as the system gives it now, with
// a drive letter, without the \\?\ prefix.
func finalDosName(h windows.Handle) (string, error) {
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetFinalPathNameByHandle(h, &buf[0], uint32(len(buf)), fileNameNormalized)
	if err != nil {
		return "", err
	}
	if int(n) >= len(buf) {
		return "", errors.New("the name is too long")
	}
	name := windows.UTF16ToString(buf[:n])
	if strings.HasPrefix(name, `\\?\UNC\`) {
		return "", errors.New("it is on a network share")
	}
	return strings.TrimPrefix(name, `\\?\`), nil
}

// verifyBatchPath checks, before a batch run resumes, that its path still
// names the held batch file (cmd.exe opens it by path for each command):
// the same file, by its final name and its identity, with no reparse
// point on it.
func verifyBatchPath(path string, id fileIdentity) error {
	p16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return notFound("the program path is invalid")
	}
	h, err := windows.CreateFile(p16, windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return notFound("%s can't be opened to check it: %v; the run is refused", path, err)
	}
	defer windows.CloseHandle(h)
	got, attrs, err := identityOf(h)
	if err != nil {
		return notFound("%s can't be checked: %v; the run is refused", path, err)
	}
	if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return notFound("%s is now a link or other reparse point; the run is refused", path)
	}
	if name, err := finalDosName(h); err != nil || name != path || !id.same(got) {
		return notFound("%s no longer names the batch file that was checked; the run is refused", path)
	}
	return nil
}

// holdCmd checks and holds System32's cmd.exe for a batch run.
func (p *Program) holdCmd() error {
	cmd, err := cmdExePath()
	if err != nil {
		return err
	}
	// The system directory's name as on disk (GetSystemDirectory may
	// differ in case), for holdFile's exact name check.
	if cmd, err = filepath.EvalSymlinks(cmd); err != nil {
		return runFailed("cmd.exe can't be found: %v", err)
	}
	if err := checkProgram(cmd); err != nil {
		return notFound("cmd.exe isn't run: %v", err)
	}
	f, h, err := holdFile(cmd)
	if err != nil {
		return err
	}
	held, err := prepareHeld(f, h, cmd)
	if err != nil {
		f.Close()
		return err
	}
	p.plat.cmd, p.plat.cmdID = f, held.plat.id
	return nil
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
	format := checkFormat
	if isBatch(path) {
		format = checkBatchFormat
	}
	sum, err := hashingCopyAs(nil, f, path, 0, format)
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

// Close releases the held files. Call it after Start, or when the run is
// refused. A started batch file stays held by its Process until the
// process ends: cmd.exe reads it while it runs.
func (p *Program) Close() error {
	var err error
	if p.plat.f != nil {
		err = p.plat.f.Close()
		p.plat.f = nil
	}
	if p.plat.cmd != nil {
		if cerr := p.plat.cmd.Close(); err == nil {
			err = cerr
		}
		p.plat.cmd = nil
	}
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
	if err := checkSecret(s.Secret); err != nil {
		return nil, err
	}
	appPath, line := p.Path, makeCmdLine(s.Argv)
	image, imageID := p.plat.f, p.plat.id
	if p.plat.cmd != nil {
		// A batch file: cmd.exe runs it, with every part checked first.
		if err := checkBatch(p.Path, s.Dir, s.Argv[1:], s.Env, s.Trusted); err != nil {
			return nil, err
		}
		if s.Secret != nil && !batchSecretOK(s.Secret.Value) {
			return nil, &Error{Code: CodeArgumentNotAllowed, Msg: TextSecretNotForBatch}
		}
		appPath, line = p.plat.cmd.Name(), batchCmdLine(p.plat.cmd.Name(), p.Path, s.Argv[1:])
		if n := len(windows.StringToUTF16(line)) - 1; n > maxBatchCmdLine {
			return nil, badRequest("the command line is %d characters, at most %d for a batch file", n, maxBatchCmdLine)
		}
		image, imageID = p.plat.cmd, p.plat.cmdID
	}
	app, err := windows.UTF16PtrFromString(appPath)
	if err != nil {
		return nil, notFound("the program path is invalid")
	}
	cmd, err := windows.UTF16FromString(line)
	if err != nil {
		return nil, badRequest("an argument holds a NUL byte")
	}
	// CreateProcess takes at most 32,767 characters, the ending NUL
	// included; quoting can take an argv within the request's limits past
	// that.
	if len(cmd) > maxCmdLine {
		return nil, badRequest("the command line is %d characters once quoted, at most %d", len(cmd)-1, maxCmdLine-1)
	}
	env, err := envBlock(setVar(s.Env, noCwdExeName, "1"), s.Secret)
	if err != nil {
		return nil, err
	}
	// The block holds the secret's value: cleared once the process is
	// created (or not).
	defer clear(env)
	dir, err := windows.UTF16PtrFromString(s.Dir)
	if err != nil {
		return nil, badRequest("cwd is invalid")
	}

	pi, err := createSuspended(app, &cmd[0], &env[0], dir, s)
	if err != nil {
		return nil, err
	}
	hook("created")
	if err := verifyImage(pi.Process, image, imageID); err != nil {
		return nil, endSuspended(pi, s, err)
	}
	if p.plat.cmd != nil {
		if err := verifyBatchPath(p.Path, p.plat.id); err != nil {
			return nil, endSuspended(pi, s, err)
		}
	}
	hook("checked")
	// The process limits assign the job here, before the resume.
	if _, err := windows.ResumeThread(pi.Thread); err != nil {
		return nil, endSuspended(pi, s, runFailed("the program can't be resumed: %v", err))
	}
	hook("resumed")
	windows.CloseHandle(pi.Thread)
	proc := &Process{Pid: int(pi.ProcessId), plat: platProcess{h: pi.Process}}
	if p.plat.cmd != nil {
		// cmd.exe reads the batch file while it runs: the process holds
		// it until it ends (platProcess.wait), not Close.
		proc.plat.held, p.plat.f = p.plat.f, nil
	}
	return proc, nil
}

// createSuspended creates the process suspended. The inheritable
// duplicates of the standard files exist only under syscall.ForkLock, as
// for Go's own process starts, so no other start in this process can
// inherit them; only those three are inherited by this one.
func createSuspended(app, cmd, env, dir *uint16, s StartSpec) (windows.ProcessInformation, error) {
	var pi windows.ProcessInformation
	syscall.ForkLock.Lock()
	defer syscall.ForkLock.Unlock()
	std, cleanup, err := inheritableStdio(s)
	if err != nil {
		return pi, runFailed("the program's standard files can't be set up: %v", err)
	}
	defer cleanup()
	// Only the three standard handles are inherited, whatever else this
	// process holds as inheritable. (chosen; not in the spec)
	al, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		return pi, runFailed("the program can't be started: %v", err)
	}
	defer al.Delete()
	handles := uniqueHandles(std[:])
	if err := al.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&handles[0]),
		uintptr(len(handles))*unsafe.Sizeof(handles[0])); err != nil {
		return pi, runFailed("the program can't be started: %v", err)
	}
	si := new(windows.StartupInfoEx)
	si.Cb = uint32(unsafe.Sizeof(*si))
	si.Flags = windows.STARTF_USESTDHANDLES
	si.StdInput, si.StdOutput, si.StdErr = std[0], std[1], std[2]
	si.ProcThreadAttributeList = al.List()
	// CREATE_NO_WINDOW: a console program gets a console of its own,
	// without a window, never the connector's (AGENT-PLAN §4.9, "The
	// process": no terminal); programs it starts share that hidden one.
	flags := uint32(windows.CREATE_SUSPENDED | windows.CREATE_UNICODE_ENVIRONMENT |
		windows.EXTENDED_STARTUPINFO_PRESENT | windows.CREATE_NO_WINDOW)
	if err := windows.CreateProcess(app, cmd, nil, nil, true, flags, env, dir, &si.StartupInfo, &pi); err != nil {
		return pi, runFailed("the program can't be started: %v", err)
	}
	return pi, nil
}

// startHook, set by tests only, is told each stage of Start.
var startHook func(stage string)

func hook(stage string) {
	if startHook != nil {
		startHook(stage)
	}
}

// verifyImage checks that the suspended process's image is the held file,
// in two ways, each needed:
//   - its native image name (PROCESS_NAME_NATIVE, \Device\...) is the
//     held handle's own native name (GetFinalPathNameByHandle with
//     VOLUME_NAME_NT), compared without case; and
//   - that name, reopened through \\?\GLOBALROOT with no drive letter
//     involved, is the held file by volume serial number and file id, on
//     an NTFS or ReFS volume.
//
// What this shows: the process was created from a file whose name, at
// the check, is the held file's own name and which is the held file. The
// identity alone would not do: a process started from another file B (if
// the start's path were redirected, as through a symbolic link object in
// the user's own DosDevices folder), then B renamed and the held file
// hard-linked at B's old name (which needs only FILE_WRITE_ATTRIBUTES on
// it), would pass it; the names then differ (TestStartRefusesAHardLinkSwap).
// What it does not show: that the image's bytes were read from the held
// file if a name was redirected and put back between the start and the
// check. The start uses the resolved drive-letter path, since programs
// read their own path and may not handle a native one; DefineDosDevice
// refuses a standard user's redefinition of an existing letter such as
// C: (TestDriveLetterCantBeRedefined), but that test does not cover
// other ways of redirecting a name in the user's own DosDevices folder.
// The held file can't be renamed, and on NTFS renaming a folder above it
// is refused too (TestHeldProgramParentRename; ReFS not yet tried).
// (chosen; not in the spec)
//
// For a batch file the image is System32's cmd.exe, held by the Program
// beside the batch file; held and id are that file's.
func verifyImage(proc windows.Handle, held *os.File, id fileIdentity) error {
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(proc, windows.PROCESS_NAME_NATIVE, &buf[0], &n); err != nil {
		return runFailed("the started program can't be checked: %v", err)
	}
	img := windows.UTF16ToString(buf[:n])
	if !strings.HasPrefix(img, `\Device\`) {
		return notFound("the started program's name %s is not a device path; the run is refused", img)
	}
	heldName, err := finalNativeName(windows.Handle(held.Fd()))
	if err != nil {
		return runFailed("the held program's name can't be read: %v", err)
	}
	if !strings.EqualFold(img, heldName) {
		return notFound("the started program %s is not the file that was checked (%s); the run is refused", img, heldName)
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
	if !id.same(got) {
		return notFound("the started program %s is not the file that was checked; the run is refused", img)
	}
	if fs, err := volumeFileSystem(h); err != nil || !allowedFileSystem(fs) {
		return notFound("the started program %s is not on an NTFS or ReFS volume; the run is refused", img)
	}
	return nil
}

// finalNativeName is a handle's file name as the system gives it now,
// with the volume's device name (\Device\...).
func finalNativeName(h windows.Handle) (string, error) {
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetFinalPathNameByHandle(h, &buf[0], uint32(len(buf)), fileNameNormalized|volumeNameNT)
	if err != nil {
		return "", err
	}
	if int(n) >= len(buf) {
		return "", errors.New("the name is too long")
	}
	return windows.UTF16ToString(buf[:n]), nil
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

// endSuspended ends a process that was never resumed, and returns
// refusal, the run's error. If the process can't be ended, that is logged
// (its id and the system's error only) and added to the error: it stays
// suspended, never having run, until the connector exits.
func endSuspended(pi windows.ProcessInformation, s StartSpec, refusal error) error {
	defer windows.CloseHandle(pi.Process)
	defer windows.CloseHandle(pi.Thread)
	if err := windows.TerminateProcess(pi.Process, 1); err != nil {
		logger(s).Warn("run: a refused suspended process could not be ended", "pid", pi.ProcessId, "err", err)
		var e *Error
		if errors.As(refusal, &e) {
			return &Error{Code: e.Code, Msg: e.Msg + fmt.Sprintf("; the suspended process %d could not be ended: %v", pi.ProcessId, err)}
		}
		return fmt.Errorf("%w; the suspended process %d could not be ended: %v", refusal, pi.ProcessId, err)
	}
	windows.WaitForSingleObject(pi.Process, 5000)
	return refusal
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
// CreateProcess documents. The secret, if any, is added from its bytes
// (replacing an entry of the same name), never through a Go string; the
// caller clears the block.
func envBlock(env []string, secret *Secret) ([]uint16, error) {
	type entry struct {
		key    string
		secret bool
		kv     string
	}
	var es []entry
	for _, kv := range env {
		k, _, ok := strings.Cut(kv, "=")
		if !ok || k == "" || strings.IndexByte(kv, 0) >= 0 {
			return nil, badRequest("an environment entry is invalid")
		}
		if secret != nil && strings.EqualFold(k, secret.Name) {
			continue
		}
		es = append(es, entry{key: strings.ToUpper(k), kv: kv})
	}
	if secret != nil {
		es = append(es, entry{key: strings.ToUpper(secret.Name), secret: true})
	}
	sort.SliceStable(es, func(i, j int) bool { return es[i].key < es[j].key })
	var b []uint16
	for _, e := range es {
		if !e.secret {
			b = append(b, windows.StringToUTF16(e.kv)...)
			continue
		}
		// Grown in place where it fits; a copy left by a reallocation is
		// cleared at once.
		for _, r := range secret.Name + "=" {
			b = appendUTF16(b, r)
		}
		for rest := secret.Value; len(rest) > 0; {
			r, n := utf8.DecodeRune(rest)
			b = appendUTF16(b, r)
			rest = rest[n:]
		}
		b = appendUTF16(b, 0)
	}
	if len(b) == 0 {
		b = append(b, 0)
	}
	return appendUTF16(b, 0), nil
}

// appendUTF16 appends r to b, clearing b's old array if it had to grow.
func appendUTF16(b []uint16, r rune) []uint16 {
	n := utf16.AppendRune(b, r)
	if len(b) > 0 && &n[0] != &b[0] {
		clear(b[:cap(b)])
	}
	return n
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
// held, for a batch run, is the batch file, held until the process ends:
// cmd.exe reads it while it runs.
type platProcess struct {
	h    windows.Handle
	held *os.File
}

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
	if p.held != nil {
		p.held.Close()
		p.held = nil
	}
	if err != nil {
		return -1, err
	}
	return int(code), nil
}

// kill ends the process; a held batch file is released once the process
// is seen to have ended (within 5 s), whether or not Wait follows.
func (p *platProcess) kill() error {
	if p.h == 0 {
		return nil
	}
	err := windows.TerminateProcess(p.h, 1)
	if p.held != nil {
		if ev, werr := windows.WaitForSingleObject(p.h, 5000); werr == nil && ev == windows.WAIT_OBJECT_0 {
			p.held.Close()
			p.held = nil
		}
	}
	return err
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

// GetFinalPathNameByHandleW's flags: the normalized name, with the
// volume's device name.
const (
	fileNameNormalized = 0x0
	volumeNameNT       = 0x2
)
