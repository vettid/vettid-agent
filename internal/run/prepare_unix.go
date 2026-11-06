//go:build linux || darwin

package run

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

// openProgram opens a resolved program path once for reading and refuses
// anything but a regular file the operator may run. O_NOFOLLOW: links
// were resolved, so a link at the path now was put there since; O_NONBLOCK:
// a FIFO put at the path doesn't block the open (it is refused below).
func openProgram(path string) (*os.File, error) {
	if path == "" || !filepath.IsAbs(path) {
		return nil, notFound("%s is not an absolute path", path)
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, notFound("%s can't be opened: %v", path, err)
	}
	f := os.NewFile(uintptr(fd), path)
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() || !canExecute(path, fi) {
		f.Close()
		return nil, notFound("%s is not a regular file the operator may run", path)
	}
	return f, nil
}

// startCmd starts the program at exe (the memory file's /proc path or the
// private copy), with extra as the child's files from 3 on. It runs in a
// session of its own (setsid), so it has no controlling terminal, never
// the connector's (AGENT-PLAN §4.9, "The process": no terminal). The
// limits and the group's ending come with the process limits.
func startCmd(exe string, extra []*os.File, s StartSpec) (*Process, error) {
	if s.Dir == "" || !filepath.IsAbs(s.Dir) {
		return nil, badRequest("cwd is not an absolute path")
	}
	if err := cloexecAll(); err != nil {
		return nil, runFailed("the connector's open files can't be kept from the program: %v", err)
	}
	cmd := &exec.Cmd{
		Path:        exe,
		Args:        append([]string(nil), s.Argv...),
		Env:         append([]string{}, s.Env...),
		Dir:         s.Dir,
		ExtraFiles:  extra,
		SysProcAttr: &syscall.SysProcAttr{Setsid: true},
	}
	// A nil *os.File in an io.Reader or io.Writer isn't nil: set only
	// those given, so the others are the null device.
	if s.Stdin != nil {
		cmd.Stdin = s.Stdin
	}
	if s.Stdout != nil {
		cmd.Stdout = s.Stdout
	}
	if s.Stderr != nil {
		cmd.Stderr = s.Stderr
	}
	if err := cmd.Start(); err != nil {
		return nil, runFailed("the program can't be started: %v", err)
	}
	return &Process{Pid: cmd.Process.Pid, plat: platProcess{cmd: cmd}}, nil
}

// cloexecAll marks every descriptor from 3 up close-on-exec, so none
// that the connector holds without the flag (one its starter, the MCP
// client, left open, for example) reaches a run. The standard files and
// ExtraFiles are placed in the child by os/exec, which clears the flag on
// those alone. (chosen; not in the spec)
func cloexecAll() error {
	dir := "/dev/fd"
	if runtime.GOOS == "linux" {
		dir = "/proc/self/fd"
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range ents {
		fd, err := strconv.Atoi(e.Name())
		if err != nil || fd < 3 {
			continue
		}
		// The directory's own descriptor is listed too, and closed by
		// now: EBADF is expected for it.
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFD, unix.FD_CLOEXEC); err != nil && err != unix.EBADF {
			return err
		}
	}
	return nil
}

// platProcess is the started command.
type platProcess struct{ cmd *exec.Cmd }

func (p *platProcess) wait() (int, error) {
	err := p.cmd.Wait()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), nil
	}
	if err != nil {
		return -1, err
	}
	return p.cmd.ProcessState.ExitCode(), nil
}

func (p *platProcess) kill() error { return p.cmd.Process.Kill() }
