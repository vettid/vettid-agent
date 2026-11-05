//go:build linux

package run

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// platProgram holds a read-only descriptor of a sealed memory file that
// holds the program's bytes as hashed (AGENT-PLAN §4.9, "Run exactly what
// was hashed", Linux). No one can change sealed content.
type platProgram struct{ exe *os.File }

// The seals: no writing, growing or shrinking, and no seal changes.
const programSeals = unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL

// memfdCreate is unix.MemfdCreate, replaced by tests.
var memfdCreate = unix.MemfdCreate

// Prepare opens the resolved program path once, refuses anything but a
// regular file the operator may run and a script (#!), and copies it into
// a sealed memory file while hashing it. binDir is not used on Linux.
func Prepare(path, _ string) (*Program, error) {
	src, err := openProgram(path)
	if err != nil {
		return nil, err
	}
	defer src.Close()
	// MFD_EXEC needs Linux 6.3 or later; without it older kernels make
	// the file executable anyway.
	fd, err := memfdCreate("vettid-run", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING|unix.MFD_EXEC)
	if errors.Is(err, unix.EINVAL) {
		fd, err = memfdCreate("vettid-run", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	}
	if err != nil {
		return nil, runFailed("a sealed memory file can't be made for the program: %v", err)
	}
	mem := os.NewFile(uintptr(fd), "memfd")
	defer mem.Close()
	sum, err := hashingCopy(mem, src, path)
	if err != nil {
		return nil, err
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_ADD_SEALS, programSeals); err != nil {
		return nil, runFailed("the program's memory file can't be sealed: %v", err)
	}
	// Reopened read only, and the writable descriptor closed, so no
	// descriptor open for writing is left on the file that is started.
	// (chosen; not in the spec)
	ro, err := os.OpenFile(fmt.Sprintf("/proc/self/fd/%d", fd), os.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, runFailed("the program's memory file can't be reopened: %v", err)
	}
	return &Program{Path: path, SHA256: sum, plat: platProgram{exe: ro}}, nil
}

// Close releases the memory file.
func (p *Program) Close() error {
	if p.plat.exe == nil {
		return nil
	}
	err := p.plat.exe.Close()
	p.plat.exe = nil
	return err
}

// childExeFd is the memory file's descriptor in the child: the first of
// os/exec's ExtraFiles, which it places at 3 after the standard files and
// before the program starts, whatever number it has here. The program
// keeps it open, read only and sealed. (chosen; not in the spec)
const childExeFd = 3

// Start resolves argv[0] again (program_not_found if the path changed)
// and starts the memory file through /proc/self/fd/3 in the child. Where
// the system refuses to run a memory file (vm.memfd_noexec = 2) the run is
// refused (run_failed); the program is never started by its path.
func (p *Program) Start(s StartSpec) (*Process, error) {
	if p.plat.exe == nil {
		return nil, runFailed("the program is no longer held")
	}
	if err := p.recheck(s); err != nil {
		return nil, err
	}
	return startCmd(fmt.Sprintf("/proc/self/fd/%d", childExeFd), []*os.File{p.plat.exe}, s)
}
