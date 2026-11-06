//go:build darwin

package run

import (
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// platProgram is the private copy of the program (AGENT-PLAN §4.9, "Run
// exactly what was hashed", macOS).
//
// macOS has neither an open that refuses writers nor sealed files, so the
// connector copies the program into the run's own bin/ folder (0700) while
// hashing it, and starts the copy. This narrows the gap but does not close
// it: a process of the connector's own user (an agent running as that
// user) can rewrite or replace the copy between the hash and the start,
// and the started bytes are then not the ones hashed. Only a separate
// account for the agent closes it (AGENT-PLAN §4.9, "A separate account
// is the only full protection").
type platProgram struct{ copy string }

// Prepare opens the resolved program path once, refuses anything but a
// regular file the operator may run and a script (#!), and copies it into
// binDir while hashing it. binDir is the run's bin/ folder: created 0700
// if missing, and refused unless it is a plain folder of this user's that
// no one else may use (this check of its owner and 0700 mode: chosen;
// not in the spec).
func Prepare(path, binDir string) (*Program, error) {
	if binDir == "" || !filepath.IsAbs(binDir) {
		return nil, runFailed("the run has no folder for the program's copy")
	}
	if err := os.Mkdir(binDir, 0o700); err != nil && !os.IsExist(err) {
		return nil, runFailed("the folder for the program's copy can't be made: %v", err)
	}
	fi, err := os.Lstat(binDir)
	if err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o700 {
		return nil, runFailed("the folder for the program's copy is not a private folder")
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != os.Geteuid() {
		return nil, runFailed("the folder for the program's copy is not this user's")
	}
	src, err := openProgram(path)
	if err != nil {
		return nil, err
	}
	defer src.Close()
	dst := filepath.Join(binDir, filepath.Base(path))
	fd, err := unix.Open(dst, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o700)
	if err != nil {
		return nil, runFailed("the program's copy can't be made: %v", err)
	}
	out := os.NewFile(uintptr(fd), dst)
	sum, err := hashingCopy(out, src, path)
	if cerr := out.Close(); err == nil && cerr != nil {
		err = runFailed("the program's copy can't be written: %v", cerr)
	}
	if err != nil {
		os.Remove(dst)
		return nil, err
	}
	return &Program{Path: path, SHA256: sum, plat: platProgram{copy: dst}}, nil
}

// Close removes the copy.
func (p *Program) Close() error {
	if p.plat.copy == "" {
		return nil
	}
	err := os.Remove(p.plat.copy)
	p.plat.copy = ""
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// Start resolves argv[0] again (program_not_found if the path changed)
// and starts the copy.
func (p *Program) Start(s StartSpec) (*Process, error) {
	if p.plat.copy == "" {
		return nil, runFailed("the program is no longer held")
	}
	if err := p.recheck(s); err != nil {
		return nil, err
	}
	return startCmd(p.plat.copy, nil, s)
}
