//go:build darwin

package run

import (
	"encoding/binary"
	"errors"
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
//
// The copy also runs from run/<id>/bin/, not from where it was installed:
// libraries it finds relative to itself (@rpath, @loader_path,
// @executable_path) are looked up beside the copy, in a folder of the
// connector's user, so an agent running as that user can put its own
// libraries there for the program to load.
//
// So macOS runs are refused (run_failed) until the separate-account mode
// is built (vettid.org #539); separateAccount is that mode's switch. The
// copy code stays, and the tests turn the switch on. (chosen; not in the
// spec)
type platProgram struct{ copy string }

// separateAccount is true only when the connector and its runs are under
// an account the agent doesn't run as. Nothing sets it yet.
var separateAccount = false

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
	sum, err := hashingCopy(out, src, path, 0)
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

// Start refuses the run unless separateAccount is set; then it resolves
// argv[0] again (program_not_found if the path changed) and starts the
// copy.
func (p *Program) Start(s StartSpec) (*Process, error) {
	if !separateAccount {
		return nil, runFailed("runs on macOS wait for the separate-account mode: an agent running as the connector's user could change the program's copy before it starts")
	}
	if p.plat.copy == "" {
		return nil, runFailed("the program is no longer held")
	}
	if err := p.recheck(s); err != nil {
		return nil, err
	}
	return startCmd(p.plat.copy, nil, s)
}

// checkFormat accepts a Mach-O program only: thin (MH_MAGIC, MH_MAGIC_64)
// or universal (FAT_MAGIC, FAT_MAGIC_64), in either byte order. FAT_MAGIC
// is also a Java class file's magic, which macOS doesn't run directly.
// (chosen; not in the spec)
func checkFormat(head []byte) error {
	if len(head) >= 4 {
		be := binary.BigEndian.Uint32(head)
		le := binary.LittleEndian.Uint32(head)
		for _, m := range []uint32{0xfeedface, 0xfeedfacf, 0xcafebabe, 0xcafebabf} {
			if be == m || le == m {
				return nil
			}
		}
	}
	return errors.New("is not a Mach-O program")
}
