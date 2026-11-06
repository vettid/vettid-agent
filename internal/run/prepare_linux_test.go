//go:build linux

package run

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The memory file is sealed: its seals are the four, and writing fails.
func TestPrepareSealsTheMemoryFile(t *testing.T) {
	exe := helperCopy(t, t.TempDir(), "helper")
	p := prepare(t, exe)
	fd := int(p.plat.exe.Fd())
	seals, err := unix.FcntlInt(uintptr(fd), unix.F_GET_SEALS, 0)
	if err != nil {
		t.Fatal(err)
	}
	if seals&programSeals != programSeals {
		t.Fatalf("seals %#x, want %#x", seals, programSeals)
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_ADD_SEALS, unix.F_SEAL_FUTURE_WRITE); err == nil {
		t.Error("seals changed after F_SEAL_SEAL")
	}
	// Opening for writing is allowed; the seals refuse the writes.
	w, err := os.OpenFile(fmt.Sprintf("/proc/self/fd/%d", fd), os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("opening the memory file for writing, to try the seals: %v", err)
	}
	defer w.Close()
	if _, err := w.Write([]byte("x")); err == nil {
		t.Fatal("wrote to the sealed memory file")
	}
	if _, err := w.WriteAt([]byte("x"), 1<<40); err == nil {
		t.Fatal("grew the sealed memory file")
	}
	if err := w.Truncate(0); err == nil {
		t.Fatal("shrank the sealed memory file")
	}
	// The file on disk can still change; the memory file doesn't.
	if err := os.WriteFile(exe, []byte("changed"), 0o755); err != nil {
		t.Fatal(err)
	}
	fi, err := p.plat.exe.Stat()
	if err != nil || fi.Size() < 1000 {
		t.Fatalf("memory file after the disk file changed: %v, %v", fi, err)
	}
}

// The started image is the memory file, reached through the descriptor
// the child holds as the path names it.
func TestStartRunsTheMemoryFile(t *testing.T) {
	lookupOnly(t)
	exe := helperCopy(t, t.TempDir(), "helper")
	p := prepare(t, exe)
	code, out := runOutput(t, p, helperSpec(t, exe, "exe"))
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if got := strings.TrimSpace(out); !strings.HasPrefix(got, "/memfd:vettid-run") {
		t.Fatalf("started image %q, want the memory file", got)
	}
}

// Without MFD_EXEC (a kernel before 6.3 answers EINVAL) the memory file
// is made again without it.
func TestPrepareRetriesWithoutMFDExec(t *testing.T) {
	var calls []int
	old := memfdCreate
	memfdCreate = func(name string, flags int) (int, error) {
		calls = append(calls, flags)
		if flags&unix.MFD_EXEC != 0 {
			return -1, unix.EINVAL
		}
		return old(name, flags)
	}
	t.Cleanup(func() { memfdCreate = old })
	exe := helperCopy(t, t.TempDir(), "helper")
	prepare(t, exe)
	if len(calls) != 2 || calls[1]&unix.MFD_EXEC != 0 {
		t.Fatalf("memfd_create flags %v", calls)
	}
}

// Where a memory file can't be run (as under vm.memfd_noexec = 2, made
// here with MFD_NOEXEC_SEAL), the run is refused as run_failed, and the
// program is not started by its path.
func TestStartRefusesWhenMemoryFilesCantRun(t *testing.T) {
	lookupOnly(t)
	old := memfdCreate
	memfdCreate = func(name string, flags int) (int, error) {
		return old(name, flags&^unix.MFD_EXEC|unix.MFD_NOEXEC_SEAL)
	}
	t.Cleanup(func() { memfdCreate = old })
	exe := helperCopy(t, t.TempDir(), "helper")
	p, err := Prepare(exe, "")
	if errors.Is(err, ErrRunFailed) {
		t.Skipf("MFD_NOEXEC_SEAL not supported by this kernel: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	// The file at the path is the helper, which would write the marker if
	// it were started by its path.
	marker := filepath.Join(t.TempDir(), "marker")
	proc, err := p.Start(helperSpec(t, exe, "marker", Var{"VETTID_RUN_TEST_MARKER", marker}))
	if !errors.Is(err, ErrRunFailed) {
		if proc != nil {
			proc.Wait()
		}
		t.Fatalf("non-executable memory file: %v, want run_failed", err)
	}
	time.Sleep(200 * time.Millisecond)
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the program was started by its path")
	}
}

// A program larger than the memory file's cap is refused; one at the cap
// is held.
func TestPrepareCapsTheMemoryFile(t *testing.T) {
	old := maxMemfdSize
	maxMemfdSize = 1 << 20
	t.Cleanup(func() { maxMemfdSize = old })
	p := filepath.Join(t.TempDir(), "big")
	body := make([]byte, 1<<20)
	copy(body, "\x7fELF")
	if err := os.WriteFile(p, body, 0o755); err != nil {
		t.Fatal(err)
	}
	q, err := Prepare(p, "")
	if err != nil {
		t.Fatalf("at the cap: %v", err)
	}
	q.Close()
	if err := os.WriteFile(p, append(body, 0), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare(p, ""); !errors.Is(err, ErrProgramNotFound) || !strings.Contains(err.Error(), "larger than 1 MiB") {
		t.Fatalf("past the cap: %v", err)
	}
}
