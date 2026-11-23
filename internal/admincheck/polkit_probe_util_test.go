package admincheck

// Pure helpers of the polkit probe (polkit_probe_linux_test.go), here so
// their tests run everywhere.

import (
	"strconv"
	"strings"
	"testing"
)

// parentOf is the ppid in /proc/<pid>/stat (field 4).
func parentOf(stat []byte) int {
	i := strings.LastIndexByte(string(stat), ')')
	if i < 0 {
		return 0
	}
	f := strings.Fields(string(stat[i+2:]))
	if len(f) < 2 {
		return 0
	}
	v, _ := strconv.Atoi(f[1])
	return v
}

func startTimeOf(stat []byte) uint64 {
	i := strings.LastIndexByte(string(stat), ')')
	if i < 0 {
		return 0
	}
	f := strings.Fields(string(stat[i+2:]))
	if len(f) < 20 {
		return 0
	}
	v, _ := strconv.ParseUint(f[19], 10, 64)
	return v
}

func TestProcStat(t *testing.T) {
	// a comm holding ") " must not shift the fields
	stat := []byte("4242 (a) b (c) S 17 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 987654 1000 10 0")
	if got := parentOf(stat); got != 17 {
		t.Errorf("ppid %d", got)
	}
	if got := startTimeOf(stat); got != 987654 {
		t.Errorf("start time %d", got)
	}
	if parentOf([]byte("junk")) != 0 || startTimeOf([]byte("1 (x) S")) != 0 {
		t.Error("short or broken stat lines should read as 0")
	}
}
