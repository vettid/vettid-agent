//go:build windows

package main

import (
	"bufio"
	"encoding/binary"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modiphlpapi             = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTable = modiphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUdpTable = modiphlpapi.NewProc("GetExtendedUdpTable")
)

// socketsOf lists the TCP and UDP endpoints (IPv4 and IPv6) whose owner is
// pid, as "tcp4", "udp6" and so on.
func socketsOf(t *testing.T, pid uint32) []string {
	t.Helper()
	var found []string
	for _, q := range []struct {
		name   string
		proc   *windows.LazyProc
		af     uint32
		class  uint32 // TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID
		rowLen int    // bytes per row
		pidOff int    // the owning pid's offset in a row
	}{
		{"tcp4", procGetExtendedTcpTable, windows.AF_INET, 5, 24, 20},
		{"tcp6", procGetExtendedTcpTable, windows.AF_INET6, 5, 56, 52},
		{"udp4", procGetExtendedUdpTable, windows.AF_INET, 1, 12, 8},
		{"udp6", procGetExtendedUdpTable, windows.AF_INET6, 1, 28, 24},
	} {
		size := uint32(1 << 16)
		var buf []byte
		for {
			buf = make([]byte, size)
			r, _, _ := q.proc.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, uintptr(q.af), uintptr(q.class), 0)
			if r == 0 {
				break
			}
			if r != uintptr(windows.ERROR_INSUFFICIENT_BUFFER) {
				t.Fatalf("%s table: error %d", q.name, r)
			}
		}
		n := int(binary.LittleEndian.Uint32(buf))
		for i := 0; i < n; i++ {
			off := 4 + i*q.rowLen + q.pidOff
			if binary.LittleEndian.Uint32(buf[off:]) == pid {
				found = append(found, q.name)
			}
		}
	}
	return found
}

// The stub opens no socket of any kind: its only channel is the pipe,
// as a client. Run as a built binary without a service (no configuration
// file for the name), it answers the MCP client and holds no TCP or UDP
// endpoint. (The connected case is the same code with the pipe open:
// TestStubOverPipe.)
func TestStubNoListener(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "vettid-agent.exe")
	if out, err := exec.Command("go", "build", "-o", exe, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	cmd := exec.Command(exe, "mcp", "--name", "no-such-pairing-"+strings.ToLower(time.Now().Format("150405")))
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	outR, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	out := bufio.NewReader(outR)
	for _, m := range []string{msgInit, msgList, msgCall} {
		if _, err := io.WriteString(in, m+"\n"); err != nil {
			t.Fatal(err)
		}
		if _, err := out.ReadString('\n'); err != nil {
			t.Fatalf("no answer: %v", err)
		}
	}
	if s := socketsOf(t, uint32(cmd.Process.Pid)); len(s) != 0 {
		t.Fatalf("the stub holds sockets: %v", s)
	}
	// The check does see a listener: one this test opens is found.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if s := socketsOf(t, uint32(os.Getpid())); !slices.Contains(s, "tcp4") {
		t.Fatalf("the check missed this test's own listener: %v", s)
	}
	in.Close()
	if err := cmd.Wait(); err != nil {
		if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() != 1 {
			t.Fatalf("exit: %v", err)
		}
	}
}
