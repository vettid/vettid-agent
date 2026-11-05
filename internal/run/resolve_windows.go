//go:build windows

package run

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// The minimal environment copied from the connector (AGENT-PLAN §4.9).
var minimalNames = []string{"SystemRoot", "SystemDrive", "windir", "PATHEXT", "USERPROFILE",
	"USERNAME", "HOMEDRIVE", "HOMEPATH", "APPDATA", "LOCALAPPDATA"}

// tempNames are set to the run's tmp directory.
var tempNames = []string{"TEMP", "TMP"}

// Windows variable names are case-insensitive.
func sameName(a, b string) bool { return strings.EqualFold(a, b) }

// FixedPath is the connector's fixed search path for bare program names:
// the system's Windows directory's System32, then the directory itself.
// It comes from the system (GetSystemWindowsDirectory), never from an
// inherited SystemRoot or windir, which the connector's starter could set.
// Without it no bare name is found.
func FixedPath() []string {
	root, err := windows.GetSystemWindowsDirectory()
	if err != nil || root == "" || !filepath.IsAbs(root) {
		return nil
	}
	return []string{filepath.Join(root, "System32"), filepath.Clean(root)}
}

// hasSeparator: a slash, a backslash or a volume name (a colon).
func hasSeparator(s string) bool { return strings.ContainsAny(s, `/\:`) }

// pathExt: the program extensions, fixed, never an inherited PATHEXT.
// .bat and .cmd are left out: their arguments go through cmd.exe, which
// Go can't quote safely, so an agent's argument could run a command.
// (chosen; not in the spec)
func pathExt() []string { return []string{".exe", ".com"} }

func hasExt(name string, exts []string) bool {
	e := strings.ToLower(filepath.Ext(name))
	for _, x := range exts {
		if x == e {
			return true
		}
	}
	return false
}

// candidates: the name itself when it has a PATHEXT extension, then the
// name with each PATHEXT extension appended.
func candidates(dir, name string) []string {
	exts := pathExt()
	var out []string
	if hasExt(name, exts) {
		out = append(out, filepath.Join(dir, name))
	}
	for _, x := range exts {
		out = append(out, filepath.Join(dir, name+x))
	}
	return out
}

// canExecute: a regular file with a program extension, and no stream
// name (x.txt:s.exe names an alternate data stream).
func canExecute(path string, _ os.FileInfo) bool {
	if strings.Contains(path[len(filepath.VolumeName(path)):], ":") {
		return false
	}
	return hasExt(path, pathExt())
}

// isUNC: a network path, \\host\share\... or //host/share/... (the
// \\?\UNC\ form included). (chosen; not in the spec)
func isUNC(path string) bool {
	return strings.HasPrefix(path, `\\`) || strings.HasPrefix(path, `//`)
}
