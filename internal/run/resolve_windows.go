//go:build windows

package run

import (
	"os"
	"path/filepath"
	"strings"
)

// The minimal environment copied from the connector (AGENT-PLAN §4.9).
var minimalNames = []string{"SystemRoot", "SystemDrive", "windir", "PATHEXT", "USERPROFILE",
	"USERNAME", "HOMEDRIVE", "HOMEPATH", "APPDATA", "LOCALAPPDATA"}

// tempNames are set to the run's tmp directory.
var tempNames = []string{"TEMP", "TMP"}

// Windows variable names are case-insensitive.
func sameName(a, b string) bool { return strings.EqualFold(a, b) }

// FixedPath is the connector's fixed search path for bare program names:
// %SystemRoot%\System32 and %SystemRoot%. Without SystemRoot (or windir)
// it is empty, and no bare name is found.
func FixedPath() []string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = os.Getenv("windir")
	}
	if root == "" || !filepath.IsAbs(root) {
		return nil
	}
	return []string{filepath.Join(root, "System32"), filepath.Clean(root)}
}

// hasSeparator: a slash, a backslash or a volume name (a colon).
func hasSeparator(s string) bool { return strings.ContainsAny(s, `/\:`) }

func pathExt() []string {
	v := os.Getenv("PATHEXT")
	if v == "" {
		v = ".COM;.EXE;.BAT;.CMD"
	}
	var out []string
	for _, e := range strings.Split(v, ";") {
		if strings.HasPrefix(e, ".") && len(e) > 1 {
			out = append(out, strings.ToLower(e))
		}
	}
	return out
}

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

// canExecute: a regular file whose extension is in PATHEXT.
func canExecute(path string, _ os.FileInfo) bool { return hasExt(path, pathExt()) }

// isUNC: a network path, \\host\share\... or //host/share/... (the
// \\?\UNC\ form included). (chosen; not in the spec)
func isUNC(path string) bool {
	return strings.HasPrefix(path, `\\`) || strings.HasPrefix(path, `//`)
}
