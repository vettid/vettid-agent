//go:build !windows

package run

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/sys/unix"
)

// The minimal environment copied from the connector (AGENT-PLAN §4.9).
var minimalNames = []string{"HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "LC_CTYPE", "TZ"}

// copiedNames: on POSIX the whole minimal set is copied.
var copiedNames = minimalNames

// systemVars: none on POSIX.
func systemVars() ([]Var, error) { return nil, nil }

// tempNames are set to the run's tmp directory.
var tempNames = []string{"TMPDIR"}

func sameName(a, b string) bool { return a == b }

// FixedPath is the connector's fixed search path for bare program names.
func FixedPath() []string {
	p := []string{"/usr/local/bin", "/usr/bin", "/bin"}
	if runtime.GOOS == "darwin" {
		p = append(p, "/opt/homebrew/bin")
	}
	return p
}

func hasSeparator(s string) bool { return strings.ContainsRune(s, '/') }

func candidates(dir, name string) []string { return []string{filepath.Join(dir, name)} }

// isUNC: never on POSIX, where a leading // is a local path.
func isUNC(string) bool { return false }

func canExecute(path string, fi os.FileInfo) bool {
	if fi.Mode().Perm()&0o111 == 0 {
		return false
	}
	return unix.Access(path, unix.X_OK) == nil
}

// platformLoaderNames: none beyond the shared list on POSIX.
var platformLoaderNames []string
