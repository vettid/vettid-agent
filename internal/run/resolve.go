package run

import (
	"os"
	"path/filepath"
	"strings"
)

// Resolve finds the program for argv0 (AGENT-PLAN §4.9, "Run") and
// returns its path with symbolic links resolved: the `program` the vault
// checks against the item's programs.
//
// An absolute argv0 must be an existing regular file the operator can
// execute. A bare name is looked up only on the fixed search path
// (FixedPath) and then in the operator's runPath directories, never on
// the inherited PATH. Any other argv0 with a separator (on Windows also
// a backslash or a volume name) is program_not_found.
func Resolve(argv0 string, runPath []string) (string, error) {
	if argv0 == "" || strings.IndexByte(argv0, 0) >= 0 {
		return "", notFound("the program name is empty or invalid")
	}
	if filepath.IsAbs(argv0) {
		// A program on a network share isn't run, nor even looked at:
		// reaching it could block, or reach another host.
		if isUNC(argv0) {
			return "", notFound("%s is on a network share", argv0)
		}
		p, ok := executable(argv0)
		if !ok {
			return "", notFound("%s is not an executable file", argv0)
		}
		return p, nil
	}
	if hasSeparator(argv0) {
		return "", notFound("%s is neither an absolute path nor a bare name", argv0)
	}
	dirs := append(FixedPath(), runPath...)
	for _, dir := range dirs {
		if dir == "" || !filepath.IsAbs(dir) {
			continue
		}
		for _, cand := range candidates(dir, argv0) {
			if p, ok := executable(cand); ok {
				return p, nil
			}
		}
	}
	return "", notFound("%s was not found on the connector's search path", argv0)
}

// executable resolves links in path and reports whether the result is a
// regular file the operator can execute.
func executable(path string) (string, bool) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", false
	}
	if !filepath.IsAbs(resolved) {
		resolved, err = filepath.Abs(resolved)
		if err != nil {
			return "", false
		}
	}
	fi, err := os.Stat(resolved)
	if err != nil || !fi.Mode().IsRegular() {
		return "", false
	}
	if !canExecute(resolved, fi) {
		return "", false
	}
	return resolved, true
}
