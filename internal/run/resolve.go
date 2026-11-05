package run

import (
	"os"
	"path/filepath"
	"strings"
)

// checkProgram is the rule a resolved program must pass at every run:
// it, its own folder and the folders above it can't be changed by the
// connector's user (owner decision, 2026-11-05; programUnchangeable). Tests of the lookup order alone replace it.
var checkProgram = programUnchangeable

// checkPlain is plainPath, replaced by tests of the pin alone.
var checkPlain = plainPath

// fixedPath is FixedPath, replaced by tests (the Homebrew case).
var fixedPath = FixedPath

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
	return ResolvePinned(argv0, runPath, "")
}

// ResolvePinned is Resolve for a program whose catalog entry may hold a
// pinned path (VAULT-MESSAGING §10.11, the catalog's `path`; AGENT-PLAN
// §4.9, "The program's content"). The check of a program only an
// administrator can change (checkProgram) runs for every resolved program
// except one exactly equal to pinned (without case on Windows); the vault
// pins that file by its SHA-256, so a changed file there is referred to
// the phone. A pinned program moved elsewhere gets the check again. An
// empty pinned matches nothing. The other refusals still apply to the
// pinned path: a junction or other reparse point in it, and on Windows a
// drive that is not a fixed local disk (plainPath).
func ResolvePinned(argv0 string, runPath []string, pinned string) (string, error) {
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
		return checked(p, pinned)
	}
	if hasSeparator(argv0) {
		return "", notFound("%s is neither an absolute path nor a bare name", argv0)
	}
	dirs := append(fixedPath(), runPath...)
	for _, dir := range dirs {
		if dir == "" || !filepath.IsAbs(dir) {
			continue
		}
		for _, cand := range candidates(dir, argv0) {
			// The first program found is the one: a refused one isn't
			// skipped for another of the same name further on.
			if p, ok := executable(cand); ok {
				return checked(p, pinned)
			}
		}
	}
	return "", notFound("%s was not found on the connector's search path", argv0)
}

// checked applies checkProgram to a resolved program, or for the pinned
// path the path rules alone (checkPlain).
func checked(p, pinned string) (string, error) {
	if pinned != "" && samePath(p, pinned) {
		if err := checkPlain(p); err != nil {
			return "", notFound("the program isn't run: %v", err)
		}
		return p, nil
	}
	if err := checkProgram(p); err != nil {
		return "", notFound("the program isn't run: %v", err)
	}
	return p, nil
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
