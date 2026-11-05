// Package run holds the pure parts of the run way of leash.run_with_secret
// (AGENT-PLAN §4.9, "Run"): finding the program, building the process
// environment, checking the operator's --run-path and --run-env values,
// and the {secret_file} substitution. It starts nothing; the per-run
// directories and the secret file are in internal/state.
package run

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Wire codes of the errors this package returns.
const (
	CodeProgramNotFound = "program_not_found"
	CodeBadRequest      = "bad_request"
)

// Error carries a wire code and a message that holds no secret value.
type Error struct {
	Code string
	Msg  string
}

func (e *Error) Error() string { return e.Code + ": " + e.Msg }

// Is matches on the code, so errors.Is(err, ErrBadRequest) is true for
// every bad_request error.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Msg == "" && t.Code == e.Code
}

// Sentinels for errors.Is.
var (
	ErrProgramNotFound error = &Error{Code: CodeProgramNotFound}
	ErrBadRequest      error = &Error{Code: CodeBadRequest}
)

// Code returns the wire code of err, or "" if it is not an *Error.
func Code(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

func notFound(format string, a ...any) error {
	return &Error{Code: CodeProgramNotFound, Msg: fmt.Sprintf(format, a...)}
}

func badRequest(format string, a ...any) error {
	return &Error{Code: CodeBadRequest, Msg: fmt.Sprintf(format, a...)}
}

// Limits of the request and of the startup flags.
const (
	MaxRequestEnv   = 32
	MaxEnvValueLen  = 4096
	MaxRunEnvNames  = 32
	MaxRunPathDirs  = 16
	maxNameLen      = 64
	secretFileToken = "{secret_file}"
)

var nameRE = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,63}$`)

// ValidName reports whether name may be used for a request env variable,
// the secret's variable or a --run-env name: it matches
// ^[A-Z_][A-Z0-9_]{0,63}$, is not in the minimal set, PATH, TMPDIR, TEMP
// or TMP, and does not start with LD_ or DYLD_. On Windows the forbidden
// checks ignore case.
func ValidName(name string) bool { return checkName(name) == nil }

func checkName(name string) error {
	if len(name) > maxNameLen || !nameRE.MatchString(name) {
		return badRequest("variable name %q is not allowed", shorten(name))
	}
	if strings.HasPrefix(name, "LD_") || strings.HasPrefix(name, "DYLD_") {
		return badRequest("variable name %q is not allowed", name)
	}
	for _, f := range forbiddenNames() {
		if sameName(f, name) {
			return badRequest("variable name %q is not allowed", name)
		}
	}
	return nil
}

func shorten(s string) string {
	if len(s) > 32 {
		return s[:32] + "..."
	}
	return s
}

func forbiddenNames() []string {
	out := append([]string{}, minimalNames...)
	return append(out, "PATH", "TMPDIR", "TEMP", "TMP")
}

// Var is one environment variable.
type Var struct{ Name, Value string }

// Spec says what the process environment is made of.
type Spec struct {
	// Tmp is the run's tmp directory (TMPDIR, or TEMP and TMP).
	Tmp string
	// RunPath is the operator's --run-path directories, appended to
	// the fixed search path in PATH.
	RunPath []string
	// RunEnv is the operator's --run-env names, copied from the
	// connector's environment when present there.
	RunEnv []string
	// Request is the request's env, in order.
	Request []Var
	// Secret is the secret's variable for how env or file; nil for
	// stdin.
	Secret *Var
}

// Env builds the process environment as KEY=VALUE strings: the minimal
// set copied from lookup when present, PATH and the temp variables set
// by the connector, the --run-env names, the request's env, then the
// secret's variable. Nothing else is inherited. lookup is os.LookupEnv
// in the connector. A later entry of the same name replaces an earlier
// one.
func Env(spec Spec, lookup func(string) (string, bool)) ([]string, error) {
	if len(spec.Request) > MaxRequestEnv {
		return nil, badRequest("env has %d variables, at most %d", len(spec.Request), MaxRequestEnv)
	}
	for _, v := range spec.Request {
		if err := checkName(v.Name); err != nil {
			return nil, err
		}
		if len(v.Value) > MaxEnvValueLen {
			return nil, badRequest("value of %s is longer than %d bytes", v.Name, MaxEnvValueLen)
		}
		if strings.IndexByte(v.Value, 0) >= 0 {
			return nil, badRequest("value of %s holds a NUL byte", v.Name)
		}
	}
	if spec.Secret != nil {
		if err := checkName(spec.Secret.Name); err != nil {
			return nil, err
		}
		if strings.IndexByte(spec.Secret.Value, 0) >= 0 {
			return nil, badRequest("value of %s holds a NUL byte", spec.Secret.Name)
		}
	}
	if err := CheckRunEnv(spec.RunEnv); err != nil {
		return nil, badRequest("%v", err)
	}
	if spec.Tmp == "" {
		return nil, badRequest("no tmp directory")
	}

	var out []Var
	set := func(name, value string) {
		for i := range out {
			if sameName(out[i].Name, name) {
				out[i].Value = value
				return
			}
		}
		out = append(out, Var{name, value})
	}
	for _, n := range minimalNames {
		if v, ok := lookup(n); ok {
			set(n, v)
		}
	}
	set("PATH", SearchPath(spec.RunPath))
	for _, n := range tempNames {
		set(n, spec.Tmp)
	}
	for _, n := range spec.RunEnv {
		if v, ok := lookup(n); ok {
			set(n, v)
		}
	}
	for _, v := range spec.Request {
		set(v.Name, v.Value)
	}
	if spec.Secret != nil {
		set(spec.Secret.Name, spec.Secret.Value)
	}
	env := make([]string, len(out))
	for i, v := range out {
		env[i] = v.Name + "=" + v.Value
	}
	return env, nil
}

// SearchPath returns the value of PATH for the process: the fixed search
// path, then the operator's directories.
func SearchPath(runPath []string) string {
	dirs := append(FixedPath(), runPath...)
	return strings.Join(dirs, string(os.PathListSeparator))
}

// CheckRunPaths checks the operator's --run-path values: at most 16,
// each an absolute path of an existing directory, with no path list
// separator in it.
func CheckRunPaths(paths []string) error {
	if len(paths) > MaxRunPathDirs {
		return fmt.Errorf("--run-path: %d directories, at most %d", len(paths), MaxRunPathDirs)
	}
	for _, p := range paths {
		if err := checkAbsDir(p); err != nil {
			return fmt.Errorf("--run-path %q: %w", p, err)
		}
	}
	return nil
}

// CheckRunEnv checks the operator's --run-env names: at most 32, each
// valid by the same rule as a request's env names.
func CheckRunEnv(names []string) error {
	if len(names) > MaxRunEnvNames {
		return fmt.Errorf("--run-env: %d names, at most %d", len(names), MaxRunEnvNames)
	}
	for _, n := range names {
		if err := checkName(n); err != nil {
			return fmt.Errorf("--run-env %q: not an allowed variable name", shorten(n))
		}
	}
	return nil
}

func checkAbsDir(p string) error {
	if p == "" || strings.IndexByte(p, 0) >= 0 {
		return errors.New("is empty or invalid")
	}
	if !filepath.IsAbs(p) {
		return errors.New("is not an absolute path")
	}
	if strings.ContainsRune(p, os.PathListSeparator) {
		return errors.New("holds a path list separator")
	}
	fi, err := os.Stat(p)
	if err != nil {
		return errors.New("does not exist")
	}
	if !fi.IsDir() {
		return errors.New("is not a directory")
	}
	return nil
}

// SubstituteSecretFile returns a copy of argv with each element that is
// exactly {secret_file} replaced by path.
func SubstituteSecretFile(argv []string, path string) []string {
	out := make([]string, len(argv))
	for i, a := range argv {
		if a == secretFileToken {
			a = path
		}
		out[i] = a
	}
	return out
}
