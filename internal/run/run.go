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
// or TMP or a code-loading variable, and does not start with a loader
// prefix (LD_, DYLD_, ...; see loaderPrefixes). On Windows the forbidden
// checks ignore case.
func ValidName(name string) bool { return checkName(name) == nil }

func checkName(name string) error {
	if len(name) > maxNameLen || !nameRE.MatchString(name) {
		return badRequest("variable name %q is not allowed", shorten(name))
	}
	for _, p := range loaderPrefixes {
		if strings.HasPrefix(name, p) {
			return badRequest("variable name %q is not allowed", name)
		}
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

// loaderPrefixes and loaderNames: variables that make a program load or
// run other code (the dynamic loader's, and language runtimes' and tools'
// own). The phone doesn't show `env`, so a request can't set them, for the
// same reason as LD_ (AGENT-PLAN §4.9; the code-loading ones beyond LD_ and
// DYLD_ are the lead's ruling, 2026-11-05). Names are upper case, as the
// name rule requires. A list like this can't be complete; the whole GIT_
// family is refused because git reads many of them as commands. The same
// rule holds for --run-env, so an operator can't pass these through either.
var loaderPrefixes = []string{"LD_", "DYLD_", "GIT_", "COR_PROFILER", "CORECLR_", "DOTNET_"}

var loaderNames = []string{
	"NODE_OPTIONS", "NODE_PATH", "BASH_ENV", "ENV",
	"PERL5OPT", "PERL5LIB", "PERLLIB", "PERL5DB",
	"PYTHONSTARTUP", "PYTHONPATH", "PYTHONHOME", "PYTHONUSERBASE", "RUBYOPT", "RUBYLIB",
	"XDG_CONFIG_HOME", "GCONV_PATH", "AWS_CONFIG_FILE", "KUBECONFIG", "COMSPEC", "PSMODULEPATH", "SHELL",
	"JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS",
	"LESSOPEN", "PAGER", "EDITOR", "VISUAL", "SSH_ASKPASS", "SUDO_ASKPASS",
}

func forbiddenNames() []string {
	out := append([]string{}, minimalNames...)
	out = append(out, loaderNames...)
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
	for _, n := range copiedNames {
		if v, ok := lookup(n); ok {
			set(n, v)
		}
	}
	sys, err := systemVars()
	if err != nil {
		return nil, err
	}
	for _, v := range sys {
		set(v.Name, v.Value)
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
//
// It returns the directories with links resolved: those, not the values as
// given, are what Resolve and the run's PATH use, so a link repointed after
// the check changes nothing.
func CheckRunPaths(paths []string) ([]string, error) {
	if len(paths) > MaxRunPathDirs {
		return nil, fmt.Errorf("--run-path: %d directories, at most %d", len(paths), MaxRunPathDirs)
	}
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		if err := checkAbsDir(p); err != nil {
			return nil, fmt.Errorf("--run-path %q: %w", p, err)
		}
		real, err := checkNotWritable(p)
		if err != nil {
			return nil, fmt.Errorf("--run-path %q: %w", p, err)
		}
		out = append(out, real)
	}
	return out, nil
}

// checkNotWritable refuses a --run-path directory that the connector's own
// user could change, through the directory or any of its parents up to the
// root (owner decision, 2026-11-05): an agent running as that user could
// otherwise swap a bound program and receive the secret without a prompt.
// Links are resolved first, so the real directories are the ones checked.
func checkNotWritable(p string) (string, error) {
	real, err := filepath.EvalSymlinks(p)
	if err != nil {
		return "", fmt.Errorf("can't be resolved: %w", err)
	}
	if err := unchangeable(real, 1); err != nil {
		return "", err
	}
	return real, nil
}

// unchangeable checks a resolved path (links followed) and every directory
// above it, up to the root: none may be changeable by the connector's own
// user (owner, write access, ACLs, reparse points; see writable). Owner
// decisions of 2026-11-05: for --run-path directories, and at every run for
// the program itself and the folders above it, on the fixed path too.
//
// The first own entries (the --run-path directory: 1; a program and its
// folder: 2) must refuse every changing right, adding files included: a
// file added to a program's own folder is loaded by it (a DLL found in the
// application's folder first, on Windows). Folders above those need only
// refuse what replaces them (renaming, deleting, changing access).
func unchangeable(real string, own int) error {
	for p, i := real, 0; ; p, i = filepath.Dir(p), i+1 {
		parent := i >= own
		w, err := writable(p, parent)
		if err != nil {
			return fmt.Errorf("%s %w", p, err)
		}
		if w {
			if i > 0 {
				return fmt.Errorf("its folder %s can be changed by this connector's user, or by others; it must be one only an administrator can change", p)
			}
			return fmt.Errorf("%s can be changed by this connector's user, or by others; it must be one only an administrator can change", p)
		}
		if filepath.Dir(p) == p {
			return nil
		}
	}
}

// programUnchangeable is unchangeable for a resolved program: the file and
// its own folder get the full rule.
func programUnchangeable(real string) error { return unchangeable(real, 2) }

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
