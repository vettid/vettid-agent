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
	CodeEnvNotAllowed   = "env_not_allowed"
	CodeRunFailed       = "run_failed"
)

// Error carries a wire code and a message that holds no secret value.
// Names is the body of env_not_allowed ({names}).
type Error struct {
	Code  string
	Msg   string
	Names []string
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
	ErrEnvNotAllowed   error = &Error{Code: CodeEnvNotAllowed}
	ErrRunFailed       error = &Error{Code: CodeRunFailed}
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

func runFailed(format string, a ...any) error {
	return &Error{Code: CodeRunFailed, Msg: fmt.Sprintf(format, a...)}
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

// ValidName reports whether name may be used for a request env variable
// or the secret's variable: it passes the base rule (checkBaseName) and is
// none of the variables that make a program load other code or send its
// traffic elsewhere (loaderPrefixes, loaderNames). On Windows the
// forbidden checks ignore case.
func ValidName(name string) bool { return checkName(name) == nil }

func checkName(name string) error {
	if err := checkBaseName(name); err != nil {
		return err
	}
	for _, p := range loaderPrefixes {
		if strings.HasPrefix(name, p) {
			return badRequest("variable name %q is not allowed", name)
		}
	}
	for _, f := range append(loaderNames, platformLoaderNames...) {
		if sameName(f, name) {
			return badRequest("variable name %q is not allowed", name)
		}
	}
	return nil
}

// checkBaseName is the name rule of AGENT-PLAN §4.9 alone: it matches
// ^[A-Z_][A-Z0-9_]{0,63}$, is not in the minimal set, PATH, TMPDIR, TEMP
// or TMP, and does not start with LD_ or DYLD_. The operator's --run-env
// names get this rule only, not the longer lists (owner decision,
// 2026-11-05).
func checkBaseName(name string) error {
	if len(name) > maxNameLen || !nameRE.MatchString(name) {
		return badRequest("variable name %q is not allowed", shorten(name))
	}
	for _, p := range []string{"LD_", "DYLD_"} {
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
// own), or send its traffic elsewhere or make it trust another
// certificate. A request can't set them, even when the item's binding
// lists them: a backstop under that allowlist, since a list like this
// can't be complete (VAULT-MESSAGING §10.11; owner decisions,
// 2026-11-05). Names are upper case, as the name rule requires. The whole
// GIT_ family is refused because git reads many of them as commands. The
// operator's --run-env names are not checked against these lists (owner
// decision, 2026-11-05).
//
// The names and prefixes marked VAULT-MESSAGING 0.86.4 below came in with
// that erratum; they too apply to the request's env (listed or not) and
// not to --run-env.
var loaderPrefixes = []string{"LD_", "DYLD_", "GIT_", "COR_PROFILER", "CORECLR_", "DOTNET_",
	// VAULT-MESSAGING 0.86.4 §10.11.
	"LUA_INIT_", "NPM_CONFIG_", "PIP_",
}

var loaderNames = []string{
	"NODE_OPTIONS", "NODE_PATH", "BASH_ENV", "ENV",
	"PERL5OPT", "PERL5LIB", "PERLLIB", "PERL5DB",
	"PYTHONSTARTUP", "PYTHONPATH", "PYTHONHOME", "PYTHONUSERBASE", "RUBYOPT", "RUBYLIB",
	"XDG_CONFIG_HOME", "GCONV_PATH", "AWS_CONFIG_FILE", "KUBECONFIG", "COMSPEC", "PSMODULEPATH", "SHELL",
	"JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS",
	"LESSOPEN", "PAGER", "EDITOR", "VISUAL", "SSH_ASKPASS", "SUDO_ASKPASS",
	"GOFLAGS", "RUSTC_WRAPPER",
	// Names that send a program's traffic elsewhere or make it trust
	// another certificate.
	"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "SSL_CERT_FILE", "SSL_CERT_DIR",
	"NODE_EXTRA_CA_CERTS", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE",
	// VAULT-MESSAGING 0.86.4 §10.11: OpenSSL's configuration and modules,
	// its key log, more configuration and data folders, Electron run as
	// Node, and other runtimes' and editors' start-up code.
	"OPENSSL_CONF", "OPENSSL_ENGINES", "OPENSSL_MODULES", "SSLKEYLOGFILE",
	"XDG_CONFIG_DIRS", "XDG_DATA_HOME", "XDG_DATA_DIRS", "ELECTRON_RUN_AS_NODE",
	"PYTHONWARNINGS", "LUA_INIT", "VIMINIT", "EXINIT", "CLASSPATH",
	// Windows's compatibility layer, which can make a program load shims,
	// and the folders Windows programs find their own files in: refused on
	// every system, so the vault needs no knowledge of the connector's
	// (VAULT-MESSAGING 0.86.4 §10.11).
	"__COMPAT_LAYER", "PROGRAMFILES", "COMMONPROGRAMFILES", "PROGRAMDATA",
}

func forbiddenNames() []string {
	out := append([]string{}, minimalNames...)
	return append(out, "PATH", "TMPDIR", "TEMP", "TMP")
}

// UnlistedEnv returns the names of the request's env that the bound
// program's entry does not list (the catalog's `env`; VAULT-MESSAGING
// §10.11, AGENT-PLAN §4.9 "An allowlist for the request's env"), each
// once, in the request's order. With no listed names (an unbound item, or
// an entry with an empty list) every name is unlisted.
func UnlistedEnv(listed []string, request []Var) []string {
	var out []string
	for _, v := range request {
		if !contains(listed, v.Name) && !contains(out, v.Name) {
			out = append(out, v.Name)
		}
	}
	return out
}

// CheckEnvAllowed is the connector's check before it sends item.run, in
// the vault's order: the request's env as Env checks it first (the count,
// each value's length and NUL bytes, and the name rule, where the
// code-loading names are refused even when listed: bad_request), then
// the allowlist (env_not_allowed, with the unlisted names as {names}).
// Names are not values: they may be shown and logged.
func CheckEnvAllowed(listed []string, request []Var) error {
	if err := checkRequestEnv(request); err != nil {
		return err
	}
	if names := UnlistedEnv(listed, request); len(names) > 0 {
		return &Error{Code: CodeEnvNotAllowed, Names: names,
			Msg: "the program's binding does not allow the variables " + strings.Join(names, ", ")}
	}
	return nil
}

// checkRequestEnv checks the request's env: at most MaxRequestEnv
// variables, each name by the rule, each value at most MaxEnvValueLen
// bytes with no NUL byte (bad_request).
func checkRequestEnv(request []Var) error {
	if len(request) > MaxRequestEnv {
		return badRequest("env has %d variables, at most %d", len(request), MaxRequestEnv)
	}
	for _, v := range request {
		if err := checkName(v.Name); err != nil {
			return err
		}
		if len(v.Value) > MaxEnvValueLen {
			return badRequest("value of %s is longer than %d bytes", v.Name, MaxEnvValueLen)
		}
		if strings.IndexByte(v.Value, 0) >= 0 {
			return badRequest("value of %s holds a NUL byte", v.Name)
		}
	}
	return nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
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
	// Listed is the bound program's env allowlist, the catalog entry's
	// `env`; empty for an unbound item. Env refuses a request name not
	// in it (env_not_allowed), as CheckEnvAllowed does.
	Listed []string
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
// one. The request's env is checked as CheckEnvAllowed checks it, against
// spec.Listed, so no caller can build a run's environment past the
// allowlist.
func Env(spec Spec, lookup func(string) (string, bool)) ([]string, error) {
	if err := CheckEnvAllowed(spec.Listed, spec.Request); err != nil {
		return nil, err
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
		w, err := writableAt(p, parent)
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

// writableAt is writable, replaced by tests of the levels.
var writableAt = writable

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
		if err := checkBaseName(n); err != nil {
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
