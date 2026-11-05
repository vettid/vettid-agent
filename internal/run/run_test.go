package run

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// platform-specific expected minimal set, written out here and not taken
// from the implementation.
func wantMinimal() []string {
	if runtime.GOOS == "windows" {
		return []string{"SystemRoot", "SystemDrive", "windir", "PATHEXT", "USERPROFILE",
			"USERNAME", "HOMEDRIVE", "HOMEPATH", "APPDATA", "LOCALAPPDATA"}
	}
	return []string{"HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "LC_CTYPE", "TZ"}
}

func wantTemp() []string {
	if runtime.GOOS == "windows" {
		return []string{"TEMP", "TMP"}
	}
	return []string{"TMPDIR"}
}

func mapLookup(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func envMap(t *testing.T, env []string) map[string]string {
	t.Helper()
	m := map[string]string{}
	for _, e := range env {
		k, v, ok := strings.Cut(e, "=")
		if !ok {
			t.Fatalf("malformed entry %q", e)
		}
		if _, dup := m[k]; dup {
			t.Fatalf("duplicate %s", k)
		}
		m[k] = v
	}
	return m
}

func TestEnvExactSet(t *testing.T) {
	tmp := t.TempDir()
	rp := t.TempDir()
	connector := map[string]string{
		"HTTP_PROXY": "decoy", "AWS_SECRET_ACCESS_KEY": "decoy", "LD_PRELOAD": "decoy",
		"MCP_TOKEN": "decoy", "OPERATOR_ALLOWED": "op-value", "OPERATOR_ABSENT_OK": "",
	}
	delete(connector, "OPERATOR_ABSENT_OK")
	for _, n := range wantMinimal() {
		connector[n] = "min-" + n
	}
	spec := Spec{
		Tmp:     tmp,
		RunPath: []string{rp},
		RunEnv:  []string{"OPERATOR_ALLOWED", "OPERATOR_MISSING"},
		Request: []Var{{"REQ_ONE", "1"}, {"REQ_TWO", "two"}},
		Secret:  &Var{"THE_SECRET", "s"},
	}
	env, err := Env(spec, mapLookup(connector))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"PATH":             SearchPath([]string{rp}),
		"OPERATOR_ALLOWED": "op-value",
		"REQ_ONE":          "1", "REQ_TWO": "two", "THE_SECRET": "s",
	}
	for _, n := range wantMinimal() {
		want[n] = "min-" + n
	}
	for _, n := range wantTemp() {
		want[n] = tmp
	}
	got := envMap(t, env)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("environment\n got %v\nwant %v", got, want)
	}
	if !strings.HasSuffix(got["PATH"], string(os.PathListSeparator)+rp) {
		t.Errorf("PATH %q does not end with the run-path directory", got["PATH"])
	}
	// Order: minimal, PATH and temp, run-env, request, secret.
	idx := func(prefix string) int {
		for i, e := range env {
			if strings.HasPrefix(e, prefix+"=") {
				return i
			}
		}
		return -1
	}
	order := []string{wantMinimal()[0], "PATH", wantTemp()[0], "OPERATOR_ALLOWED", "REQ_ONE", "REQ_TWO", "THE_SECRET"}
	for i := 1; i < len(order); i++ {
		if idx(order[i-1]) >= idx(order[i]) {
			t.Errorf("%s should come before %s in %v", order[i-1], order[i], env)
		}
	}
}

func TestEnvNothingInherited(t *testing.T) {
	t.Setenv("VETTID_DECOY_VAR", "decoy")
	t.Setenv("HTTPS_PROXY", "decoy")
	env, err := Env(Spec{Tmp: t.TempDir()}, os.LookupEnv)
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{"PATH": true}
	for _, n := range append(wantMinimal(), wantTemp()...) {
		allowed[strings.ToUpper(n)] = true
	}
	for k := range envMap(t, env) {
		if !allowed[strings.ToUpper(k)] {
			t.Errorf("unexpected variable %s", k)
		}
	}
}

func TestEnvRefusals(t *testing.T) {
	long := strings.Repeat("A", 65)
	cases := []struct {
		name string
		v    Var
	}{
		{"loader", Var{"LD_PRELOAD", "x"}},
		{"loader prefix", Var{"LD_LIBRARY_PATH", "x"}},
		{"dyld", Var{"DYLD_INSERT_LIBRARIES", "x"}},
		{"path", Var{"PATH", "x"}},
		{"tmpdir", Var{"TMPDIR", "x"}},
		{"temp", Var{"TEMP", "x"}},
		{"tmp", Var{"TMP", "x"}},
		{"lower", Var{"lower", "x"}},
		{"digit first", Var{"1A", "x"}},
		{"dash", Var{"A-B", "x"}},
		{"empty", Var{"", "x"}},
		{"too long", Var{long, "x"}},
		{"newline", Var{"A\n", "x"}},
		{"value too long", Var{"OK_NAME", strings.Repeat("v", MaxEnvValueLen+1)}},
		{"value NUL", Var{"OK_NAME", "a\x00b"}},
	}
	for _, n := range wantMinimal() {
		cases = append(cases, struct {
			name string
			v    Var
		}{"minimal " + n, Var{strings.ToUpper(n), "x"}})
	}
	if runtime.GOOS != "windows" {
		// Case-sensitive there: HOME is minimal, other spellings are
		// refused only by the name rule.
		cases = append(cases, struct {
			name string
			v    Var
		}{"minimal HOME", Var{"HOME", "x"}})
	}
	for _, c := range cases {
		for _, secret := range []bool{false, true} {
			if secret && c.name == "value too long" {
				continue // the 4096-byte limit is for the request's env
			}
			spec := Spec{Tmp: t.TempDir()}
			if secret {
				spec.Secret = &c.v
			} else {
				spec.Request = []Var{c.v}
			}
			_, err := Env(spec, mapLookup(nil))
			if !errors.Is(err, ErrBadRequest) || Code(err) != CodeBadRequest {
				t.Errorf("%s (secret=%v): err = %v, want bad_request", c.name, secret, err)
			}
		}
	}
	// Right at the limits.
	ok := Spec{Tmp: t.TempDir(), Request: []Var{{strings.Repeat("A", 64), strings.Repeat("v", MaxEnvValueLen)}}}
	if _, err := Env(ok, mapLookup(nil)); err != nil {
		t.Errorf("limits: %v", err)
	}
	many := Spec{Tmp: t.TempDir()}
	for i := 0; i <= MaxRequestEnv; i++ {
		many.Request = append(many.Request, Var{"V" + string(rune('A'+i%26)) + string(rune('A'+i/26)), "x"})
	}
	if _, err := Env(many, mapLookup(nil)); !errors.Is(err, ErrBadRequest) {
		t.Errorf("33 variables: %v", err)
	}
	many.Request = many.Request[:MaxRequestEnv]
	if _, err := Env(many, mapLookup(nil)); err != nil {
		t.Errorf("32 variables: %v", err)
	}
	// A bad --run-env name is refused as well.
	if _, err := Env(Spec{Tmp: t.TempDir(), RunEnv: []string{"LD_PRELOAD"}}, mapLookup(nil)); !errors.Is(err, ErrBadRequest) {
		t.Errorf("run-env LD_PRELOAD: %v", err)
	}
}

func TestEnvWindowsForbiddenIgnoresCase(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows names are case-insensitive")
	}
	// The name rule needs capitals, so the case-insensitive match shows
	// for names that differ from the minimal set only in case.
	for _, n := range []string{"SYSTEMROOT", "WINDIR", "APPDATA", "USERPROFILE", "TEMP", "TMP", "PATH", "PATHEXT"} {
		if ValidName(n) {
			t.Errorf("%s accepted", n)
		}
	}
	for _, n := range []string{"temp", "Temp", "path"} {
		if ValidName(n) {
			t.Errorf("%s accepted", n)
		}
	}
	if !ValidName("MY_VAR") {
		t.Error("MY_VAR refused")
	}
}

func TestEnvLaterReplacesEarlier(t *testing.T) {
	spec := Spec{
		Tmp:     t.TempDir(),
		RunEnv:  []string{"SHARED"},
		Request: []Var{{"SHARED", "from-request"}},
		Secret:  &Var{"SHARED", "from-secret"},
	}
	env, err := Env(spec, mapLookup(map[string]string{"SHARED": "from-operator"}))
	if err != nil {
		t.Fatal(err)
	}
	if got := envMap(t, env)["SHARED"]; got != "from-secret" {
		t.Errorf("SHARED = %q", got)
	}
}

func TestSubstituteSecretFile(t *testing.T) {
	in := []string{"prog", "--key={secret_file}", "{secret_file}", "{secret_file} ", "{SECRET_FILE}", "{secret_file}"}
	got := SubstituteSecretFile(in, "/p/s")
	want := []string{"prog", "--key={secret_file}", "/p/s", "{secret_file} ", "{SECRET_FILE}", "/p/s"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %q want %q", got, want)
	}
	if in[2] != "{secret_file}" {
		t.Error("input modified")
	}
}

// systemDir is a directory the test's user can't change: what a good
// --run-path looks like.
func systemDir(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("SystemRoot"), "System32")
	}
	if os.Geteuid() == 0 {
		t.Skip("as root every directory is writable")
	}
	return "/usr/bin"
}

func TestCheckRunPaths(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "f")
	os.WriteFile(file, nil, 0o600)
	good := systemDir(t)
	if err := CheckRunPaths(nil); err != nil {
		t.Errorf("none: %v", err)
	}
	if err := CheckRunPaths([]string{good}); err != nil {
		t.Errorf("good: %v", err)
	}
	bad := map[string][]string{
		"relative":    {"rel/dir"},
		"dot":         {"."},
		"missing":     {filepath.Join(dir, "nope")},
		"file":        {file},
		"empty":       {""},
		"separator":   {dir + string(os.PathListSeparator) + dir},
		"one bad two": {dir, "rel"},
	}
	for name, p := range bad {
		if err := CheckRunPaths(p); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	sixteen := make([]string, MaxRunPathDirs)
	for i := range sixteen {
		sixteen[i] = good
	}
	if err := CheckRunPaths(sixteen); err != nil {
		t.Errorf("16: %v", err)
	}
	if err := CheckRunPaths(append(sixteen, good)); err == nil {
		t.Error("17 accepted")
	}
}

func TestCheckRunEnv(t *testing.T) {
	if err := CheckRunEnv([]string{"MY_VAR", "_X", "A1"}); err != nil {
		t.Errorf("good: %v", err)
	}
	for _, bad := range []string{"lower", "LD_PRELOAD", "PATH", "TMP", "TEMP", "TMPDIR", "1X", "A-B", "", "DYLD_X"} {
		if err := CheckRunEnv([]string{"OK", bad}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	names := make([]string, 0, 33)
	for i := 0; i < MaxRunEnvNames; i++ {
		names = append(names, "V"+string(rune('A'+i%26))+string(rune('A'+i/26)))
	}
	if err := CheckRunEnv(names); err != nil {
		t.Errorf("32: %v", err)
	}
	if err := CheckRunEnv(append(names, "EXTRA")); err == nil {
		t.Error("33 accepted")
	}
	sort.Strings(names)
}

// Owner decision 2026-11-05: a --run-path the connector's own user can
// change (the directory, or a parent) is refused, with the reason.
func TestCheckRunPathsRefusesWritable(t *testing.T) {
	_ = systemDir(t) // skips as root
	own := t.TempDir() // the test user's own: writable
	err := CheckRunPaths([]string{own})
	if err == nil || !strings.Contains(err.Error(), "can be changed by this connector's user") {
		t.Fatalf("own directory: %v", err)
	}
	// A directory the user can't write, under one it can: the parent counts.
	sub := filepath.Join(own, "locked")
	if err := os.Mkdir(sub, 0o555); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		err = CheckRunPaths([]string{sub})
		if err == nil || !strings.Contains(err.Error(), "its parent") {
			t.Fatalf("writable parent: %v", err)
		}
	}
}
