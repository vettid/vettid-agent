package main

import (
	"bytes"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
)

func runArgs(args ...string) (code int, stdout, stderr string) {
	var out, errb bytes.Buffer
	code = run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestVersionPrintsVersionCommitAndGo(t *testing.T) {
	code, out, errOut := runArgs("version")
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	want := 3
	if readVersion().Devstack {
		want = 4 // the devstack line (go test -tags devstack)
	}
	if len(lines) != want {
		t.Fatalf("want %d lines, got %q", want, out)
	}
	if !strings.HasPrefix(lines[0], "vettid-agent ") || len(lines[0]) <= len("vettid-agent ") {
		t.Errorf("version line %q", lines[0])
	}
	if !strings.HasPrefix(lines[1], "commit: ") || len(lines[1]) <= len("commit: ") {
		t.Errorf("commit line %q", lines[1])
	}
	if lines[2] != "go: "+runtime.Version() {
		t.Errorf("go line %q, want %q", lines[2], "go: "+runtime.Version())
	}
	if errOut != "" {
		t.Errorf("unexpected stderr %q", errOut)
	}
}

func TestVersionRefusesArguments(t *testing.T) {
	if code, _, _ := runArgs("version", "extra"); code != 2 {
		t.Errorf("version extra: exit %d, want 2", code)
	}
	if code, _, _ := runArgs("version", "-nosuchflag"); code != 2 {
		t.Errorf("version -nosuchflag: exit %d, want 2", code)
	}
}

func TestVersionFrom(t *testing.T) {
	bi := &debug.BuildInfo{
		GoVersion: "go1.26.0",
		Main:      debug.Module{Path: "github.com/vettid/vettid-agent", Version: "v0.1.0"},
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "0123456789abcdef0123456789abcdef01234567"},
			{Key: "vcs.modified", Value: "true"},
		},
	}
	got := versionFrom(bi).String()
	want := "vettid-agent v0.1.0\ncommit: 0123456789abcdef0123456789abcdef01234567 (modified)\ngo: go1.26.0\n"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestVersionFromDevstackBuild(t *testing.T) {
	for _, tags := range []string{"devstack", "foo,devstack", "devstack,bar"} {
		bi := &debug.BuildInfo{
			GoVersion: "go1.26.9",
			Settings:  []debug.BuildSetting{{Key: "-tags", Value: tags}},
		}
		v := versionFrom(bi)
		if !v.Devstack {
			t.Errorf("-tags=%s: not reported as a devstack build", tags)
		}
		if !strings.HasSuffix(v.String(), "build: devstack (accepts a plain-HTTP relay on loopback; not a release build)\n") {
			t.Errorf("-tags=%s: output %q", tags, v.String())
		}
	}
	for _, tags := range []string{"", "devstackx", "nodevstack,foo"} {
		bi := &debug.BuildInfo{Settings: []debug.BuildSetting{{Key: "-tags", Value: tags}}}
		if v := versionFrom(bi); v.Devstack || strings.Contains(v.String(), "devstack") {
			t.Errorf("-tags=%q: reported as a devstack build: %q", tags, v.String())
		}
	}
}

func TestReleaseStampOverridesBuildInfo(t *testing.T) {
	old := releaseStamp
	t.Cleanup(func() { releaseStamp = old })
	releaseStamp = "vettid-agent-release/v0.1.0/0123456789abcdef0123456789abcdef01234567"
	v := readVersion()
	if v.Version != "v0.1.0" || v.Commit != "0123456789abcdef0123456789abcdef01234567" {
		t.Errorf("got %+v", v)
	}
	for _, bad := range []string{"", "v0.1.0", "vettid-agent-release/v0.1.0/0123", "other/v0.1.0/0123456789abcdef0123456789abcdef01234567",
		"vettid-agent-release//0123456789abcdef0123456789abcdef01234567", "vettid-agent-release/a/b/0123456789abcdef0123456789abcdef01234567"} {
		releaseStamp = bad
		if v := readVersion(); v.Version == "v0.1.0" || v.Commit == "0123456789abcdef0123456789abcdef01234567" {
			t.Errorf("stamp %q accepted: %+v", bad, v)
		}
	}
}

func TestVersionFromWithoutBuildInfo(t *testing.T) {
	got := versionFrom(nil)
	if got.Version != "(devel)" || got.Commit != "unknown" || got.GoVersion != runtime.Version() || got.Modified {
		t.Errorf("got %+v", got)
	}
	got = versionFrom(&debug.BuildInfo{})
	if got.Version != "(devel)" || got.Commit != "unknown" || got.GoVersion != runtime.Version() {
		t.Errorf("empty build info: got %+v", got)
	}
}

func TestPlannedCommandsNotYetAvailable(t *testing.T) {
	for _, name := range []string{"forget"} {
		code, out, errOut := runArgs(name)
		if code != 2 {
			t.Errorf("%s: exit %d, want 2", name, code)
		}
		if out != "" {
			t.Errorf("%s: wrote to stdout: %q", name, out)
		}
		if want := "vettid-agent " + name + ": not yet available\n"; errOut != want {
			t.Errorf("%s: stderr %q, want %q", name, errOut, want)
		}
	}
}

func TestUsageListsCommands(t *testing.T) {
	code, out, _ := runArgs("help")
	if code != 0 {
		t.Fatalf("help: exit %d", code)
	}
	for _, name := range []string{"forget"} {
		found := false
		for _, line := range strings.Split(out, "\n") {
			f := strings.Fields(line)
			if len(f) > 0 && f[0] == name {
				found = true
				if !strings.Contains(line, "not yet available") {
					t.Errorf("usage line for %s does not say not yet available: %q", name, line)
				}
			}
		}
		if !found {
			t.Errorf("usage does not list %s:\n%s", name, out)
		}
	}
	if !strings.Contains(out, "version") {
		t.Errorf("usage does not list version:\n%s", out)
	}
}

func TestNoArgumentsAndUnknownCommand(t *testing.T) {
	code, out, errOut := runArgs()
	if code != 2 || out != "" || !strings.Contains(errOut, "Usage:") {
		t.Errorf("no args: exit %d, stdout %q, stderr %q", code, out, errOut)
	}
	code, out, errOut = runArgs("nosuch")
	if code != 2 || out != "" || !strings.Contains(errOut, `unknown command "nosuch"`) {
		t.Errorf("unknown: exit %d, stdout %q, stderr %q", code, out, errOut)
	}
	for _, h := range []string{"-h", "--help", "-help"} {
		if code, out, _ := runArgs(h); code != 0 || !strings.Contains(out, "Usage:") {
			t.Errorf("%s: exit %d", h, code)
		}
	}
}
