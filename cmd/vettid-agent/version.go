package main

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
)

// Set by scripts/build-release through -ldflags -X to
// "vettid-agent-release/<version>/<commit>": the release tag (or
// "untagged") and the full commit hash, in one string that
// scripts/check-release-binaries finds in the binary. Release builds use
// -buildvcs=false so that the binary does not depend on the state of a
// checkout; this stamp takes the place of the VCS stamp.
var releaseStamp string

// parseReleaseStamp splits releaseStamp; ok is false for an empty or
// malformed stamp, which is then ignored.
func parseReleaseStamp(stamp string) (version, commit string, ok bool) {
	parts := strings.Split(stamp, "/")
	if len(parts) != 3 || parts[0] != "vettid-agent-release" || parts[1] == "" || len(parts[2]) != 40 {
		return "", "", false
	}
	return parts[1], parts[2], true
}

// versionInfo is what `vettid-agent version` prints.
type versionInfo struct {
	Version   string // release tag, module version, or "(devel)" for a build from a checkout
	Commit    string // commit hash, or "unknown"
	Modified  bool   // the working tree had uncommitted changes
	GoVersion string // toolchain that built the binary
	Devstack  bool   // built with the devstack tag: never a release
}

// readVersion reads the binary's embedded build information.
func readVersion() versionInfo {
	bi, _ := debug.ReadBuildInfo() // nil when not ok
	v := versionFrom(bi)
	if version, commit, ok := parseReleaseStamp(releaseStamp); ok {
		v.Version, v.Commit = version, commit
	}
	return v
}

// versionFrom extracts versionInfo from build information; bi may be nil
// (a binary built without module support).
func versionFrom(bi *debug.BuildInfo) versionInfo {
	v := versionInfo{
		Version:   "(devel)",
		Commit:    "unknown",
		GoVersion: runtime.Version(),
	}
	if bi == nil {
		return v
	}
	if bi.Main.Version != "" {
		v.Version = bi.Main.Version
	}
	if bi.GoVersion != "" {
		v.GoVersion = bi.GoVersion
	}
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			if s.Value != "" {
				v.Commit = s.Value
			}
		case "vcs.modified":
			v.Modified = s.Value == "true"
		case "-tags":
			for _, tag := range strings.Split(s.Value, ",") {
				if tag == "devstack" {
					v.Devstack = true
				}
			}
		}
	}
	return v
}

func (v versionInfo) String() string {
	commit := v.Commit
	if v.Modified {
		commit += " (modified)"
	}
	s := fmt.Sprintf("vettid-agent %s\ncommit: %s\ngo: %s\n", v.Version, commit, v.GoVersion)
	if v.Devstack {
		s += "build: devstack (accepts a plain-HTTP relay on loopback; not a release build)\n"
	}
	return s
}
