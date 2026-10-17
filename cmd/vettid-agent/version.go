package main

import (
	"fmt"
	"runtime"
	"runtime/debug"
)

// versionInfo is what `vettid-agent version` prints.
type versionInfo struct {
	Version   string // module version, or "(devel)" for a build from a checkout
	Commit    string // VCS revision, or "unknown"
	Modified  bool   // the working tree had uncommitted changes
	GoVersion string // toolchain that built the binary
}

// readVersion reads the binary's embedded build information.
func readVersion() versionInfo {
	bi, _ := debug.ReadBuildInfo() // nil when not ok
	return versionFrom(bi)
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
		}
	}
	return v
}

func (v versionInfo) String() string {
	commit := v.Commit
	if v.Modified {
		commit += " (modified)"
	}
	return fmt.Sprintf("vettid-agent %s\ncommit: %s\ngo: %s\n", v.Version, commit, v.GoVersion)
}
