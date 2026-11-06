//go:build linux || darwin

package run

import (
	"os"
	"testing"
)

// What runs is what was hashed: after Prepare, the file at the path is
// replaced, in place or by renaming it away and putting another there,
// with a program that behaves differently. The start still runs the
// original, which prints its arguments; the replacement would print
// "replaced".
func TestStartRunsTheHashedBytes(t *testing.T) {
	lookupOnly(t)
	replacement := []byte("#!/bin/sh\necho replaced\n")
	for name, replace := range map[string]func(t *testing.T, path string){
		"overwritten in place": func(t *testing.T, path string) {
			if err := os.WriteFile(path, replacement, 0o755); err != nil {
				t.Fatal(err)
			}
		},
		"renamed and replaced": func(t *testing.T, path string) {
			if err := os.Rename(path, path+".old"); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, replacement, 0o755); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			exe := helperCopy(t, t.TempDir(), "helper")
			p := prepare(t, exe)
			replace(t, exe)
			spec := helperSpec(t, exe, "args")
			spec.Argv = []string{exe, "original"}
			code, out := runOutput(t, p, spec)
			if code != 0 || out != "\"original\"\n" {
				t.Fatalf("exit %d, output %q: not the hashed program", code, out)
			}
		})
	}
}
