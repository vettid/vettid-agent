//go:build windows

package run

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// A Windows batch file (.cmd or .bat) runs through System32's cmd.exe
// (AGENT-PLAN §4.9; owner decision b, GC #14880): cmd.exe /d /v:off /s /c
// with the batch file and each argument in double quotes. cmd.exe reads
// the command line again, and the batch file may read an argument again
// (%~1 strips our quotes; %* puts the arguments on a line it parses), so
// anything cmd.exe would take for a command is refused before anything
// starts, fail closed:
//   - % expands inside quotes too;
//   - & | < > run another command or redirect once %~1 strips the quotes;
//   - ( and ) end a parenthesized block early;
//   - ^ is an escape that %~1 drops, which changes the argument;
//   - ! expands where the batch turns on delayed expansion;
//   - " can't be escaped inside cmd.exe's quotes;
//   - C0 controls and DEL (a line break ends cmd.exe's line);
//   - any character outside ASCII: a program the batch starts may convert
//     it to its code page with a best-fit mapping that turns lookalikes
//     (U+FF02, the yen sign) into " or \ ;
//   - an argument that ends in a backslash: a program that reads its
//     command line by the C runtime's rules takes \" for a quote, so the
//     argument would run into the next.
//
// The batch file's path and the working folder follow the same rule (the
// path is on the command line; cmd.exe reads the folder for %cd%), and so
// does the value of every environment variable the agent controls:
// cmd.exe expands %NAME% before it parses a line, so a value holding
// " & is syntax wherever the batch uses it. A variable named as one of
// cmd.exe's own dynamic variables (%CD%, %ERRORLEVEL%, ...) is refused:
// it would replace what the batch reads there.
//
// The rule protects a batch file that quotes what it is given ("%~1",
// "%NAME%") or passes %* on, as npm's shims do. A batch that uses %~1
// bare, as in `if %~1==x`, can still be steered by spaces, which are
// allowed: that is the batch file's own bug.

// CodeArgumentNotAllowed is a batch run refused for an argument, its path
// or its working folder.
const CodeArgumentNotAllowed = "argument_not_allowed"

// ErrArgumentNotAllowed is a sentinel for errors.Is.
var ErrArgumentNotAllowed error = &Error{Code: CodeArgumentNotAllowed}

// TextArgumentNotAllowed is the refusal shown to the agent. (NEW text)
const TextArgumentNotAllowed = "This program is a Windows batch file (.cmd or .bat), which runs through cmd.exe. " +
	"Its arguments, the environment variables the request sets, its path and its working folder can't hold any of " +
	"% & | < > ^ ( ) ! \" or a control character, or any character outside ASCII " +
	"(so a file name in another alphabet can't be passed to it), and an argument or variable can't end in a backslash: " +
	"cmd.exe would read them as commands. A variable can't be named as one cmd.exe sets itself, such as CD or ERRORLEVEL. " +
	"Pass the value in a file instead."

// batchMeta are the ASCII characters cmd.exe reads as commands.
const batchMeta = `%&|<>^()!"`

// maxBatchCmdLine is cmd.exe's own limit on a command line, in
// characters (8,191), below CreateProcess's.
const maxBatchCmdLine = 8191

// isBatch reports whether path names a batch file.
func isBatch(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".cmd", ".bat":
		return true
	}
	return false
}

// batchText checks s, which names what it is ("argument 2", "the
// program's path", "the working folder"), and says which kind of
// character it holds; never the value itself.
func batchText(s, what string) error {
	for _, r := range s {
		switch {
		case r > 0x7e:
			if r == 0x7f {
				return argNotAllowed("%s holds a control character", what)
			}
			return argNotAllowed("%s holds a character outside ASCII", what)
		case r < 0x20:
			return argNotAllowed("%s holds a control character", what)
		case strings.ContainsRune(batchMeta, r):
			return argNotAllowed("%s holds %c", what, r)
		}
	}
	return nil
}

// batchValue is batchText for a value cmd.exe puts between quotes it
// doesn't control: it can't end in a backslash either.
func batchValue(s, what string) error {
	if err := batchText(s, what); err != nil {
		return err
	}
	if strings.HasSuffix(s, `\`) {
		return argNotAllowed("%s ends in a backslash", what)
	}
	return nil
}

// cmdDynamicNames are the variables cmd.exe sets itself; an environment
// variable of the same name replaces what a batch reads there.
var cmdDynamicNames = []string{"CD", "DATE", "TIME", "RANDOM", "ERRORLEVEL", "CMDEXTVERSION",
	"CMDCMDLINE", "HIGHESTNUMANODENUMBER", "__CD__", "__APPDIR__"}

// connectorSet reports whether the connector sets name itself from the
// system or the operator's configuration (the minimal set, PATH, the temp
// variables, NoDefaultCurrentDirectoryInExePath): its value is not the
// agent's.
func connectorSet(name string) bool {
	for _, set := range [][]string{minimalNames, tempNames, {"PATH", noCwdExeName}} {
		for _, n := range set {
			if sameName(n, name) {
				return true
			}
		}
	}
	return false
}

// checkBatch checks a batch run's path, working folder, arguments and
// environment. Every variable's value is checked except the connector's
// own (connectorSet) and those named in trusted (the secret's variable,
// the operator's --run-env names): fail closed, a variable not known to
// be trusted is the agent's. A refusal names the variable, never its
// value.
func checkBatch(path, dir string, args, env, trusted []string) error {
	if err := batchText(path, "the program's path"); err != nil {
		return err
	}
	if err := batchText(dir, "the working folder"); err != nil {
		return err
	}
	for i, a := range args {
		if err := batchValue(a, fmt.Sprintf("argument %d", i+1)); err != nil {
			return err
		}
	}
	for _, kv := range env {
		name, value, _ := strings.Cut(kv, "=")
		for _, d := range cmdDynamicNames {
			if sameName(d, name) {
				return argNotAllowed("the environment variable %s is one cmd.exe sets itself", name)
			}
		}
		if connectorSet(name) || containsName(trusted, name) {
			continue
		}
		if err := batchValue(value, "the environment variable "+name); err != nil {
			return err
		}
	}
	return nil
}

func containsName(names []string, name string) bool {
	for _, n := range names {
		if sameName(n, name) {
			return true
		}
	}
	return false
}

func argNotAllowed(format string, a ...any) error {
	return &Error{Code: CodeArgumentNotAllowed, Msg: TextArgumentNotAllowed + " (" + fmt.Sprintf(format, a...) + ")"}
}

// batchCmdLine is cmd.exe's command line for a batch run: /d (no AutoRun
// commands from the registry), /v:off (no ! expansion, whatever the
// registry says), /s /c and the whole command in one more pair of quotes,
// which /s strips. Command extensions stay on: batch files such as npm's
// shims need %~dp0 and setlocal. The parts were checked by checkBatch.
func batchCmdLine(cmdExe, bat string, args []string) string {
	var b strings.Builder
	b.WriteString(`"` + cmdExe + `" /d /v:off /s /c ""` + bat + `"`)
	for _, a := range args {
		b.WriteString(` "` + a + `"`)
	}
	b.WriteString(`"`)
	return b.String()
}

// cmdExePath is System32's cmd.exe, from the system's own directory
// (GetSystemDirectory), never from an inherited ComSpec.
func cmdExePath() (string, error) {
	dir, err := windows.GetSystemDirectory()
	if err != nil || dir == "" || !filepath.IsAbs(dir) {
		return "", runFailed("the system directory can't be found")
	}
	return filepath.Join(filepath.Clean(dir), "cmd.exe"), nil
}

// checkBatchFormat accepts a batch file's first bytes: anything but a
// Windows program (an MZ header) named as one. (chosen; not in the spec)
func checkBatchFormat(head []byte) error {
	if len(head) >= 2 && head[0] == 'M' && head[1] == 'Z' {
		return fmt.Errorf("is a Windows program named as a batch file")
	}
	return nil
}

// shimFor: an absolute path without an extension that names a regular
// file which is not a Windows program, with <path>.cmd beside it, is run
// as that .cmd: npm installs a sh script and a .cmd of the same name. Only
// .cmd is tried; no .bat, .ps1 or PATHEXT walk. (AGENT-PLAN §4.9)
func shimFor(path string) (string, bool) {
	if filepath.Ext(path) != "" {
		return "", false
	}
	fi, err := os.Stat(path)
	if err != nil || !fi.Mode().IsRegular() {
		return "", false
	}
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	var head [2]byte
	n, _ := io.ReadFull(f, head[:])
	f.Close()
	if n == 2 && head[0] == 'M' && head[1] == 'Z' {
		return "", false
	}
	cmd := path + ".cmd"
	if fi, err := os.Stat(cmd); err != nil || !fi.Mode().IsRegular() {
		return "", false
	}
	return cmd, true
}
