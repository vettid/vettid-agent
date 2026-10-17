//go:build !linux && !darwin && !windows

package state

import (
	"errors"
	"io"
	"os"
)

// The connector supports Linux, macOS and Windows (AGENT-PLAN §2 AG4).
// Elsewhere every operation fails, so that no state is kept without the
// owner-only checks and the lock.

var errUnsupported = errors.New("state: this operating system is not supported")

func mkdirOwnerOnly(string) error                                 { return errUnsupported }
func checkDir(string) error                                       { return errUnsupported }
func checkFile(*os.File) error                                    { return errUnsupported }
func openPrivate(string) (*os.File, error)                        { return nil, errUnsupported }
func openForOverwrite(string) (*os.File, error)                   { return nil, errUnsupported }
func createTemp(string, string, string) (*os.File, string, error) { return nil, "", errUnsupported }
func renameReplace(string, string) error                          { return errUnsupported }
func syncDir(string) error                                        { return errUnsupported }
func lockDir(string) (io.Closer, error)                           { return nil, errUnsupported }
