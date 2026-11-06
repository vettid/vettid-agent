//go:build !windows && !linux && !darwin

package run

import "errors"

// On other systems no way to run exactly the bytes hashed is built, so no
// program is run.
type platProgram struct{}

// Prepare refuses every run here (run_failed).
func Prepare(path, _ string) (*Program, error) {
	return nil, runFailed("runs are not supported on this system")
}

// Close does nothing.
func (p *Program) Close() error { return nil }

// Start refuses every run here (run_failed).
func (p *Program) Start(StartSpec) (*Process, error) {
	return nil, runFailed("runs are not supported on this system")
}

type platProcess struct{}

func (*platProcess) wait() (int, error) { return -1, errors.New("not supported") }
func (*platProcess) kill() error        { return errors.New("not supported") }

func checkFormat([]byte) error { return nil }
