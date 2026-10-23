//go:build !windows

package runner

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

func prepare(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

var errNoHandoff = errors.New("передача sing-box между процессами есть только в Windows")

type osProcess struct {
	proc *os.Process
}

func attach(cmd *exec.Cmd) *osProcess { return &osProcess{proc: cmd.Process} }

func adopt(Handoff, string) (*osProcess, error) { return nil, errNoHandoff }

func HoldJob(string) (func(), error) { return nil, errNoHandoff }

func (o *osProcess) handoff() (Handoff, error) { return Handoff{}, errNoHandoff }

func (o *osProcess) wait() (uint32, error) { return 0, errNoHandoff }

func (o *osProcess) interrupt() error { return o.proc.Signal(os.Interrupt) }

func (o *osProcess) kill() error { return o.proc.Kill() }

func (o *osProcess) close() {}

func IsElevated() bool {
	return os.Geteuid() == 0
}

const isWindows = false

func openLocked(path string) (*os.File, error) {
	return os.Open(path)
}
