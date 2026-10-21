//go:build !windows

package runner

import (
	"os"
	"os/exec"
	"syscall"
)

func prepare(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func attach(*exec.Cmd) func() { return func() {} }

func interrupt(cmd *exec.Cmd) error {
	return cmd.Process.Signal(os.Interrupt)
}

func IsElevated() bool {
	return os.Geteuid() == 0
}
