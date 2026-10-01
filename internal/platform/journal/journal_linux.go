//go:build linux

package journal

import (
	"os/exec"
	"syscall"
)

func supervise(command *exec.Cmd) error {
	command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	return nil
}
