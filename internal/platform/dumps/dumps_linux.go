//go:build linux

package dumps

import (
	"errors"
	"fmt"
	"syscall"
)

const (
	getDumpable = 3
	setDumpable = 4
)

func withhold() error {
	if err := syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{}); err != nil {
		return fmt.Errorf("leave the kernel no core dump of the agent to write: %w", err)
	}
	if _, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, setDumpable, 0, 0); errno != 0 {
		return fmt.Errorf("keep the agent's memory to itself: %w", errno)
	}
	return withheld()
}

func withheld() error {
	var allowed syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_CORE, &allowed); err != nil {
		return fmt.Errorf("read how large a core dump of the agent may be: %w", err)
	}
	if allowed.Cur != 0 || allowed.Max != 0 {
		return fmt.Errorf("the kernel writes a core dump of the agent of up to %d bytes", allowed.Cur)
	}
	readable, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, getDumpable, 0, 0)
	if errno != 0 {
		return fmt.Errorf("read whether the agent's memory is its own: %w", errno)
	}
	if readable != 0 {
		return errors.New("the agent's memory is within reach of the other processes of its account")
	}
	return nil
}
