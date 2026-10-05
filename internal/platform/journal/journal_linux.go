//go:build linux

package journal

import (
	"fmt"
	"net"
	"os/exec"
	"syscall"
	"time"
)

func supervise(command *exec.Cmd) error {
	command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	return nil
}

func send(payload []byte) error {
	connection, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: socket, Net: "unixgram"})
	if err != nil {
		return fmt.Errorf("reach journald: %w", err)
	}
	defer connection.Close()
	err = connection.SetWriteDeadline(time.Now().Add(stopping))
	if err == nil {
		_, err = connection.Write(payload)
	}
	if err != nil {
		return fmt.Errorf("write to journald: %w", err)
	}
	return nil
}
