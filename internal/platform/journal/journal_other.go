//go:build !linux

package journal

import (
	"errors"
	"fmt"
	"os/exec"
	"runtime"
)

func supervise(*exec.Cmd) error {
	return fmt.Errorf("read the system journal on %s: %w", runtime.GOOS, errors.ErrUnsupported)
}

func send([]byte) error {
	return fmt.Errorf("write to the system journal on %s: %w", runtime.GOOS, errors.ErrUnsupported)
}
