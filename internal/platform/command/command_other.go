//go:build !linux

package command

import (
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
)

func supervise(command *exec.Cmd) error {
	return fmt.Errorf("run %s on %s: %w", filepath.Base(command.Path), runtime.GOOS, errors.ErrUnsupported)
}
