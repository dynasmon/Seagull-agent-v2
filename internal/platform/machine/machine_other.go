//go:build !linux

package machine

import (
	"errors"
	"fmt"
	"runtime"
)

func Running() (Kernel, error) {
	return Kernel{}, fmt.Errorf("describe the kernel of %s: %w", runtime.GOOS, errors.ErrUnsupported)
}
