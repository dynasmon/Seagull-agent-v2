//go:build !linux

package dumps

import (
	"errors"
	"fmt"
	"runtime"
)

func withhold() error {
	return fmt.Errorf("keep the agent's memory to itself on %s: %w", runtime.GOOS, errors.ErrUnsupported)
}
