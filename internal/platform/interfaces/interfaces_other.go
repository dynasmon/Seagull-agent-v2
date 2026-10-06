//go:build !linux

package interfaces

import (
	"errors"
	"fmt"
	"runtime"
)

func ipv4(bool) ([]labeled, error) {
	return nil, fmt.Errorf("read the network interfaces of %s: %w", runtime.GOOS, errors.ErrUnsupported)
}
