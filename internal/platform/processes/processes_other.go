//go:build !linux

package processes

import (
	"context"
	"errors"
	"fmt"
	"runtime"
)

func List(context.Context, int) ([]Process, error) {
	return nil, fmt.Errorf("read the processes of %s: %w", runtime.GOOS, errors.ErrUnsupported)
}
