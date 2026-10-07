//go:build !linux

package inotify

import (
	"errors"
	"fmt"
	"os"
	"runtime"
)

func open() (*os.File, error) {
	return nil, fmt.Errorf("watch the directories of %s: %w", runtime.GOOS, errors.ErrUnsupported)
}

func add(*os.File, *os.File) (int, error) {
	return 0, fmt.Errorf("watch the directories of %s: %w", runtime.GOOS, errors.ErrUnsupported)
}

func remove(*os.File, int) error {
	return fmt.Errorf("watch the directories of %s: %w", runtime.GOOS, errors.ErrUnsupported)
}

func parse([]byte) ([]Event, error) {
	return nil, fmt.Errorf("read the events of %s: %w", runtime.GOOS, errors.ErrUnsupported)
}
