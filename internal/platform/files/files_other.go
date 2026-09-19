//go:build !linux && !darwin

package files

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"runtime"
)

func Lock(file *os.File) error {
	return fmt.Errorf("lock %s on %s: %w", file.Name(), runtime.GOOS, errors.ErrUnsupported)
}

func Private(fs.FileInfo) error {
	return fmt.Errorf("cannot tell who may reach it on %s: %w", runtime.GOOS, errors.ErrUnsupported)
}

func Trusted(fs.FileInfo) error {
	return fmt.Errorf("cannot tell who may change it on %s: %w", runtime.GOOS, errors.ErrUnsupported)
}
