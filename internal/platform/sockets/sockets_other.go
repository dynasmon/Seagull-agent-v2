//go:build !linux

package sockets

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"runtime"
)

func Read(context.Context, Limits) (Reading, error) {
	return Reading{}, fmt.Errorf("read the sockets of %s: %w", runtime.GOOS, errors.ErrUnsupported)
}

func inode(fs.FileInfo) (uint64, bool) { return 0, false }
