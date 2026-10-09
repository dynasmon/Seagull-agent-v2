//go:build linux

package sockets

import (
	"context"
	"io/fs"
	"syscall"
)

func Read(ctx context.Context, limits Limits) (Reading, error) { return read(ctx, proc, limits) }

func inode(described fs.FileInfo) (uint64, bool) {
	held, known := described.Sys().(*syscall.Stat_t)
	if !known {
		return 0, false
	}
	return held.Ino, true
}
