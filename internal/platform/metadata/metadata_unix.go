//go:build linux || darwin

package metadata

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

type identity struct {
	device, inode uint64
}

// Describe says what is at path, which is an absolute path with nothing to
// resolve. The directories above it are followed when they are links, and the
// path itself is not.
func Describe(path string) (Node, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return Node{}, fmt.Errorf("describe %q: the path is not absolute or has something to resolve", path)
	}
	hidden := hiders()
	reached := prefixes(path)
	for index, prefix := range reached {
		var info fs.FileInfo
		var err error
		if index == len(reached)-1 {
			info, err = os.Lstat(prefix)
		} else {
			info, err = os.Stat(prefix)
		}
		switch {
		case errors.Is(err, fs.ErrNotExist), errors.Is(err, syscall.ENOTDIR):
			return Node{}, fmt.Errorf("%w: %s", ErrAbsent, path)
		case errors.Is(err, fs.ErrPermission):
			return Node{}, fmt.Errorf("%w: %s cannot be searched", ErrDenied, filepath.Dir(prefix))
		case err != nil:
			return Node{}, fmt.Errorf("describe %s: %w", path, err)
		}
		held, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return Node{}, fmt.Errorf("describe %s: the kernel says nothing of who owns it", path)
		}
		if hidden[identity{device: uint64(held.Dev), inode: uint64(held.Ino)}] {
			return Node{}, fmt.Errorf("%w: %s", ErrHidden, prefix)
		}
		if index == len(reached)-1 {
			return Node{Kind: kindOf(info.Mode()), User: held.Uid, Group: held.Gid, Permissions: permissions(info.Mode())}, nil
		}
	}
	return Node{}, fmt.Errorf("describe %q: the path names nothing", path)
}

func hiders() map[identity]bool {
	held := map[identity]bool{}
	for _, name := range []string{"dir", "reg", "chr", "blk", "fifo", "sock"} {
		info, err := os.Lstat(filepath.Join(inaccessible, name))
		if err != nil {
			continue
		}
		if node, ok := info.Sys().(*syscall.Stat_t); ok {
			held[identity{device: uint64(node.Dev), inode: uint64(node.Ino)}] = true
		}
	}
	return held
}
