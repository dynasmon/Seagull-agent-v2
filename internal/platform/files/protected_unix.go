//go:build linux || darwin

package files

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const maxLinks = 40

// Protected reports whether the superuser alone can change what path names:
// the file and every directory on the way to it belong to root and let no
// group or other account write them, except a directory that lets others add
// entries of their own and never remove one of root's. A link is followed,
// and what it leads to is held to the same rule as the path that named it.
func Protected(path string) error {
	return guarded(path, os.Lstat, os.Readlink)
}

func guarded(path string, describe func(string) (fs.FileInfo, error), resolve func(string) (string, error)) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("%s is not an absolute path", path)
	}
	root, err := describe("/")
	if err != nil {
		return err
	}
	if err := owned("/", root); err != nil {
		return err
	}
	pending, current, links := components(path), "/", 0
	for len(pending) > 0 {
		next := filepath.Join(current, pending[0])
		pending = pending[1:]
		described, err := describe(next)
		if err != nil {
			return err
		}
		if described.Mode()&fs.ModeSymlink != 0 {
			if links++; links > maxLinks {
				return fmt.Errorf("%s goes through more than %d links", path, maxLinks)
			}
			target, err := resolve(next)
			if err != nil {
				return err
			}
			if !filepath.IsAbs(target) {
				target = filepath.Join(current, target)
			}
			pending, current = append(components(target), pending...), "/"
			continue
		}
		if err := owned(next, described); err != nil {
			return err
		}
		current = next
	}
	return nil
}

func components(path string) []string {
	var named []string
	for _, name := range strings.Split(filepath.Clean(path), "/") {
		if name != "" {
			named = append(named, name)
		}
	}
	return named
}

func owned(path string, info fs.FileInfo) error {
	described, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%s does not say who owns it", path)
	}
	if described.Uid != 0 {
		return fmt.Errorf("%w: %s belongs to uid %d", ErrUnprotected, path, described.Uid)
	}
	sticky := info.IsDir() && info.Mode()&fs.ModeSticky != 0
	if permissions := info.Mode().Perm(); permissions&0o022 != 0 && !sticky {
		return fmt.Errorf("%w: %s grants %s, which lets its group or others change it", ErrUnprotected, path, permissions)
	}
	return nil
}
