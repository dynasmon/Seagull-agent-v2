//go:build linux

package tree

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"
	"time"
)

var errLooped = syscall.ELOOP

func describe(info fs.FileInfo) (Node, error) {
	held, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return Node{}, errors.New("the filesystem does not say what the file is")
	}
	node := Node{
		Device:   uint64(held.Dev),
		Inode:    uint64(held.Ino),
		Links:    uint64(held.Nlink),
		User:     held.Uid,
		Group:    held.Gid,
		Mode:     held.Mode & 0o7777,
		Size:     held.Size,
		Modified: time.Unix(held.Mtim.Unix()),
		Changed:  time.Unix(held.Ctim.Unix()),
	}
	switch held.Mode & syscall.S_IFMT {
	case syscall.S_IFREG:
		node.Kind = Regular
	case syscall.S_IFDIR:
		node.Kind = Directory
	case syscall.S_IFLNK:
		node.Kind = Link
	case syscall.S_IFIFO:
		node.Kind = Pipe
	case syscall.S_IFSOCK:
		node.Kind = Socket
	case syscall.S_IFBLK:
		node.Kind, node.Special = Block, uint64(held.Rdev)
	case syscall.S_IFCHR:
		node.Kind, node.Special = Character, uint64(held.Rdev)
	default:
		return Node{}, fmt.Errorf("the filesystem says it is a file of type %#o", held.Mode&syscall.S_IFMT)
	}
	return node, nil
}

// The kernel resolves the one name it is handed from the directory it is
// handed, and refuses it when it is a link: a link put there after the name
// was looked at is never followed, wherever it points.
func openFile(directory *os.File, name string) (*os.File, error) {
	connection, err := directory.SyscallConn()
	if err != nil {
		return nil, err
	}
	descriptor, opened := -1, error(nil)
	if err := connection.Control(func(held uintptr) {
		for {
			descriptor, opened = syscall.Openat(int(held), name, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_NOCTTY|syscall.O_CLOEXEC, 0)
			if !errors.Is(opened, syscall.EINTR) {
				return
			}
		}
	}); err != nil {
		return nil, err
	}
	if opened != nil {
		return nil, &fs.PathError{Op: "openat", Path: name, Err: opened}
	}
	return os.NewFile(uintptr(descriptor), name), nil
}
