// Package metadata describes a path as the kernel shows it to the agent: what
// it is, the account and group that own it and its permission bits, read
// without opening it and without following it when it is a link. A path the
// agent's service hides from it, by mounting one of systemd's inaccessible
// nodes over it or over a directory above it, is told apart from the path the
// host keeps there.
package metadata

import (
	"errors"
	"io/fs"
	"strings"
)

var inaccessible = "/run/systemd/inaccessible"

var (
	ErrAbsent = errors.New("nothing is at the path")
	ErrDenied = errors.New("the agent's account cannot reach the path")
	ErrHidden = errors.New("the agent's service hides the path from it")
)

type Kind int

const (
	Other Kind = iota
	Regular
	Directory
	Symlink
)

func (k Kind) String() string {
	switch k {
	case Regular:
		return "regular file"
	case Directory:
		return "directory"
	case Symlink:
		return "symbolic link"
	default:
		return "special file"
	}
}

type Node struct {
	Kind        Kind
	User        uint32
	Group       uint32
	Permissions uint32
}

func kindOf(mode fs.FileMode) Kind {
	switch {
	case mode.IsRegular():
		return Regular
	case mode.IsDir():
		return Directory
	case mode&fs.ModeSymlink != 0:
		return Symlink
	default:
		return Other
	}
}

func permissions(mode fs.FileMode) uint32 {
	held := uint32(mode.Perm())
	if mode&fs.ModeSetuid != 0 {
		held |= 0o4000
	}
	if mode&fs.ModeSetgid != 0 {
		held |= 0o2000
	}
	if mode&fs.ModeSticky != 0 {
		held |= 0o1000
	}
	return held
}

// prefixes are the directories a path is reached through, from the top, and
// the path itself last.
func prefixes(path string) []string {
	var held []string
	for index := 1; index < len(path); index++ {
		if path[index] == '/' {
			held = append(held, path[:index])
		}
	}
	return append(held, strings.TrimSuffix(path, "/"))
}
