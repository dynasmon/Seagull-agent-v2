// Package tree looks at the files of the host as they stand, and never through
// a symbolic link: a path is opened one name at a time from the root of the
// filesystem, each name through the directory that holds it, and what a name
// stands for as it is opened is checked against what it stood for as it was
// looked at, so a link or another file put in its place meanwhile is never
// taken for what it replaced.
package tree

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/secrets"
)

const listing = 256

type Kind uint8

const (
	Regular Kind = iota + 1
	Directory
	Link
	Pipe
	Socket
	Block
	Character
)

func (k Kind) String() string {
	switch k {
	case Regular:
		return "regular"
	case Directory:
		return "directory"
	case Link:
		return "link"
	case Pipe:
		return "pipe"
	case Socket:
		return "socket"
	case Block:
		return "block device"
	case Character:
		return "character device"
	}
	return fmt.Sprintf("kind(%d)", int(k))
}

// A Node is what the filesystem says of a name: what it is, which file on
// which device, how many names that file has, who owns it, the permissions it
// grants with its setuid, setgid and sticky bits, the device it stands for when
// it is one, how large it is, and when its content and its inode last changed.
type Node struct {
	Kind     Kind
	Device   uint64
	Inode    uint64
	Links    uint64
	User     uint32
	Group    uint32
	Mode     uint32
	Special  uint64
	Size     int64
	Modified time.Time
	Changed  time.Time
}

func (n Node) Same(other Node) bool { return n.Device == other.Device && n.Inode == other.Inode }

var (
	ErrLink         = errors.New("a symbolic link stands where a directory is named")
	ErrNotDirectory = errors.New("something other than a directory stands where a directory is named")
	ErrChanged      = errors.New("the name stood for another file as it was opened than as it was looked at")
	ErrTooMany      = errors.New("the directory holds more names than the agent reads")
	ErrLonger       = errors.New("the link names a target longer than the agent reads")
	errName         = errors.New("a name within a directory is one element of a path")
)

type Dir struct {
	root *os.Root
	self *os.File
	node Node
	path string
}

// Open opens the directory at the absolute path, one name at a time from the
// root of the filesystem, and refuses a path any element of which is a link.
// The directory is held open until it is closed, so what it reads stays what
// it was opened as, wherever it is moved meanwhile.
func Open(path string) (*Dir, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fmt.Errorf("open %s: the path is not absolute or has something to resolve", secrets.Shown(path))
	}
	root, err := os.OpenRoot(string(filepath.Separator))
	if err != nil {
		return nil, err
	}
	current, err := enclose(root, string(filepath.Separator), nil)
	if err != nil {
		return nil, err
	}
	for _, name := range strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator)) {
		if name == "" {
			continue
		}
		seen, err := current.Stat(name)
		if err == nil {
			switch seen.Kind {
			case Directory:
			case Link:
				err = fmt.Errorf("%w: %s", ErrLink, secrets.Shown(filepath.Join(current.path, name)))
			default:
				err = fmt.Errorf("%w: %s is a %s", ErrNotDirectory, secrets.Shown(filepath.Join(current.path, name)), seen.Kind)
			}
		}
		var next *Dir
		if err == nil {
			next, err = current.Enter(name, seen)
		}
		current.Close()
		if err != nil {
			return nil, err
		}
		current = next
	}
	return current, nil
}

func enclose(root *os.Root, path string, seen *Node) (*Dir, error) {
	self, err := root.Open(".")
	if err != nil {
		root.Close()
		return nil, err
	}
	held := &Dir{root: root, self: self, path: path}
	described, err := self.Stat()
	if err == nil {
		held.node, err = describe(described)
	}
	switch {
	case err != nil:
	case held.node.Kind != Directory:
		err = fmt.Errorf("%w: %s is a %s", ErrNotDirectory, secrets.Shown(path), held.node.Kind)
	case seen != nil && !held.node.Same(*seen):
		err = fmt.Errorf("%w: %s", ErrChanged, secrets.Shown(path))
	}
	if err != nil {
		held.Close()
		return nil, err
	}
	return held, nil
}

func (d *Dir) Node() Node     { return d.node }
func (d *Dir) Path() string   { return d.path }
func (d *Dir) File() *os.File { return d.self }

func (d *Dir) Close() error {
	return errors.Join(d.self.Close(), d.root.Close())
}

func (d *Dir) Names(most int) ([]string, error) {
	var names []string
	for {
		read, err := d.self.Readdirnames(listing)
		if len(names)+len(read) > most {
			return nil, fmt.Errorf("%w: %s holds more than %d", ErrTooMany, secrets.Shown(d.path), most)
		}
		names = append(names, read...)
		if errors.Is(err, io.EOF) {
			slices.Sort(names)
			return names, nil
		}
		if err != nil {
			return nil, err
		}
	}
}

func (d *Dir) Stat(name string) (Node, error) {
	if err := element(name); err != nil {
		return Node{}, err
	}
	described, err := d.root.Lstat(name)
	if err != nil {
		return Node{}, err
	}
	return describe(described)
}

func (d *Dir) Enter(name string, seen Node) (*Dir, error) {
	if err := element(name); err != nil {
		return nil, err
	}
	path := filepath.Join(d.path, name)
	if seen.Kind != Directory {
		return nil, fmt.Errorf("%w: %s was seen as a %s", ErrNotDirectory, secrets.Shown(path), seen.Kind)
	}
	root, err := d.root.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	return enclose(root, path, &seen)
}

func (d *Dir) Target(name string, most int) (string, error) {
	if err := element(name); err != nil {
		return "", err
	}
	target, err := d.root.Readlink(name)
	if err != nil {
		return "", err
	}
	if len(target) > most {
		return "", fmt.Errorf("%w: %s names more than %d bytes", ErrLonger, secrets.Shown(filepath.Join(d.path, name)), most)
	}
	return target, nil
}

// Read opens the regular file the name stands for to read it, without
// following a link and without waiting on a pipe, and refuses it unless it is
// the file seen when the name was looked at.
func (d *Dir) Read(name string, seen Node) (*File, error) {
	if err := element(name); err != nil {
		return nil, err
	}
	path := filepath.Join(d.path, name)
	opened, err := openFile(d.self, name)
	if err != nil {
		if errors.Is(err, errLooped) {
			return nil, fmt.Errorf("%w: %s is a link now", ErrChanged, secrets.Shown(path))
		}
		return nil, err
	}
	held := &File{file: opened}
	now, err := held.Stat()
	switch {
	case err != nil:
	case now.Kind != Regular || seen.Kind != Regular || !now.Same(seen):
		err = fmt.Errorf("%w: %s", ErrChanged, secrets.Shown(path))
	}
	if err != nil {
		held.Close()
		return nil, err
	}
	return held, nil
}

func element(name string) error {
	if name == "" || name == "." || name == ".." || strings.ContainsRune(name, filepath.Separator) {
		return fmt.Errorf("%w: %s", errName, secrets.Shown(name))
	}
	return nil
}

type File struct{ file *os.File }

func (f *File) Read(buffer []byte) (int, error) { return f.file.Read(buffer) }
func (f *File) Close() error                    { return f.file.Close() }

func (f *File) Stat() (Node, error) {
	described, err := f.file.Stat()
	if err != nil {
		return Node{}, err
	}
	return describe(described)
}
