package diagnostics

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"slices"
	"syscall"

	"github.com/dynasmon/Seagull-agent-v2/internal/platform/files"
)

const (
	MaxFiles = 1024
	maxDepth = 8
	chunk    = 128
)

type pending struct {
	path  string
	depth int
}

// List names what directory holds, the files it is made of and never what
// they hold: each one's path, mode, size, owner and when it last changed,
// directories first by level. It follows no link and opens nothing but
// directories, without waiting on one that turned into a pipe, so a key is
// listed by its name and never read, and a directory that holds more than the
// agent wrote costs MaxFiles entries, maxDepth levels and the time ctx leaves.
func List(ctx context.Context, directory string) Files {
	listed := Files{Directory: Text(directory), Complete: true}
	described, err := os.Lstat(directory)
	switch {
	case err != nil:
		listed.Unread = Text(err.Error())
		return listed
	case !described.IsDir():
		listed.Unread = Text(directory + " is not a directory")
		return listed
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		listed.Unread = Text(err.Error())
		return listed
	}
	defer root.Close()
	if opened, err := root.Stat("."); err != nil || !os.SameFile(opened, described) {
		listed.Unread = Text(directory + " changed while it was being opened")
		return listed
	}
	listed.directories = append(listed.directories, described)
	queue := []pending{{path: "."}}
	for len(queue) > 0 && len(listed.Entries) < MaxFiles && ctx.Err() == nil {
		next := queue[0]
		queue = queue[1:]
		held, err := names(root, next.path, MaxFiles-len(listed.Entries)+1)
		if err != nil {
			listed.Complete = false
		}
		for _, name := range held {
			if len(listed.Entries) == MaxFiles {
				listed.Complete = false
				break
			}
			named := path.Join(next.path, name)
			info, err := root.Lstat(named)
			if err != nil {
				continue
			}
			listed.Entries = append(listed.Entries, file(named, info))
			if !info.IsDir() {
				continue
			}
			listed.directories = append(listed.directories, info)
			if next.depth+1 < maxDepth {
				queue = append(queue, pending{path: named, depth: next.depth + 1})
			} else {
				listed.Complete = false
			}
		}
	}
	if len(queue) > 0 {
		listed.Complete = false
	}
	return listed
}

func names(root *os.Root, name string, most int) ([]string, error) {
	directory, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	if described, err := directory.Stat(); err != nil || !described.IsDir() {
		return nil, fmt.Errorf("%s is no longer a directory", name)
	}
	var held []string
	for len(held) < most {
		read, err := directory.Readdirnames(min(chunk, most-len(held)))
		held = append(held, read...)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			slices.Sort(held)
			return held, err
		}
	}
	slices.Sort(held)
	return held, nil
}

func file(name string, info fs.FileInfo) File {
	held := File{Path: Text(name), Mode: Text(info.Mode().String()), Size: info.Size(), Modified: info.ModTime().UTC()}
	if owner, err := files.Owner(info); err == nil {
		held.Owner = &owner
	}
	return held
}
