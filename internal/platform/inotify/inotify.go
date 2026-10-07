// Package inotify tells the agent when what a directory holds may have
// changed, through the kernel's inotify: an event names a directory the agent
// watches and, within it, the name something happened to. What it tells is a
// hint and nothing more: the kernel folds an event into the one before it when
// they are alike, drops every event once its queue for the agent is full and
// says it did, and tells nothing of a directory nobody watches.
package inotify

import (
	"errors"
	"os"
)

const readBytes = 64 << 10

type What uint32

const (
	Created What = 1 << iota
	Deleted
	Modified
	Attributes
	Written
	MovedFrom
	MovedTo
	SelfDeleted
	SelfMoved
	Unmounted
	Ignored
	Overflowed
	OfDirectory
)

var named = []string{"created", "deleted", "modified", "attributes", "written", "moved from", "moved to",
	"deleted itself", "moved itself", "unmounted", "ignored", "overflowed", "of a directory"}

func (w What) Names() []string {
	var held []string
	for i, name := range named {
		if w&(1<<i) != 0 {
			held = append(held, name)
		}
	}
	return held
}

// An Event is one the kernel queued for a watch: what happened, to the name it
// gives within the directory watched, or to that directory itself when it
// gives none, and the cookie a move from one name shares with the move to the
// other.
type Event struct {
	Watch  int
	What   What
	Cookie uint32
	Name   string
}

var (
	ErrLimit     = errors.New("the kernel watches no more directories for the account the agent runs as")
	ErrClosed    = errors.New("the watcher is closed")
	ErrMalformed = errors.New("what the kernel said does not read as events")
)

type Watcher struct {
	file   *os.File
	buffer []byte
}

func Open() (*Watcher, error) {
	file, err := open()
	if err != nil {
		return nil, err
	}
	return &Watcher{file: file, buffer: make([]byte, readBytes)}, nil
}

// Add watches the directory the agent holds open, whatever path names it
// now, and returns the watch its events name. A directory watched already
// keeps the watch it has.
func (w *Watcher) Add(directory *os.File) (int, error) { return add(w.file, directory) }

func (w *Watcher) Remove(watch int) error { return remove(w.file, watch) }

// Read waits for the kernel to queue events and returns them, or ErrClosed
// once the watcher is closed, which also ends a Read waiting meanwhile.
func (w *Watcher) Read() ([]Event, error) {
	for {
		read, err := w.file.Read(w.buffer)
		switch {
		case errors.Is(err, os.ErrClosed):
			return nil, ErrClosed
		case err != nil:
			return nil, err
		case read > 0:
			return parse(w.buffer[:read])
		}
	}
}

func (w *Watcher) Close() error { return w.file.Close() }
