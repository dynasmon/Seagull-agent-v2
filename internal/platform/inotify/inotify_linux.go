//go:build linux

package inotify

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strconv"
	"syscall"
)

const (
	header  = syscall.SizeofInotifyEvent
	maxName = 4 << 10
	watched = syscall.IN_CREATE | syscall.IN_DELETE | syscall.IN_MODIFY | syscall.IN_ATTRIB | syscall.IN_CLOSE_WRITE |
		syscall.IN_MOVED_FROM | syscall.IN_MOVED_TO | syscall.IN_DELETE_SELF | syscall.IN_MOVE_SELF |
		syscall.IN_ONLYDIR | syscall.IN_EXCL_UNLINK
)

var told = []struct {
	mask uint32
	what What
}{
	{syscall.IN_CREATE, Created}, {syscall.IN_DELETE, Deleted}, {syscall.IN_MODIFY, Modified},
	{syscall.IN_ATTRIB, Attributes}, {syscall.IN_CLOSE_WRITE, Written}, {syscall.IN_MOVED_FROM, MovedFrom},
	{syscall.IN_MOVED_TO, MovedTo}, {syscall.IN_DELETE_SELF, SelfDeleted}, {syscall.IN_MOVE_SELF, SelfMoved},
	{syscall.IN_UNMOUNT, Unmounted}, {syscall.IN_IGNORED, Ignored}, {syscall.IN_Q_OVERFLOW, Overflowed},
	{syscall.IN_ISDIR, OfDirectory},
}

func open() (*os.File, error) {
	descriptor, err := syscall.InotifyInit1(syscall.IN_CLOEXEC | syscall.IN_NONBLOCK)
	if err != nil {
		return nil, fmt.Errorf("start watching directories: %w", err)
	}
	return os.NewFile(uintptr(descriptor), "inotify"), nil
}

// The kernel watches what the descriptor's link in procfs leads to, which is
// the directory the agent opened, and never what a path names by then.
func add(watcher, directory *os.File) (int, error) {
	notifying, err := watcher.SyscallConn()
	if err != nil {
		return 0, err
	}
	held, err := directory.SyscallConn()
	if err != nil {
		return 0, err
	}
	watch, added := 0, error(nil)
	err = notifying.Control(func(notified uintptr) {
		if err := held.Control(func(opened uintptr) {
			watch, added = syscall.InotifyAddWatch(int(notified), "/proc/self/fd/"+strconv.Itoa(int(opened)), watched)
		}); err != nil {
			added = err
		}
	})
	switch {
	case err != nil:
		return 0, err
	case errors.Is(added, syscall.ENOSPC):
		return 0, fmt.Errorf("%w: watch %s: %w", ErrLimit, directory.Name(), added)
	case added != nil:
		return 0, fmt.Errorf("watch %s: %w", directory.Name(), added)
	}
	return watch, nil
}

func remove(watcher *os.File, watch int) error {
	notifying, err := watcher.SyscallConn()
	if err != nil {
		return err
	}
	removed := error(nil)
	if err := notifying.Control(func(notified uintptr) {
		_, removed = syscall.InotifyRmWatch(int(notified), uint32(watch))
	}); err != nil {
		return err
	}
	if removed != nil && !errors.Is(removed, syscall.EINVAL) {
		return fmt.Errorf("stop watching %d: %w", watch, removed)
	}
	return nil
}

func parse(buffer []byte) ([]Event, error) {
	var events []Event
	for offset := 0; offset < len(buffer); {
		if len(buffer)-offset < header {
			return events, fmt.Errorf("%w: %d bytes are left of an event of %d", ErrMalformed, len(buffer)-offset, header)
		}
		read := buffer[offset:]
		length := binary.NativeEndian.Uint32(read[12:])
		if length > maxName || int(length) > len(read)-header {
			return events, fmt.Errorf("%w: an event names %d bytes, and %d are left", ErrMalformed, length, len(read)-header)
		}
		name := read[header : header+int(length)]
		if ends := bytes.IndexByte(name, 0); ends >= 0 {
			name = name[:ends]
		}
		mask := binary.NativeEndian.Uint32(read[4:])
		var what What
		for _, held := range told {
			if mask&held.mask != 0 {
				what |= held.what
			}
		}
		events = append(events, Event{
			Watch:  int(int32(binary.NativeEndian.Uint32(read))),
			What:   what,
			Cookie: binary.NativeEndian.Uint32(read[8:]),
			Name:   string(name),
		})
		offset += header + int(length)
	}
	return events, nil
}
