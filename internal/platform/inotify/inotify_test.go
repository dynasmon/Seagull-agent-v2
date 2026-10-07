//go:build linux

package inotify_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/platform/inotify"
)

type watching struct {
	t       *testing.T
	watcher *inotify.Watcher
	events  chan inotify.Event
	ended   chan error
}

func watch(t *testing.T) *watching {
	t.Helper()
	watcher, err := inotify.Open()
	if err != nil {
		t.Fatal(err)
	}
	held := &watching{t: t, watcher: watcher, events: make(chan inotify.Event, 1<<16), ended: make(chan error, 1)}
	go func() {
		for {
			events, err := watcher.Read()
			for _, event := range events {
				held.events <- event
			}
			if err != nil {
				held.ended <- err
				return
			}
		}
	}()
	t.Cleanup(func() { watcher.Close() })
	return held
}

func (w *watching) add(path string) int {
	w.t.Helper()
	directory, err := os.Open(path)
	if err != nil {
		w.t.Fatal(err)
	}
	defer directory.Close()
	watch, err := w.watcher.Add(directory)
	if err != nil {
		w.t.Fatal(err)
	}
	return watch
}

func (w *watching) until(found func(inotify.Event) bool) []inotify.Event {
	w.t.Helper()
	var seen []inotify.Event
	deadline := time.After(5 * time.Second)
	for {
		select {
		case event := <-w.events:
			seen = append(seen, event)
			if found(event) {
				return seen
			}
		case err := <-w.ended:
			w.t.Fatalf("the watcher ended with %v after %v", err, seen)
		case <-deadline:
			w.t.Fatalf("no such event among %v", seen)
		}
	}
}

func TestAWatchedDirectoryTellsWhatHappensToTheNamesItHolds(t *testing.T) {
	base := t.TempDir()
	watched := watch(t)
	watch := watched.add(base)
	path := filepath.Join(base, "file")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	seen := watched.until(func(event inotify.Event) bool { return event.What&inotify.Written != 0 })
	for _, event := range seen {
		if event.Watch != watch || event.Name != "file" {
			t.Errorf("writing a file told %+v", event)
		}
	}
	if seen[0].What&inotify.Created == 0 {
		t.Errorf("creating a file told %v first", seen[0].What.Names())
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	watched.until(func(event inotify.Event) bool { return event.What == inotify.Attributes && event.Name == "file" })
	if err := os.Mkdir(filepath.Join(base, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	watched.until(func(event inotify.Event) bool {
		return event.What == inotify.Created|inotify.OfDirectory && event.Name == "sub"
	})
	if err := os.Rename(path, filepath.Join(base, "renamed")); err != nil {
		t.Fatal(err)
	}
	moved := watched.until(func(event inotify.Event) bool { return event.What == inotify.MovedTo })
	from := moved[len(moved)-2]
	to := moved[len(moved)-1]
	if from.What != inotify.MovedFrom || from.Name != "file" || to.Name != "renamed" || from.Cookie == 0 || from.Cookie != to.Cookie {
		t.Errorf("a rename told %+v and %+v", from, to)
	}
	if err := os.Remove(filepath.Join(base, "renamed")); err != nil {
		t.Fatal(err)
	}
	watched.until(func(event inotify.Event) bool { return event.What == inotify.Deleted && event.Name == "renamed" })
}

func TestAWatchFollowsTheDirectoryItWasGivenWhereverItMoves(t *testing.T) {
	base := t.TempDir()
	if err := os.Mkdir(filepath.Join(base, "watched"), 0o755); err != nil {
		t.Fatal(err)
	}
	watched := watch(t)
	directory, err := os.Open(filepath.Join(base, "watched"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(base, "watched"), filepath.Join(base, "moved")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(base, "watched"), 0o755); err != nil {
		t.Fatal(err)
	}
	watch, err := watched.watcher.Add(directory)
	directory.Close()
	if err != nil {
		t.Fatal(err)
	}
	if again := watched.add(filepath.Join(base, "moved")); again != watch {
		t.Errorf("the directory opened is watched as %d, and the one now at its path as %d", watch, again)
	}
	if err := os.WriteFile(filepath.Join(base, "watched", "elsewhere"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "moved", "inside"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, event := range watched.until(func(event inotify.Event) bool { return event.Name == "inside" }) {
		if event.Name == "elsewhere" || event.Watch != watch {
			t.Errorf("the watch told %+v", event)
		}
	}
	if err := os.RemoveAll(filepath.Join(base, "moved")); err != nil {
		t.Fatal(err)
	}
	seen := watched.until(func(event inotify.Event) bool { return event.What&inotify.Ignored != 0 })
	if !slices.ContainsFunc(seen, func(event inotify.Event) bool { return event.What&inotify.SelfDeleted != 0 && event.Name == "" }) {
		t.Errorf("removing the watched directory told %v", seen)
	}
	if err := watched.watcher.Remove(watch); err != nil {
		t.Errorf("removing a watch the kernel dropped: %v", err)
	}
}

func TestAFileIsNotWatched(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	watched := watch(t)
	if _, err := watched.watcher.Add(file); err == nil {
		t.Error("a file was watched as a directory")
	}
}

func TestClosingTheWatcherEndsTheReadWaitingOnIt(t *testing.T) {
	watched := watch(t)
	watched.add(t.TempDir())
	time.Sleep(50 * time.Millisecond)
	if err := watched.watcher.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-watched.ended:
		if !errors.Is(err, inotify.ErrClosed) {
			t.Errorf("the read ended with %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the read still waits on a closed watcher")
	}
}

func TestAQueueTheKernelFilledSaysItDroppedEvents(t *testing.T) {
	written, err := os.ReadFile("/proc/sys/fs/inotify/max_queued_events")
	if err != nil {
		t.Skip("the kernel does not say how many events it queues")
	}
	queued, err := strconv.Atoi(strings.TrimSpace(string(written)))
	if err != nil || queued > 1<<17 {
		t.Skipf("the kernel queues %s events, too many to fill here", written)
	}
	base := t.TempDir()
	watcher, err := inotify.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer watcher.Close()
	directory, err := os.Open(base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := watcher.Add(directory); err != nil {
		t.Fatal(err)
	}
	directory.Close()
	for i := range queued/2 + 8 {
		path := filepath.Join(base, fmt.Sprint(i))
		if err := os.WriteFile(path, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	read := 0
	for {
		events, err := watcher.Read()
		if err != nil {
			t.Fatal(err)
		}
		read += len(events)
		if slices.ContainsFunc(events, func(event inotify.Event) bool { return event.What == inotify.Overflowed && event.Watch == -1 }) {
			break
		}
		if read > 2*queued {
			t.Fatalf("read %d events and none said the queue overflowed", read)
		}
	}
}
