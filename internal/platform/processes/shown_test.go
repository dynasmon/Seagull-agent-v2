package processes

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Whatever the mount table says, procfs mounted with any hidepid but 0 or off
// is reported as hiding processes, and nothing else is.
func FuzzShown(f *testing.F) {
	f.Add([]byte("22 1 0:21 / /proc rw,nosuid,nodev,noexec,relatime shared:13 - proc proc rw\n"))
	f.Add([]byte("22 1 0:21 / /proc rw,nosuid shared:13 - proc proc rw,hidepid=invisible,subset=pid\n"))
	f.Add([]byte("22 1 0:21 / /proc rw - tmpfs tmpfs rw\n"))
	f.Add([]byte("22 1 0:21 / /proc rw - proc proc rw,hidepid=0\n23 22 0:22 / /proc rw - proc proc rw,hidepid=2\n"))
	f.Fuzz(func(t *testing.T, mounts []byte) {
		directory := t.TempDir()
		if err := os.MkdirAll(filepath.Join(directory, "self"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "self", "mountinfo"), mounts, 0o644); err != nil {
			t.Fatal(err)
		}
		held, err := os.OpenRoot(directory)
		if err != nil {
			t.Fatal(err)
		}
		defer held.Close()
		err = shown(held)
		switch {
		case err != nil && len(err.Error()) > 1<<10:
			t.Fatalf("a refusal of %d bytes", len(err.Error()))
		case errors.Is(err, ErrHidden) && !strings.Contains(string(mounts), "hidepid="):
			t.Fatalf("processes were reported hidden by a mount table that says nothing of it: %v", err)
		case err != nil && !errors.Is(err, ErrHidden) && !errors.Is(err, ErrUnreadable):
			t.Fatalf("a refusal that names no reason: %v", err)
		}
	})
}

// Whatever procfs says of when the host booted, the moment read is one it says
// in whole seconds after 1970, or it is refused as unreadable.
func FuzzBoot(f *testing.F) {
	f.Add([]byte("cpu  1 2 3\nbtime 1760689800\nprocesses 4242\n"))
	f.Add([]byte("btime -1\n"))
	f.Add([]byte("btime 99999999999999999999\n"))
	f.Fuzz(func(t *testing.T, system []byte) {
		directory := t.TempDir()
		if err := os.WriteFile(filepath.Join(directory, "stat"), system, 0o644); err != nil {
			t.Fatal(err)
		}
		held, err := os.OpenRoot(directory)
		if err != nil {
			t.Fatal(err)
		}
		defer held.Close()
		booted, err := boot(held)
		switch {
		case err != nil && !errors.Is(err, ErrUnreadable):
			t.Fatalf("a refusal that names no reason: %v", err)
		case err == nil && (!booted.After(time.Unix(0, 0)) || booted.Nanosecond() != 0):
			t.Fatalf("the host was read as booted at %s", booted)
		}
	})
}
