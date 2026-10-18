//go:build linux || darwin

package status_test

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/status"
)

func swapping(t *testing.T, swap func() error) (stop func()) {
	t.Helper()
	var done atomic.Bool
	var group sync.WaitGroup
	group.Go(func() {
		for !done.Load() {
			if err := swap(); err != nil {
				t.Errorf("swap: %v", err)
				return
			}
		}
	})
	return func() { done.Store(true); group.Wait() }
}

func readsWhileSwapped(t *testing.T, directory string, unblock func()) []status.Snapshot {
	t.Helper()
	var held []status.Snapshot
	ended := make(chan struct{})
	go func() {
		defer close(ended)
		for deadline := time.Now().Add(1500 * time.Millisecond); time.Now().Before(deadline); {
			if snapshot, err := status.Read(directory); err == nil {
				held = append(held, snapshot)
			}
		}
	}()
	select {
	case <-ended:
		return held
	case <-time.After(10 * time.Second):
		unblock()
		t.Fatalf("reading the status in %s was held", directory)
		return nil
	}
}

func TestWhatIsSwappedInWhileAStatusIsReadIsNeverReadForIt(t *testing.T) {
	t.Run("a FIFO in place of the status", func(t *testing.T) {
		directory := private(t)
		path := filepath.Join(directory, "status.json")
		regular, fifo, moving := filepath.Join(directory, ".regular"), filepath.Join(directory, ".fifo"), filepath.Join(directory, ".moving")
		if err := os.WriteFile(regular, []byte(encoded(t, snapshot())), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Mkfifo(fifo, 0o600); err != nil {
			t.Fatal(err)
		}
		stop := swapping(t, func() error {
			for _, source := range []string{regular, fifo} {
				if err := os.Link(source, moving); err != nil {
					return err
				}
				if err := os.Rename(moving, path); err != nil {
					return err
				}
			}
			return nil
		})
		defer stop()
		readsWhileSwapped(t, directory, func() {
			stop()
			if writer, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
				writer.Close()
			}
		})
	})

	t.Run("another directory in place of the status directory", func(t *testing.T) {
		top := t.TempDir()
		directory, aside, elsewhere := filepath.Join(top, "status"), filepath.Join(top, "aside"), filepath.Join(top, "elsewhere")
		for name, said := range map[string]string{directory: "the agent", elsewhere: "another directory"} {
			if err := os.Mkdir(name, 0o700); err != nil {
				t.Fatal(err)
			}
			held := snapshot()
			held.Reason = status.Text(said)
			if err := os.WriteFile(filepath.Join(name, "status.json"), []byte(encoded(t, held)), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		stop := swapping(t, func() error {
			return errors.Join(os.Rename(directory, aside), os.Symlink(elsewhere, directory), os.Remove(directory), os.Rename(aside, directory))
		})
		defer stop()
		for _, held := range readsWhileSwapped(t, directory, stop) {
			if held.Reason != "the agent" {
				t.Fatalf("the status of %s was read for the agent's", held.Reason)
			}
		}
	})
}
