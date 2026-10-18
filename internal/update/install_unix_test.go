//go:build linux || darwin

package update_test

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/update"
)

func fifoIn(t *testing.T, root *os.Root, name string) string {
	t.Helper()
	path := filepath.Join(root.Name(), name)
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func within(t *testing.T, fifo string, run func() error) error {
	t.Helper()
	ended := make(chan error, 1)
	go func() { ended <- run() }()
	select {
	case err := <-ended:
		return err
	case <-time.After(10 * time.Second):
		if writer, err := os.OpenFile(fifo, os.O_WRONLY, 0); err == nil {
			writer.Close()
		}
		t.Fatalf("a FIFO at %s held the installer", fifo)
		return nil
	}
}

func TestNothingTheAgentsAccountPutsInPlaceHoldsTheInstaller(t *testing.T) {
	t.Run("the offer", func(t *testing.T) {
		installing := newEstate(t).installing(t, "v0.3.0")
		fifo := fifoIn(t, installing.staged, "offer.pb")
		if err := within(t, fifo, func() error { return installing.installer.Run(t.Context()) }); !errors.Is(err, update.ErrDamaged) {
			t.Fatalf("an offer that is a FIFO was read: %v", err)
		}
		if left := entries(t, installing.staged); len(left) != 0 || len(installing.manager.installed) != 0 {
			t.Fatalf("the installer left %v staged and installed %v", left, installing.manager.installed)
		}
	})

	t.Run("the package of the release", func(t *testing.T) {
		installing := newEstate(t).installing(t, "v0.3.0")
		fifo := fifoIn(t, installing.staged, update.PackageName(digest(installing.next)))
		if err := within(t, fifo, func() error { return installing.installer.Run(t.Context()) }); err != nil {
			t.Fatalf("run: %v", err)
		}
		if journal := installing.journal(t); journal.Stage != update.Failed || journal.Failure != update.Unverified || len(installing.manager.installed) != 0 {
			t.Fatalf("a package that is a FIFO ended at %+v, installing %v", journal, installing.manager.installed)
		}
	})

	t.Run("the generation of the state", func(t *testing.T) {
		held := directory(t)
		fifo := fifoIn(t, held, "generation")
		if err := within(t, fifo, func() error { _, err := update.ReadGeneration(held); return err }); !errors.Is(err, update.ErrDamaged) {
			t.Fatalf("a generation that is a FIFO was read: %v", err)
		}
	})
}
