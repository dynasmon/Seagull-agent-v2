package update_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/dynasmon/Seagull-agent-v2/internal/update"
)

func TestTheInstallersJournalSaysAnInstallationIsPendingUntilItEnds(t *testing.T) {
	held := directory(t)
	if _, found, err := update.ReadJournal(held); err != nil || found {
		t.Fatalf("an empty directory holds a journal: %v", err)
	}
	pending := filepath.Join(held.Name(), "pending")
	journal := update.Journal{Stage: update.Installing, Version: "v0.3.0", Previous: "v0.2.0", Catalog: 7, Root: 2, Started: written, Since: written}
	if err := update.KeepJournal(held, journal); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(pending); err != nil {
		t.Fatalf("an installation under way is not marked pending: %v", err)
	}
	read, found, err := update.ReadJournal(held)
	if err != nil || !found || read.Stage != update.Installing || read.Version != "v0.3.0" || read.Format != update.Format || !read.Started.Equal(written) {
		t.Fatalf("the journal read back as %+v: %v", read, err)
	}

	journal.Stage, journal.Failure, journal.Reason = update.RolledBack, update.Unhealthy, "it did not run"
	if err := update.KeepJournal(held, journal); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(pending); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("an installation that ended is still marked pending: %v", err)
	}
	if read, _, err := update.ReadJournal(held); err != nil || !read.Done() || read.Failure != update.Unhealthy {
		t.Fatalf("the journal read back as %+v: %v", read, err)
	}

	if err := os.WriteFile(filepath.Join(held.Name(), "journal.json"), []byte(`{"format":1,"stage":"installed","unknown":1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := update.ReadJournal(held); !errors.Is(err, update.ErrDamaged) {
		t.Fatalf("a journal holding what the installer never writes was read: %v", err)
	}
}
