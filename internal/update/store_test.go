package update_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/dynasmon/Seagull-agent-v2/internal/update"
	updatev1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/update/v1"
)

func directory(t *testing.T) *os.Root {
	t.Helper()
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	return root
}

func TestWhatWasVerifiedOfUpdatesOutlivesARestart(t *testing.T) {
	first, second := newSigner(t), newSigner(t)
	anchor := anchored(t, rootOf(1, []signer{first}, 1, []signer{first}, 1), first)
	newer := anchor.Walk([]*updatev1.Envelope{sign(t, rootOf(2, []signer{second}, 1, []signer{second}, 1), update.RootPayloadType, first, second)}, written)
	held := directory(t)

	store, err := update.OpenStore(held)
	if err != nil {
		t.Fatal(err)
	}
	if nothing, err := store.Held(anchor, written); err != nil || nothing.Root.Version() != 1 || nothing.Catalog != 0 {
		t.Fatalf("nothing kept was read as root %d and catalog %d: %v", nothing.Root.Version(), nothing.Catalog, err)
	}
	if err := store.Keep(update.Held{Root: newer, Catalog: 9}); err != nil {
		t.Fatalf("keep: %v", err)
	}
	reopened, err := update.OpenStore(held)
	if err != nil {
		t.Fatal(err)
	}
	if again, err := reopened.Held(anchor, written); err != nil || again.Root.Version() != 2 || again.Catalog != 9 {
		t.Fatalf("what was kept read back as root %d and catalog %d: %v", again.Root.Version(), again.Catalog, err)
	}

	provisioned := anchored(t, rootOf(3, []signer{first}, 1, []signer{first}, 1), first)
	if moved, err := reopened.Held(provisioned, written); err != nil || moved.Root.Version() != 3 || moved.Catalog != 9 {
		t.Fatalf("a newer provisioned root left the agent on root %d: %v", moved.Root.Version(), err)
	}
}

func TestWhatCannotBeReadBackIsReportedAndTheProvisionedRootStands(t *testing.T) {
	owner := newSigner(t)
	anchor := anchored(t, rootOf(1, []signer{owner}, 1, []signer{owner}, 1), owner)
	for name, content := range map[string]struct {
		written string
		want    error
	}{
		"text":                  {"not json", update.ErrDamaged},
		"a field it never kept": {`{"format":1,"root":"","catalog":3,"extra":true}`, update.ErrDamaged},
		"a newer format":        {`{"format":2}`, update.ErrNewer},
		"a root that is none":   {`{"format":1,"root":"bm90IGEgcm9vdA==","catalog":3}`, update.ErrDamaged},
	} {
		t.Run(name, func(t *testing.T) {
			held := directory(t)
			if err := os.WriteFile(filepath.Join(held.Name(), "held.json"), []byte(content.written), 0o600); err != nil {
				t.Fatal(err)
			}
			store, err := update.OpenStore(held)
			if err != nil {
				t.Fatal(err)
			}
			read, err := store.Held(anchor, written)
			if !errors.Is(err, content.want) || read.Root.Version() != 1 {
				t.Fatalf("read as root %d: %v", read.Root.Version(), err)
			}
		})
	}
}

func TestAWriteACrashInterruptedIsDiscarded(t *testing.T) {
	held := directory(t)
	interrupted := filepath.Join(held.Name(), ".held.json.0123456789abcdef.tmp")
	if err := os.WriteFile(interrupted, []byte("half"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := update.OpenStore(held); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(interrupted); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("an interrupted write was left behind: %v", err)
	}
}
