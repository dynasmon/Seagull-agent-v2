package update_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/dynasmon/Seagull-agent-v2/internal/update"
)

func TestTheGenerationOfTheStateIsTheNewestARunKeptItAt(t *testing.T) {
	held := directory(t)
	if generation, err := update.ReadGeneration(held); err != nil || generation != 1 {
		t.Fatalf("state no release wrote a generation for reads as %d: %v", generation, err)
	}
	if err := update.KeepGeneration(held); err != nil {
		t.Fatal(err)
	}
	if generation, err := update.ReadGeneration(held); err != nil || generation != update.StateGeneration {
		t.Fatalf("the state reads as generation %d: %v", generation, err)
	}

	path := filepath.Join(held.Name(), "generation")
	if err := os.WriteFile(path, []byte("5\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := update.KeepGeneration(held); err != nil {
		t.Fatal(err)
	}
	if generation, err := update.ReadGeneration(held); err != nil || generation != 5 {
		t.Fatalf("an older release lowered the generation to %d: %v", generation, err)
	}

	if err := os.WriteFile(path, []byte("many"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := update.ReadGeneration(held); !errors.Is(err, update.ErrDamaged) {
		t.Fatalf("a generation that is no number was read: %v", err)
	}
}
