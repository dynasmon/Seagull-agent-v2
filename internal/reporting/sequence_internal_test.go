package reporting

import (
	"errors"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// Whatever the count of the reports holds, the agent opens it, and the next
// report it sends follows every report it could have sent before: the count it
// read, or the clock when it read none.
func FuzzSequence(f *testing.F) {
	for _, seed := range []string{`{"format":1,"sequence":41}`, `{"format":1,"sequence":0}`, `{"format":2,"sequence":41}`, `{"format":1,"sequence":-1}`,
		`{"format":1,"sequence":41,"more":1}`, `{"format":1,"sequence":` + strconv.FormatUint(math.MaxUint64-1, 10) + `}`} {
		f.Add([]byte(seed))
	}
	now := time.Date(2026, time.October, 17, 12, 0, 0, 0, time.UTC)
	f.Fuzz(func(t *testing.T, content []byte) {
		directory := t.TempDir()
		if err := os.WriteFile(filepath.Join(directory, sequenceFile), content, 0o600); err != nil {
			t.Fatal(err)
		}
		root, err := os.OpenRoot(directory)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		held, err := openSequence(root, now)
		if err != nil {
			t.Fatalf("the count of the reports could not be opened: %v", err)
		}
		before := held.last
		if held.lost == nil {
			if read, err := held.read(); err != nil || read != before {
				t.Fatalf("the count was taken as %d and reads as %d: %v", before, read, err)
			}
		} else if !errors.Is(held.lost, ErrSequenceLost) || before != uint64(now.Unix()) {
			t.Fatalf("a count that does not read was taken up again at %d: %v", before, held.lost)
		}
		if before == math.MaxUint64 {
			return
		}
		next, err := held.next()
		if err != nil || next != before+1 {
			t.Fatalf("after %d the next report was counted %d: %v", before, next, err)
		}
		if read, err := held.read(); err != nil || read != next {
			t.Fatalf("report %d was kept as %d: %v", next, read, err)
		}
	})
}
