package inventory

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

func directory(t *testing.T) (*os.Root, string) {
	t.Helper()
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("the collector keeps its baseline where it can tell who owns it")
	}
	path := t.TempDir()
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	return root, path
}

const digest = "ff0bf68e5669a1a3c1f0a8d0b5a3e8f1c3a0e6f4d2b8c9a7e5f3d1b9a7c5e3f1"

func TestABaselineReadsBackAsItWasWritten(t *testing.T) {
	root, path := directory(t)
	if _, err := load(root, Name); !errors.Is(err, errUnwritten) {
		t.Fatalf("a directory with no baseline was read as %v", err)
	}
	written := baseline{Kinds: map[string]entry{
		"package": {CollectedAt: time.Date(2026, 10, 5, 13, 0, 0, 123456789, time.UTC), RecordID: "0b6f6c55-0d55-8c0e-9b55-6a0f2b8a9e11", Items: 2099, Bytes: 180867, Digest: digest},
		"kernel":  {CollectedAt: time.Date(2026, 10, 5, 13, 0, 0, 0, time.UTC), RecordID: "1b6f6c55-0d55-8c0e-9b55-6a0f2b8a9e11", Items: 1, Bytes: 208, Digest: digest},
	}}
	if err := save(root, Name, written); err != nil {
		t.Fatal(err)
	}
	read, err := load(root, Name)
	if err != nil {
		t.Fatal(err)
	}
	if read.Format != format || len(read.Kinds) != 2 || read.Kinds["package"] != written.Kinds["package"] || read.Kinds["kernel"] != written.Kinds["kernel"] {
		t.Errorf("the baseline was read back as %+v", read)
	}
	if read.needs() != 180867+208 {
		t.Errorf("the next round needs %d bytes", read.needs())
	}
	described, err := os.Stat(filepath.Join(path, Name+".json"))
	if err != nil || described.Mode().Perm() != 0o600 {
		t.Errorf("the baseline is %v, %v", described.Mode(), err)
	}
	if (baseline{}).needs() != leastNeeds {
		t.Error("a round with nothing admitted before needs nothing")
	}
}

func TestABaselineThatDoesNotReadIsDamagedAndOneOfANewerAgentIsNewer(t *testing.T) {
	collected := `"collected_at":"2026-10-05T13:00:00Z","record_id":"0b6f6c55-0d55-8c0e-9b55-6a0f2b8a9e11","items":1,"bytes":208,"digest":"` + digest + `"`
	for name, content := range map[string]string{
		"no JSON":             "kinds: package",
		"an unknown setting":  `{"format":1,"kinds":{},"place":"x"}`,
		"two baselines":       `{"format":1,"kinds":{}}{"format":1,"kinds":{}}`,
		"no format":           `{"kinds":{}}`,
		"an unknown kind":     `{"format":1,"kinds":{"process":{` + collected + `}}}`,
		"no moment":           `{"format":1,"kinds":{"kernel":{"record_id":"x","items":1,"bytes":1,"digest":"` + digest + `"}}}`,
		"no record":           `{"format":1,"kinds":{"kernel":{"collected_at":"2026-10-05T13:00:00Z","items":1,"bytes":1,"digest":"` + digest + `"}}}`,
		"a digest of nothing": `{"format":1,"kinds":{"kernel":{"collected_at":"2026-10-05T13:00:00Z","record_id":"x","items":1,"bytes":1,"digest":"ff"}}}`,
		"fewer than no items": `{"format":1,"kinds":{"kernel":{"collected_at":"2026-10-05T13:00:00Z","record_id":"x","items":-1,"bytes":1,"digest":"` + digest + `"}}}`,
		"too large":           `{"format":1,"kinds":{}}` + strings.Repeat(" ", maxBaseline),
	} {
		if _, err := decode([]byte(content), Name); !errors.Is(err, ErrDamaged) {
			t.Errorf("%s: the baseline was read as %v", name, err)
		}
	}
	if _, err := decode([]byte(`{"format":2,"kinds":{"process":{}}}`), Name); !errors.Is(err, ErrNewer) {
		t.Errorf("a baseline of format 2 was read as %v", err)
	}
	if held, err := decode([]byte(`{"format":1,"kinds":{"kernel":{`+collected+`}}}`), Name); err != nil || held.Kinds["kernel"].Items != 1 {
		t.Errorf("a baseline that reads was read as %+v and %v", held, err)
	}
	if _, err := decode([]byte(`{"format":1,"kinds":{"kernel":{`+collected+`}}}`), Processes); !errors.Is(err, ErrDamaged) {
		t.Errorf("a baseline of the processes that holds the kernel was read as %v", err)
	}
}

func TestABaselineOthersMayReachOrThatIsNoFileIsNotTrusted(t *testing.T) {
	root, path := directory(t)
	file := filepath.Join(path, Name+".json")
	if err := os.WriteFile(file, []byte(`{"format":1,"kinds":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(file, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := load(root, Name); !errors.Is(err, ErrInsecure) {
		t.Errorf("a baseline others may read was read as %v", err)
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", file); err != nil {
		t.Fatal(err)
	}
	if _, err := load(root, Name); !errors.Is(err, ErrInsecure) {
		t.Errorf("a baseline that is a symbolic link was read as %v", err)
	}
}

func TestAnInterruptedWriteOfTheBaselineIsDiscardedAndNothingElse(t *testing.T) {
	root, path := directory(t)
	names := []string{".inventory.json.0123456789abcdef.tmp", ".authentication.json.0123456789abcdef.tmp", ".processes.json.0123456789abcdef.tmp", "authentication.json", ".inventory.json.tmp", "inventory.json.0123456789abcdef.tmp"}
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(path, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := discard(root, Name); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	var left []string
	for _, entry := range entries {
		left = append(left, entry.Name())
	}
	if want := slices.Sorted(slices.Values(names[1:])); !slices.Equal(left, want) {
		t.Errorf("after discarding, %s holds %v, want %v", path, left, want)
	}
}

// Whatever the baseline holds, what reads as one is written back as bytes that
// read as the same baseline, and anything else is refused as damaged or newer,
// so the collector sends whole snapshots again rather than trust it.
func FuzzDecode(f *testing.F) {
	digest := strings.Repeat("ab", 32)
	for _, seed := range []string{
		`{"format":1,"kinds":{"package":{"collected_at":"2026-10-05T12:00:00Z","record_id":"0190f5d2-7c3e-7a41-9b6e-2f4d8c1a3f01","items":2099,"bytes":185000,"digest":"` + digest + `"}}}`,
		`{"format":1,"kinds":{"process":{"collected_at":"2026-10-05T12:00:00Z","record_id":"r","items":1,"bytes":1,"digest":"` + digest + `"}}}`,
		`{"format":1,"kinds":{}}`,
		`{"format":2}`,
		`{"format":1,"kinds":{"package":{"collected_at":"2026-10-05T12:00:00Z","record_id":"r","items":-1,"bytes":1,"digest":"` + digest + `"}}}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, content []byte) {
		for _, module := range []string{"inventory", Processes} {
			held, err := decode(content, module)
			if err != nil {
				if !errors.Is(err, ErrDamaged) && !errors.Is(err, ErrNewer) {
					t.Fatalf("a refusal that names no reason: %v", err)
				}
				continue
			}
			written, err := json.Marshal(held)
			if err != nil {
				t.Fatal(err)
			}
			again, err := decode(written, module)
			if err != nil {
				t.Fatalf("a baseline was written as %s, which does not read: %v", written, err)
			}
			if rewritten, err := json.Marshal(again); err != nil || !bytes.Equal(rewritten, written) {
				t.Fatalf("a baseline was written as %s, and once read again as %s: %v", written, rewritten, err)
			}
		}
	})
}
