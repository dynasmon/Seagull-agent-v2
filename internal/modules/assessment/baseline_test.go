package assessment

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func collection(t *testing.T) *os.Root {
	t.Helper()
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("the module keeps its baseline where it can tell who owns it")
	}
	directory := filepath.Join(t.TempDir(), "collection")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	return root
}

func TestTheBaselineIsReadBackAsItWasWrittenDown(t *testing.T) {
	root := collection(t)
	if _, err := load(root); !errors.Is(err, errUnwritten) {
		t.Fatalf("a module that admitted nothing reads its baseline as %v", err)
	}
	held := baseline{Format: format, AssessedAt: madeAt, AssessmentID: "0d1c2b3a-4f5e-8d7c-9b0a-1f2e3d4c5b6a", PolicyID: "linux-baseline", Revision: 7,
		Checks: 3, Bytes: 412, Digest: strings.Repeat("ab", 32)}
	if err := save(root, held); err != nil {
		t.Fatal(err)
	}
	if read, err := load(root); err != nil || read != held {
		t.Fatalf("the baseline reads back as %+v: %v", read, err)
	}
	described, err := root.Stat(baselineFile)
	if err != nil || described.Mode().Perm() != 0o600 {
		t.Fatalf("the baseline is kept with permissions %v: %v", described.Mode().Perm(), err)
	}
	if err := os.WriteFile(filepath.Join(root.Name(), "."+baselineFile+".0123456789abcdef.tmp"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := discard(root); err != nil {
		t.Fatal(err)
	}
	if _, err := root.Stat("." + baselineFile + ".0123456789abcdef.tmp"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a write a crash interrupted was kept: %v", err)
	}
}

func TestABaselineThatDoesNotReadIsDamagedAndOneOfANewerAgentIsNewer(t *testing.T) {
	for content, want := range map[string]error{
		`{"format": 1}`: ErrDamaged,
		`{"format": 1, "assessed_at": "2026-10-15T12:00:00Z", "assessment_id": "a", "policy_id": "linux baseline", "policy_revision": 7, "checks": 3, "bytes": 1, "digest": "` + strings.Repeat("ab", 32) + `"}`: ErrDamaged,
		`{"format": 1, "assessed_at": "2026-10-15T12:00:00Z", "assessment_id": "a", "policy_id": "linux", "policy_revision": 7, "checks": 3, "bytes": 1, "digest": "x", "extra": 1}`:                             ErrDamaged,
		`{"format": 2}`: ErrNewer,
		`not json`:      ErrDamaged,
	} {
		if _, err := decode([]byte(content)); !errors.Is(err, want) {
			t.Errorf("%s was read as %v, want %v", content, err, want)
		}
	}
	if _, err := decode([]byte(strings.Repeat(" ", maxBaseline+1))); !errors.Is(err, ErrDamaged) {
		t.Errorf("a baseline beyond its bound was read as %v", err)
	}
}

func TestABaselineAnotherAccountCouldWriteIsNotRead(t *testing.T) {
	root := collection(t)
	if err := save(root, baseline{Format: format, AssessedAt: madeAt, AssessmentID: "a", PolicyID: "linux", Revision: 1, Digest: strings.Repeat("ab", 32)}); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root.Name(), baselineFile), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := load(root); !errors.Is(err, ErrInsecure) {
		t.Fatalf("a baseline others may read was answered %v", err)
	}
}

// Whatever the baseline holds, what reads as one is written back as bytes that
// read as the same baseline, and anything else is refused as damaged or newer,
// so the module admits its assessment again rather than trust it.
func FuzzDecode(f *testing.F) {
	digest := strings.Repeat("cd", 32)
	for _, seed := range []string{
		`{"format":1,"assessed_at":"2026-10-15T12:00:00Z","assessment_id":"0190f5d2-7c3e-7a41-9b6e-2f4d8c1a3f01","policy_id":"linux-web","policy_revision":3,"checks":21,"bytes":4096,"digest":"` + digest + `"}`,
		`{"format":1}`,
		`{"format":2}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, content []byte) {
		held, err := decode(content)
		if err != nil {
			if !errors.Is(err, ErrDamaged) && !errors.Is(err, ErrNewer) {
				t.Fatalf("a refusal that names no reason: %v", err)
			}
			return
		}
		written, err := json.Marshal(held)
		if err != nil {
			t.Fatal(err)
		}
		again, err := decode(written)
		if err != nil {
			t.Fatalf("a baseline was written as %s, which does not read: %v", written, err)
		}
		if rewritten, err := json.Marshal(again); err != nil || !bytes.Equal(rewritten, written) {
			t.Fatalf("a baseline was written as %s, and once read again as %s: %v", written, rewritten, err)
		}
	})
}
