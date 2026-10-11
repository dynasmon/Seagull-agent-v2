package policy_test

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/policy"
)

func opened(t *testing.T) (*policy.Store, string) {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "policy")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	store, err := policy.Open(root)
	if err != nil {
		t.Fatalf("open the store: %v", err)
	}
	return store, directory
}

func TestThePolicyTheAgentAppliedIsReadBackWhole(t *testing.T) {
	store, directory := opened(t)
	if _, found, err := store.Read(); found || err != nil {
		t.Fatalf("an empty store held a policy: %v", err)
	}

	key := signingKey(t)
	for _, revision := range []uint64{3, 4} {
		verified, err := verifier(t, key).Verify(signed(t, named(revision, "web-01"), key))
		if err != nil {
			t.Fatal(err)
		}
		at := written.Add(time.Duration(revision) * time.Minute)
		kept, err := store.Keep(verified, at)
		if err != nil {
			t.Fatalf("keep revision %d: %v", revision, err)
		}
		held, found, err := store.Read()
		switch {
		case err != nil || !found:
			t.Fatalf("revision %d was not read back: %v", revision, err)
		case held.Revision != revision || held.Digest != verified.Digest || !held.AppliedAt.Equal(at) || !slices.Equal(held.Envelope, verified.Envelope):
			t.Fatalf("revision %d was read back as %+v", revision, held.Holding)
		case kept.Holding != held.Holding:
			t.Fatalf("keeping answered %+v and reading %+v", kept.Holding, held.Holding)
		}
	}
	described, err := os.Stat(filepath.Join(directory, "policy.json"))
	if err != nil || described.Mode().Perm() != 0o600 {
		t.Fatalf("the policy is kept as %v: %v", described.Mode(), err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 1 {
		t.Fatalf("the store holds %d files: %v", len(entries), err)
	}
}

func TestAnInterruptedWriteIsDiscardedAndADamagedOneReported(t *testing.T) {
	store, directory := opened(t)
	key := signingKey(t)
	verified, err := verifier(t, key).Verify(signed(t, named(3, "web-01"), key))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Keep(verified, written); err != nil {
		t.Fatal(err)
	}
	leftover := filepath.Join(directory, ".policy.json.0123456789abcdef.tmp")
	if err := os.WriteFile(leftover, []byte("half"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	reopened, err := policy.Open(root)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if _, err := os.Stat(leftover); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("an interrupted write survived reopening: %v", err)
	}
	if held, found, err := reopened.Read(); err != nil || !found || held.Revision != 3 {
		t.Fatalf("the policy kept before the interrupted write reads as %+v, %v", held.Holding, err)
	}

	for name, content := range map[string]struct {
		written string
		want    error
	}{
		"text":                  {written: "not json", want: policy.ErrDamaged},
		"a setting it lacks":    {written: `{"format": 1, "revision": 3, "digest_sha256": "ab", "applied_at": "2026-10-10T12:00:00Z", "envelope": "AQ==", "extra": 1}`, want: policy.ErrDamaged},
		"no revision":           {written: `{"format": 1, "revision": 0, "digest_sha256": "ab", "applied_at": "2026-10-10T12:00:00Z", "envelope": "AQ=="}`, want: policy.ErrDamaged},
		"no envelope":           {written: `{"format": 1, "revision": 3, "digest_sha256": "ab", "applied_at": "2026-10-10T12:00:00Z"}`, want: policy.ErrDamaged},
		"a newer agent's state": {written: `{"format": 2}`, want: policy.ErrNewer},
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(filepath.Join(directory, "policy.json"), []byte(content.written), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, found, err := reopened.Read(); found || !errors.Is(err, content.want) {
				t.Fatalf("a policy file holding %s was read as %v, %v", name, found, err)
			}
		})
	}
}
