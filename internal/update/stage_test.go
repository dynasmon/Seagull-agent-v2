package update_test

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/dynasmon/Seagull-agent-v2/internal/update"
	updatev1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/update/v1"
)

func releaseFor(version string, content []byte) *updatev1.Release {
	release := releaseOf(version, 0)
	sum := sha256.Sum256(content)
	release.Payload = &updatev1.Payload{Sha256: sum[:], Size: uint64(len(content))}
	return release
}

func entries(t *testing.T, root *os.Root) []string {
	t.Helper()
	listed, err := os.ReadDir(root.Name())
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range listed {
		names = append(names, entry.Name())
	}
	return names
}

func TestAPackageIsKeptOnlyOnceItIsExactlyTheOneTheReleaseNames(t *testing.T) {
	staging := update.OpenStaging(directory(t))
	content := []byte("!<arch>\nthe package of v0.3.0")
	release := releaseFor("v0.3.0", content)

	fetched := 0
	fetch := func(into io.Writer) error {
		fetched++
		_, err := into.Write(content)
		return err
	}
	for range 2 {
		if err := staging.Fetch(release, fetch); err != nil {
			t.Fatalf("fetch: %v", err)
		}
	}
	if fetched != 1 {
		t.Fatalf("a package already kept was fetched %d times", fetched)
	}

	for name, arrived := range map[string][]byte{
		"other bytes of the same size": bytes.Repeat([]byte("x"), len(content)),
		"fewer bytes":                  content[:len(content)-1],
		"more bytes":                   append(append([]byte{}, content...), '!'),
	} {
		t.Run(name, func(t *testing.T) {
			held := directory(t)
			if err := update.OpenStaging(held).Fetch(release, func(into io.Writer) error {
				_, err := into.Write(arrived)
				return err
			}); !errors.Is(err, update.ErrUnverified) {
				t.Fatalf("kept: %v", err)
			}
			if left := entries(t, held); len(left) != 0 {
				t.Fatalf("a package that was not the release's left %v behind", left)
			}
		})
	}
}

func TestTheInstallerTakesACopyItVerifiesAndNothingThatIsNotThePackage(t *testing.T) {
	agent, installer := directory(t), directory(t)
	staging := update.OpenStaging(agent)
	content := []byte("!<arch>\nthe package of v0.3.0")
	release := releaseFor("v0.3.0", content)
	if err := staging.Fetch(release, func(into io.Writer) error { _, err := into.Write(content); return err }); err != nil {
		t.Fatal(err)
	}
	if staging.Ready() {
		t.Fatal("a staging area is ready before the offer is handed over")
	}
	if err := staging.Hand([]byte("the offer")); err != nil {
		t.Fatal(err)
	}
	if offer, err := staging.Offer(); !staging.Ready() || err != nil || string(offer) != "the offer" {
		t.Fatalf("the staged offer reads %q: %v", offer, err)
	}

	if err := staging.Take(release, installer); err != nil {
		t.Fatalf("take: %v", err)
	}
	copied, err := os.ReadFile(filepath.Join(installer.Name(), update.PackageName(release.GetPayload().GetSha256())))
	if err != nil || !bytes.Equal(copied, content) {
		t.Fatalf("the installer holds %q: %v", copied, err)
	}

	for change, apply := range map[string]func(name string) error{
		"swapped for other bytes": func(name string) error { return os.WriteFile(name, bytes.Repeat([]byte("x"), len(content)), 0o644) },
		"cut short":               func(name string) error { return os.WriteFile(name, content[:4], 0o644) },
		"a link to elsewhere": func(name string) error {
			outside := filepath.Join(t.TempDir(), "outside.deb")
			if err := os.WriteFile(outside, content, 0o644); err != nil {
				return err
			}
			if err := os.Remove(name); err != nil {
				return err
			}
			return os.Symlink(outside, name)
		},
	} {
		t.Run(change, func(t *testing.T) {
			held := directory(t)
			tampered := update.OpenStaging(held)
			if err := tampered.Fetch(release, func(into io.Writer) error { _, err := into.Write(content); return err }); err != nil {
				t.Fatal(err)
			}
			if err := apply(filepath.Join(held.Name(), update.PackageName(release.GetPayload().GetSha256()))); err != nil {
				t.Fatal(err)
			}
			if err := tampered.Take(release, directory(t)); !errors.Is(err, update.ErrUnverified) {
				t.Fatalf("a package %s was taken: %v", change, err)
			}
		})
	}

	if err := staging.Clear(); err != nil || staging.Ready() || len(entries(t, agent)) != 0 {
		t.Fatalf("clearing left %v: %v", entries(t, agent), err)
	}
}
