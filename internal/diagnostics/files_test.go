//go:build linux || darwin

package diagnostics_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/diagnostics"
)

// An installation as the agent keeps it, with a key no account may read and
// beside it what the agent never writes: a pipe nothing writes into, and a
// link to a directory outside the installation.
func installation(t *testing.T) (string, string) {
	t.Helper()
	state := filepath.Join(t.TempDir(), "state")
	outside := t.TempDir()
	for _, directory := range []string{"", "keys", "spool", "spool/events"} {
		if err := os.Mkdir(filepath.Join(state, directory), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for name, content := range map[string]string{
		"installation.json":                         `{"format": 1}`,
		"keys/" + strings.Repeat("ab", 32) + ".pem": "-----BEGIN PRIVATE KEY-----",
		"spool/events/00000000000000000001.seg":     "SGSG",
	} {
		if err := os.WriteFile(filepath.Join(state, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(filepath.Join(state, "keys", strings.Repeat("ab", 32)+".pem"), 0); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(state, "spool", "events", "pipe"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "elsewhere"), []byte("not the agent's"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(state, "linked")); err != nil {
		t.Fatal(err)
	}
	return state, outside
}

func TestAListingNamesWhatADirectoryHoldsWithoutOpeningIt(t *testing.T) {
	state, _ := installation(t)
	listed := listing(t, state)
	if listed.Unread != "" || !listed.Complete || listed.Directory != diagnostics.Text(state) {
		t.Fatalf("the installation was listed as %+v", listed)
	}
	key := "keys/" + strings.Repeat("ab", 32) + ".pem"
	var paths []string
	for _, file := range listed.Entries {
		paths = append(paths, string(file.Path))
	}
	want := []string{"installation.json", "keys", "linked", "spool", key, "spool/events", "spool/events/00000000000000000001.seg", "spool/events/pipe"}
	if !slices.Equal(paths, want) {
		t.Fatalf("the installation was listed as %q, want %q", paths, want)
	}
	modes := map[string]string{
		"installation.json":                     "-rw-------",
		"keys":                                  "drwx------",
		"linked":                                "Lrwxrwxrwx",
		key:                                     "----------",
		"spool/events/pipe":                     "prw-------",
		"spool/events/00000000000000000001.seg": "-rw-------",
	}
	for _, file := range listed.Entries {
		if mode, named := modes[string(file.Path)]; named && string(file.Mode) != mode {
			t.Errorf("%s is listed as %s, want %s", file.Path, file.Mode, mode)
		}
		if file.Owner == nil || *file.Owner != os.Geteuid() || file.Modified.IsZero() || file.Modified.Location() != time.UTC {
			t.Errorf("%s is listed as %+v", file.Path, file)
		}
		if file.Path == "installation.json" && file.Size != int64(len(`{"format": 1}`)) {
			t.Errorf("installation.json is listed as %d bytes", file.Size)
		}
	}
}

func TestAListingCostsNoMoreThanItsBoundsWhateverTheDirectoryHolds(t *testing.T) {
	wide := t.TempDir()
	for n := range diagnostics.MaxFiles + 500 {
		if err := os.WriteFile(filepath.Join(wide, fmt.Sprintf("stray-%05d", n)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if listed := listing(t, wide); len(listed.Entries) != diagnostics.MaxFiles || listed.Complete || listed.Entries[0].Path != "stray-00000" {
		t.Errorf("a directory of %d files was listed as %d entries, complete %t", diagnostics.MaxFiles+500, len(listed.Entries), listed.Complete)
	}

	deep := t.TempDir()
	nested := deep
	for range 12 {
		nested = filepath.Join(nested, "d")
		if err := os.Mkdir(nested, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	listed := listing(t, deep)
	if len(listed.Entries) != 8 || listed.Complete || strings.Count(string(listed.Entries[7].Path), "d") != 8 {
		t.Errorf("a directory 12 levels deep was listed as %d entries, complete %t", len(listed.Entries), listed.Complete)
	}

	ended, cancel := context.WithCancel(t.Context())
	cancel()
	if listed := diagnostics.List(ended, deep); listed.Complete || len(listed.Entries) != 0 {
		t.Errorf("a listing out of time was %+v", listed)
	}
}

func TestADirectoryTheAccountMayNotListLeavesTheRestListed(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the superuser lists every directory")
	}
	directory := t.TempDir()
	for _, name := range []string{"closed", "open"} {
		if err := os.Mkdir(filepath.Join(directory, name), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, name, "held"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(filepath.Join(directory, "closed"), 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(filepath.Join(directory, "closed"), 0o700) })
	listed := listing(t, directory)
	var paths []string
	for _, file := range listed.Entries {
		paths = append(paths, string(file.Path))
	}
	if !slices.Equal(paths, []string{"closed", "open", "open/held"}) || listed.Complete {
		t.Errorf("a directory holding one the account may not list was listed as %q, complete %t", paths, listed.Complete)
	}
}

func TestAListingOfWhatIsNoDirectorySaysWhy(t *testing.T) {
	directory := t.TempDir()
	file := filepath.Join(directory, "file")
	link := filepath.Join(directory, "link")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(directory, link); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{"nothing": filepath.Join(directory, "absent"), "a file": file, "a link to a directory": link} {
		if listed := listing(t, path); listed.Unread == "" || len(listed.Entries) != 0 {
			t.Errorf("a listing of %s was %+v", name, listed)
		}
	}
}

// A name in the installation is whatever wrote it chose, so it is written down
// as data: escaped where it is not printable and cut where it is long.
func TestNamesNobodyChoseForTheAgentAreWrittenDownAsData(t *testing.T) {
	directory := t.TempDir()
	for _, name := range []string{"\x1b]0;owned\x07", "line\nbreak", "\xff\xfe", strings.Repeat("n", 250)} {
		if err := os.WriteFile(filepath.Join(directory, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	encoded, err := json.Marshal(listing(t, directory))
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(string(encoded), "\x1b\x07\n\xff") {
		t.Errorf("the listing wrote down names as they were written: %q", encoded)
	}
}

func listing(t *testing.T, directory string) diagnostics.Files {
	t.Helper()
	done := make(chan diagnostics.Files, 1)
	go func() { done <- diagnostics.List(t.Context(), directory) }()
	select {
	case listed := <-done:
		return listed
	case <-time.After(10 * time.Second):
		t.Fatalf("listing %s waited on something it opened", directory)
	}
	return diagnostics.Files{}
}
