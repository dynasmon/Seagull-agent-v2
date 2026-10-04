//go:build linux || darwin

package diagnostics_test

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/diagnostics"
)

const childDirectory = "SEAGULL_DIAGNOSTICS_TEST_DIRECTORY"

// A child writes bundles one after the other into the directory it is given,
// saying which it wrote, until it is killed.
func TestMain(m *testing.M) {
	if directory, ok := os.LookupEnv(childDirectory); ok {
		os.Exit(writeUntilKilled(directory))
	}
	os.Exit(m.Run())
}

func writeUntilKilled(directory string) int {
	bundle := diagnostics.Bundle{Status: diagnostics.Took("status", strings.Repeat("x", 1<<20))}
	for n := 0; ; n++ {
		if _, err := diagnostics.Write(filepath.Join(directory, fmt.Sprintf("bundle-%04d.json", n)), bundle); err != nil {
			fmt.Println("failed", err)
			return 1
		}
		fmt.Println("written", n)
	}
}

func TestABundleIsANewFileOnlyTheAccountThatWroteItReads(t *testing.T) {
	directory := shared(t)
	destination := filepath.Join(directory, "bundle.json")
	before := time.Now().UTC()
	written, err := diagnostics.Write(destination, diagnostics.Bundle{Configuration: diagnostics.Took("agent.json", map[string]int{"format": 1})})
	if err != nil {
		t.Fatalf("write the bundle: %v", err)
	}
	described, err := os.Lstat(destination)
	if err != nil || described.Mode() != 0o600 || described.Size() != int64(written) || described.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		t.Fatalf("the bundle was written as %v of %d bytes: %v", described, written, err)
	}
	var bundle diagnostics.Bundle
	content, err := os.ReadFile(destination)
	if err == nil {
		err = json.Unmarshal(content, &bundle)
	}
	var settings map[string]int
	if err == nil {
		err = json.Unmarshal(bundle.Configuration.Held, &settings)
	}
	if err != nil || bundle.Format != diagnostics.Format || bundle.WrittenAt.Before(before) || bundle.Limits.Bytes != diagnostics.MaxBytes ||
		bundle.Limits.Files != diagnostics.MaxFiles || bundle.Limits.LogEntries != diagnostics.MaxEntries || settings["format"] != 1 {
		t.Fatalf("the bundle reads as %+v: %v", bundle, err)
	}
	if held := entries(t, directory); !slices.Equal(held, []string{"bundle.json"}) {
		t.Errorf("writing the bundle left %q", held)
	}
}

func TestABundleNeverReplacesOrFollowsWhatIsAlreadyThere(t *testing.T) {
	directory := shared(t)
	key := filepath.Join(directory, "key.pem")
	if err := os.WriteFile(key, []byte("-----BEGIN PRIVATE KEY-----"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, prepare := range map[string]func(string) error{
		"a file":                 func(path string) error { return os.WriteFile(path, []byte("an operator's notes"), 0o644) },
		"a link to the key":      func(path string) error { return os.Symlink(key, path) },
		"a link to nothing":      func(path string) error { return os.Symlink(filepath.Join(directory, "absent"), path) },
		"a directory":            func(path string) error { return os.Mkdir(path, 0o700) },
		"a pipe":                 func(path string) error { return syscall.Mkfifo(path, 0o600) },
		"a link to a directory ": func(path string) error { return os.Symlink(directory, path) },
	} {
		destination := filepath.Join(directory, strings.ReplaceAll(name, " ", "-"))
		if err := prepare(destination); err != nil {
			t.Fatal(err)
		}
		before, err := os.Lstat(destination)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := diagnostics.Write(destination, diagnostics.Bundle{}); !errors.Is(err, diagnostics.ErrExists) {
			t.Errorf("a bundle written over %s returned %v", name, err)
		}
		if after, err := os.Lstat(destination); err != nil || !os.SameFile(before, after) || after.Mode() != before.Mode() || after.Size() != before.Size() {
			t.Errorf("a bundle written over %s changed it into %v: %v", name, after, err)
		}
	}
	if content, err := os.ReadFile(key); err != nil || string(content) != "-----BEGIN PRIVATE KEY-----" {
		t.Errorf("the key reads as %q: %v", content, err)
	}
	for _, name := range entries(t, directory) {
		if strings.HasSuffix(name, ".tmp") {
			t.Errorf("a refused bundle left %s", name)
		}
	}
}

func TestABundleNeverLandsInTheDirectoryItLists(t *testing.T) {
	state, _ := installation(t)
	deep := filepath.Join(state, "spool", "events", "a", "b", "c", "d", "e", "f", "g", "h")
	if err := os.MkdirAll(deep, 0o700); err != nil {
		t.Fatal(err)
	}
	listed := diagnostics.List(t.Context(), state)
	elsewhere := shared(t)
	through := filepath.Join(elsewhere, "through")
	if err := os.Symlink(filepath.Join(state, "spool"), through); err != nil {
		t.Fatal(err)
	}
	before := tree(t, state)
	for _, destination := range []string{
		filepath.Join(state, "bundle.json"),
		filepath.Join(state, "keys", "bundle.json"),
		filepath.Join(state, "spool", "events", "bundle.json"),
		filepath.Join(through, "events", "bundle.json"),
		filepath.Join(state, "spool", "..", "bundle.json"),
		filepath.Join(deep, "bundle.json"),
	} {
		if _, err := diagnostics.Write(destination, diagnostics.Bundle{Files: listed}); !errors.Is(err, diagnostics.ErrInstallation) {
			t.Errorf("a bundle written to %s returned %v", destination, err)
		}
	}
	if after := tree(t, state); !slices.Equal(before, after) {
		t.Errorf("the installation held %q and holds %q", before, after)
	}
	if _, err := diagnostics.Write(filepath.Join(elsewhere, "bundle.json"), diagnostics.Bundle{Files: listed}); err != nil {
		t.Errorf("a bundle written beside the installation returned %v", err)
	}
}

// When the configuration cannot be read, nobody can tell which installation a
// bundle describes, and the directories the agent keeps as its own are still
// those only its account may enter.
func TestABundleNeverLandsWhereOnlyTheAccountMayEnter(t *testing.T) {
	state, _ := installation(t)
	private := t.TempDir()
	if err := os.Chmod(private, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, destination := range []string{
		filepath.Join(state, "bundle.json"),
		filepath.Join(state, "keys", "bundle.json"),
		filepath.Join(private, "bundle.json"),
	} {
		if _, err := diagnostics.Write(destination, diagnostics.Bundle{}); !errors.Is(err, diagnostics.ErrInstallation) {
			t.Errorf("a bundle of no installation written to %s returned %v", destination, err)
		}
	}
	if held := entries(t, private); len(held) != 0 {
		t.Errorf("a refused bundle left %q", held)
	}
}

func TestABundleThatCannotBeWrittenLeavesNothingBehind(t *testing.T) {
	directory := shared(t)
	for name, destination := range map[string]string{
		"a directory":          directory + "/",
		"the directory itself": filepath.Join(directory, "."),
		"its parent":           filepath.Join(directory, ".."),
		"a missing directory":  filepath.Join(directory, "absent", "bundle.json"),
	} {
		if _, err := diagnostics.Write(destination, diagnostics.Bundle{}); err == nil {
			t.Errorf("a bundle written to %s returned nothing wrong", name)
		}
	}
	tooLarge := diagnostics.Bundle{Status: diagnostics.Took("status", strings.Repeat("x", diagnostics.MaxBytes))}
	if _, err := diagnostics.Write(filepath.Join(directory, "large.json"), tooLarge); err == nil || !strings.Contains(err.Error(), "would hold") {
		t.Errorf("a bundle larger than one may be was written: %v", err)
	}
	if os.Geteuid() != 0 {
		closed := filepath.Join(directory, "closed")
		if err := os.Mkdir(closed, 0o555); err != nil {
			t.Fatal(err)
		}
		if _, err := diagnostics.Write(filepath.Join(closed, "bundle.json"), diagnostics.Bundle{}); !errors.Is(err, fs.ErrPermission) {
			t.Errorf("a bundle written where the account may not write returned %v", err)
		}
		if held := entries(t, closed); len(held) != 0 {
			t.Errorf("a refused bundle left %q", held)
		}
	}
	if held := entries(t, directory); !slices.Equal(held, []string{"closed"}) && len(held) != 0 {
		t.Errorf("bundles that were not written left %q", held)
	}
}

// A bundle is written whole under another name and linked into place, so a
// process killed at any moment leaves at its destination a whole bundle or
// nothing, and at most what it was writing, which no other account reads.
func TestABundleKilledAsItIsWrittenIsWholeOrAbsent(t *testing.T) {
	for round := range 24 {
		directory := shared(t)
		writer := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^$")
		writer.Env = append(os.Environ(), childDirectory+"="+directory)
		said, err := writer.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := writer.Start(); err != nil {
			t.Fatal(err)
		}
		lines := bufio.NewScanner(said)
		if !lines.Scan() || !strings.HasPrefix(lines.Text(), "written") {
			t.Fatalf("round %d: the writer said %q", round, lines.Text())
		}
		time.Sleep(time.Duration(rand.IntN(60)) * time.Millisecond)
		if err := writer.Process.Kill(); err != nil {
			t.Fatal(err)
		}
		writer.Wait()
		for _, name := range entries(t, directory) {
			path := filepath.Join(directory, name)
			described, err := os.Lstat(path)
			if err != nil || described.Mode() != 0o600 {
				t.Errorf("round %d: %s is %v: %v", round, name, described, err)
			}
			if strings.HasPrefix(name, ".") {
				continue
			}
			var bundle diagnostics.Bundle
			content, err := os.ReadFile(path)
			if err == nil {
				err = json.Unmarshal(content, &bundle)
			}
			if err != nil || bundle.Format != diagnostics.Format || len(bundle.Status.Held) < 1<<20 {
				t.Errorf("round %d: %s holds %d bytes that are no whole bundle: %v", round, name, len(content), err)
			}
		}
	}
}

// A directory the account writes in and others may enter, as /var/tmp is: a
// directory only the account may enter is one the agent keeps as its own.
func shared(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	return directory
}

func entries(t *testing.T, directory string) []string {
	t.Helper()
	listed, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range listed {
		names = append(names, entry.Name())
	}
	return names
}

func tree(t *testing.T, directory string) []string {
	t.Helper()
	var held []string
	err := filepath.WalkDir(directory, func(path string, _ fs.DirEntry, err error) error {
		held = append(held, path)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return held
}
