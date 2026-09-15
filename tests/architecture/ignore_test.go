package architecture_test

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// Sources that do not exist yet but whose names a careless runtime-artifact
// pattern, such as spool/ for a local spool directory, would hide from Git.
var plannedSources = []string{
	"internal/spool/spool.go",
	"internal/spool/testdata/fuzz/FuzzRecover/582528ddfad69eb5",
}

var localOnly = []string{"go.work", "go.work.sum", ".agents/skills", ".claude/skills"}

func TestIgnoreRulesHideNoSourceOrFixture(t *testing.T) {
	root := moduleRoot(t)
	requireWorkTree(t, root)

	visible := append(sourcesAndFixtures(t, root), plannedSources...)
	for _, name := range ignoredByGit(t, root, visible) {
		t.Errorf("git ignores %s: ignore runtime artifacts with anchored patterns that cannot match a source package or a fixture", name)
	}
}

func TestLocalOnlyFilesStayOutOfGit(t *testing.T) {
	root := moduleRoot(t)
	requireWorkTree(t, root)

	tracked := run(t, root, "git", "ls-files", "-z", "--", "go.work", "go.work.sum", ".agents", ".claude/skills")
	for name := range strings.SplitSeq(strings.TrimSuffix(string(tracked), "\x00"), "\x00") {
		if name != "" {
			t.Errorf("git tracks %s: a workspace and the local skills stay on the machine that holds them", name)
		}
	}
	ignored := ignoredByGit(t, root, localOnly)
	for _, name := range localOnly {
		if !slices.Contains(ignored, name) {
			t.Errorf("git does not ignore %s: it could be committed by accident", name)
		}
	}
}

func sourcesAndFixtures(t *testing.T, root string) []string {
	t.Helper()
	var names []string
	err := filepath.WalkDir(root, func(file string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if file != root && (strings.HasPrefix(entry.Name(), ".") || strings.HasPrefix(entry.Name(), "_")) {
				return filepath.SkipDir
			}
			return nil
		}
		name := relative(root, file)
		base := path.Base(name)
		if path.Ext(base) == ".go" || base == "go.mod" || base == "go.sum" || slices.Contains(strings.Split(path.Dir(name), "/"), "testdata") {
			names = append(names, name)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk the sources: %v", err)
	}
	return names
}

func requireWorkTree(t *testing.T, root string) {
	t.Helper()
	command := exec.CommandContext(t.Context(), "git", "rev-parse", "--is-inside-work-tree")
	command.Dir = root
	output, err := command.Output()
	if err == nil && strings.TrimSpace(string(output)) == "true" {
		return
	}
	if os.Getenv("CI") != "" {
		t.Fatalf("CI must verify the ignore rules from a git work tree: %v", err)
	}
	t.Skip("the sources are not a git work tree, so there are no ignore rules to verify")
}

func ignoredByGit(t *testing.T, root string, names []string) []string {
	t.Helper()
	command := exec.CommandContext(t.Context(), "git", "-c", "core.excludesFile="+os.DevNull,
		"check-ignore", "--no-index", "--stdin", "-z")
	command.Dir = root
	command.Stdin = strings.NewReader(strings.Join(names, "\x00") + "\x00")
	var stderr bytes.Buffer
	command.Stderr = &stderr
	output, err := command.Output()
	var exit *exec.ExitError
	switch {
	case errors.As(err, &exit) && exit.ExitCode() == 1:
		return nil
	case err != nil:
		t.Fatalf("git check-ignore: %v\n%s", err, strings.TrimSpace(stderr.String()))
	}
	return strings.Split(strings.TrimSuffix(string(output), "\x00"), "\x00")
}
