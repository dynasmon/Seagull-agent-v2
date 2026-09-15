package architecture_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

const (
	modulePath    = "github.com/dynasmon/Seagull-agent-v2"
	contractsPath = "github.com/dynasmon/Seagull-contracts"
	productOwner  = "github.com/dynasmon/"
)

var publishedRelease = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)

// The contracts are the only code the Seagull repositories share. Any other
// path under their owner belongs to the backend, the frontend or a legacy
// agent, and needing one would leave this repository unable to build alone.
func foreign(path string) bool {
	if !strings.HasPrefix(strings.ToLower(path), productOwner) {
		return false
	}
	return !within(path, modulePath) && !within(path, contractsPath)
}

func within(path, root string) bool {
	return path == root || strings.HasPrefix(path, root+"/")
}

func TestForeignProductCodeIsRecognised(t *testing.T) {
	cases := map[string]bool{
		"github.com/dynasmon/Seagull-backend-v2/tests/fixtures":          true,
		"github.com/dynasmon/Seagull-frontend-v2":                        true,
		"github.com/dynasmon/seagull-agent/internal/spool":               true,
		"github.com/Dynasmon/Seagull-backend-v2/tests/fixtures":          true,
		"github.com/dynasmon/Seagull-contracts-fork/gen/go":              true,
		"github.com/dynasmon/Seagull-agent-v2-legacy/cmd":                true,
		"github.com/dynasmon/Seagull-contracts/gen/go/seagull/ingest/v1": false,
		"github.com/dynasmon/Seagull-agent-v2/internal/spool":            false,
		"google.golang.org/protobuf/proto":                               false,
		"net/http":                                                       false,
	}
	for path, want := range cases {
		if got := foreign(path); got != want {
			t.Errorf("foreign(%q) = %t, want %t", path, got, want)
		}
	}
}

func TestNoSourceImportsAnotherSeagullImplementation(t *testing.T) {
	root := moduleRoot(t)
	files := token.NewFileSet()
	for _, source := range goSources(t, root) {
		parsed, err := parser.ParseFile(files, source, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", relative(root, source), err)
		}
		for _, spec := range parsed.Imports {
			imported, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatalf("read an import of %s: %v", relative(root, source), err)
			}
			if foreign(imported) {
				t.Errorf("%s imports %s: only %s may be shared with another Seagull repository",
					relative(root, source), imported, contractsPath)
			}
		}
	}
}

type goModule struct {
	Module struct {
		Path string
	}
	Require []struct {
		Path    string
		Version string
	}
	Replace []struct {
		Old struct {
			Path string
		}
		New struct {
			Path    string
			Version string
		}
	}
}

func TestTheModuleBuildsFromPublishedModulesAlone(t *testing.T) {
	root := moduleRoot(t)
	var described goModule
	if err := json.Unmarshal(run(t, root, "go", "mod", "edit", "-json"), &described); err != nil {
		t.Fatalf("decode the go.mod description: %v", err)
	}

	if described.Module.Path != modulePath {
		t.Errorf("go.mod declares %s, the repository publishes %s", described.Module.Path, modulePath)
	}
	for _, replacement := range described.Replace {
		t.Errorf("go.mod replaces %s with %s: the build uses modules as they were published, never a sibling checkout or a fork",
			replacement.Old.Path, strings.TrimSpace(replacement.New.Path+" "+replacement.New.Version))
	}
	for _, requirement := range described.Require {
		switch {
		case requirement.Path == contractsPath && !publishedRelease.MatchString(requirement.Version):
			t.Errorf("go.mod requires %s at %s: depend on a published release of the contracts",
				contractsPath, requirement.Version)
		case foreign(requirement.Path):
			t.Errorf("go.mod requires %s: only %s may be shared with another Seagull repository",
				requirement.Path, contractsPath)
		}
	}

	_, err := os.Lstat(filepath.Join(root, ".gitmodules"))
	switch {
	case err == nil:
		t.Error("the repository declares submodules: no other checkout may be needed to build it")
	case !errors.Is(err, fs.ErrNotExist):
		t.Fatalf("inspect .gitmodules: %v", err)
	}
}

func ignoredByGo(name string) bool {
	return strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") || name == "testdata"
}

func goSources(t *testing.T, root string) []string {
	t.Helper()
	var sources []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path != root && ignoredByGo(entry.Name()) {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if !entry.IsDir() && filepath.Ext(path) == ".go" {
			sources = append(sources, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk the sources: %v", err)
	}
	return sources
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve the module root: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("find the module root: %v", err)
	}
	return root
}

func relative(root, path string) string {
	name, err := filepath.Rel(root, path)
	if err != nil {
		return path
	}
	return filepath.ToSlash(name)
}

func run(t *testing.T, dir, name string, args ...string) []byte {
	t.Helper()
	return runWith(t, dir, nil, name, args...)
}

func runWith(t *testing.T, dir string, env []string, name string, args ...string) []byte {
	t.Helper()
	command := exec.CommandContext(t.Context(), name, args...)
	command.Dir = dir
	command.Env = append(append(os.Environ(), "GOWORK=off"), env...)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	output, err := command.Output()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return output
}
