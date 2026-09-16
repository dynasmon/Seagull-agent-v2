package architecture_test

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// What a message crossing the wire is made of: generated bindings, descriptors
// built at run time, or the protobuf APIs that predate them. The agent sends and
// reads only what the published contracts define, so it needs none of these.
var wireDefinitions = []string{
	"google.golang.org/protobuf/runtime/protoimpl",
	"google.golang.org/protobuf/reflect/protodesc",
	"google.golang.org/protobuf/types/dynamicpb",
	"github.com/golang/protobuf",
	"github.com/gogo/protobuf",
}

func definesWireMessages(path string) bool {
	return slices.ContainsFunc(wireDefinitions, func(definition string) bool { return within(path, definition) })
}

func TestWireDefinitionsAreRecognised(t *testing.T) {
	cases := map[string]bool{
		"google.golang.org/protobuf/runtime/protoimpl":    true,
		"google.golang.org/protobuf/reflect/protodesc":    true,
		"google.golang.org/protobuf/types/dynamicpb":      true,
		"github.com/golang/protobuf/proto":                true,
		"github.com/gogo/protobuf/protoc-gen-gogo":        true,
		"google.golang.org/protobuf/proto":                false,
		"google.golang.org/protobuf/reflect/protoreflect": false,
		"google.golang.org/protobuf/encoding/protowire":   false,
		contractsPath + "/gen/go/seagull/ingest/v1":       false,
	}
	for path, want := range cases {
		if got := definesWireMessages(path); got != want {
			t.Errorf("definesWireMessages(%q) = %t, want %t", path, got, want)
		}
	}
}

func TestOnlyThePublishedContractsDefineWhatCrossesTheWire(t *testing.T) {
	root := moduleRoot(t)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() && path != root && strings.HasPrefix(entry.Name(), ".") {
			return filepath.SkipDir
		}
		if !entry.IsDir() && filepath.Ext(path) == ".proto" {
			t.Errorf("%s defines protobuf messages: a message the agent sends or reads belongs in %s, where the platform can consume it",
				relative(root, path), contractsPath)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk the repository: %v", err)
	}

	files := token.NewFileSet()
	for _, source := range goSources(t, root) {
		if strings.HasSuffix(source, "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(files, source, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", relative(root, source), err)
		}
		for _, spec := range parsed.Imports {
			imported, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatalf("read an import of %s: %v", relative(root, source), err)
			}
			if definesWireMessages(imported) {
				t.Errorf("%s imports %s: the agent speaks only the messages %s publishes, and adds no handshake or envelope of its own",
					relative(root, source), imported, contractsPath)
			}
		}
	}
}
