package architecture_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// What procfs keeps of what a process was started with: its arguments and its
// environment, which carry whatever whoever started it put there, a password
// among them. The agent names neither file of any process, so it reads neither.
var startedWith = []string{"cmdline", "environ"}

func namesWhatAProcessWasStartedWith(file *ast.File) []token.Pos {
	var found []token.Pos
	ast.Inspect(file, func(node ast.Node) bool {
		literal, ok := node.(*ast.BasicLit)
		if !ok || literal.Kind != token.STRING {
			return true
		}
		value, err := strconv.Unquote(literal.Value)
		if err != nil {
			return true
		}
		if slices.ContainsFunc(strings.Split(value, "/"), func(element string) bool { return slices.Contains(startedWith, element) }) {
			found = append(found, literal.Pos())
		}
		return true
	})
	return found
}

func TestNamingWhatAProcessWasStartedWithIsRecognised(t *testing.T) {
	cases := map[string]int{
		`package p; import "os"; func f() ([]byte, error) { return os.ReadFile("/proc/self/cmdline") }`:                      1,
		`package p; import "os"; func f(root *os.Root, pid string) (*os.File, error) { return root.Open(pid + "/environ") }`: 1,
		"package p; import \"path/filepath\"; func f(pid string) string { return filepath.Join(\"/proc\", pid, `cmdline`) }": 1,
		`package p; const said = "the agent sends no command line and reads no environment"`:                                 0,
		`package p; import "os"; func f() ([]byte, error) { return os.ReadFile("/proc/self/stat") }`:                         0,
	}
	for source, want := range cases {
		file, err := parser.ParseFile(token.NewFileSet(), "p.go", source, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %q: %v", source, err)
		}
		if found := len(namesWhatAProcessWasStartedWith(file)); found != want {
			t.Errorf("%q: found %d names of what a process was started with, want %d", source, found, want)
		}
	}
}

func TestNoProductionCodeNamesWhatAProcessWasStartedWith(t *testing.T) {
	root := moduleRoot(t)
	files := token.NewFileSet()
	for _, source := range goSources(t, root) {
		if strings.HasSuffix(source, "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(files, source, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", relative(root, source), err)
		}
		for _, position := range namesWhatAProcessWasStartedWith(parsed) {
			t.Errorf("%s:%d names the arguments or the environment of a process: the agent takes stock of what runs without what it was started with, which is nobody's to send",
				relative(root, source), files.Position(position).Line)
		}
	}
}
