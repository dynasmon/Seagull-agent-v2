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

// What procfs keeps of a process that is nobody's to read: the arguments and
// the environment it was started with, which carry whatever whoever started it
// put there, a password among them, and its memory, which an operator lets the
// agent read when it lets it name the process that holds a socket. The agent
// names none of these files of any process, so it reads none of them.
var startedWith = []string{"cmdline", "environ", "mem"}

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
		`package p; import "os"; func f(pid string) (*os.File, error) { return os.Open("/proc/" + pid + "/mem") }`:           1,
		`package p; import "os"; func f() ([]byte, error) { return os.ReadFile("/proc/meminfo") }`:                           0,
		`package p; import "os"; func f(root *os.Root) (string, error) { return root.Readlink("fd/3") }`:                     0,
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
			t.Errorf("%s:%d names the arguments, the environment or the memory of a process: the agent takes stock of what runs without what it was started with or holds, which is nobody's to send",
				relative(root, source), files.Position(position).Line)
		}
	}
}
