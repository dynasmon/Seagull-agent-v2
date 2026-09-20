package architecture_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"slices"
	"strings"
	"testing"
)

// What a process reads of the environment it was started in. An operator who
// writes a credential there writes it where every child process and, on some
// systems, every account can read it, so the agent reads none of it.
var environment = []string{"Getenv", "LookupEnv", "Environ", "ExpandEnv"}

func readsTheEnvironment(file *ast.File) []token.Pos {
	var found []token.Pos
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		read, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if held, ok := read.X.(*ast.Ident); ok && held.Name == "os" && slices.Contains(environment, read.Sel.Name) {
			found = append(found, call.Pos())
		}
		return true
	})
	return found
}

func TestReadingTheEnvironmentIsRecognised(t *testing.T) {
	cases := map[string]int{
		`package p; import "os"; func f() string { return os.Getenv("SEAGULL_TOKEN") }`:                      1,
		`package p; import "os"; func f() (string, bool) { return os.LookupEnv("SEAGULL_TOKEN") }`:           1,
		`package p; import "os"; func f() []string { return append(os.Environ(), os.ExpandEnv("$HOME")) }`:   2,
		`package p; import "os"; func f() ([]byte, error) { return os.ReadFile("/etc/seagull-agent.json") }`: 0,
		`package p; type settings struct{}; func (settings) Getenv(string) string { return "" }`:             0,
	}
	for source, want := range cases {
		file, err := parser.ParseFile(token.NewFileSet(), "p.go", source, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %q: %v", source, err)
		}
		if found := len(readsTheEnvironment(file)); found != want {
			t.Errorf("%q: found %d reads of the environment, want %d", source, found, want)
		}
	}
}

func TestNoProductionCodeReadsTheEnvironmentItWasStartedIn(t *testing.T) {
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
		for _, position := range readsTheEnvironment(parsed) {
			t.Errorf("%s:%d reads the environment the agent was started in: the agent runs on the file it is given, and a secret written into a variable would reach its log, its state or the platform",
				relative(root, source), files.Position(position).Line)
		}
	}
}
