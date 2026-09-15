package architecture_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

func recoveries(file *ast.File) []token.Pos {
	var found []token.Pos
	ast.Inspect(file, func(node ast.Node) bool {
		if call, ok := node.(*ast.CallExpr); ok {
			if name, ok := call.Fun.(*ast.Ident); ok && name.Name == "recover" && len(call.Args) == 0 {
				found = append(found, call.Pos())
			}
		}
		return true
	})
	return found
}

func TestRecoveryIsRecognised(t *testing.T) {
	cases := map[string]int{
		`package p; func f() { defer func() { recover() }() }`:                                             1,
		`package p; func f() { defer func() { if r := recover(); r != nil { panic(r) } }() }`:              1,
		`package p; func f() { defer recover(); defer func() { _ = recover() }() }`:                        2,
		`package p; type journal struct{}; func (journal) recover() {}; func f(j journal) { j.recover() }`: 0,
		`package p; func f() { panic("state is inconsistent") }`:                                           0,
	}
	for source, want := range cases {
		file, err := parser.ParseFile(token.NewFileSet(), "p.go", source, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %q: %v", source, err)
		}
		if found := len(recoveries(file)); found != want {
			t.Errorf("%q: found %d recoveries, want %d", source, found, want)
		}
	}
}

func TestNoProductionCodeRecoversFromAPanic(t *testing.T) {
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
		for _, position := range recoveries(parsed) {
			t.Errorf("%s:%d recovers from a panic: the goroutine may have left shared state inconsistent, so let the panic end the process",
				relative(root, source), files.Position(position).Line)
		}
	}
}
