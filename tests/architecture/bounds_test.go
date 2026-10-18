package architecture_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"slices"
	"strings"
	"testing"
)

// What reads a file or a stream whole, whatever it holds. The agent reads what
// another account, a program or the platform wrote, so it reads through a bound
// it chose: a limited reader, a scanner given its buffer, or bytes it already
// holds.
var readsWhole = map[string][]string{"os": {"ReadFile"}, "ioutil": {"ReadFile", "ReadAll"}}

// What decodes a Protobuf message without counting what it holds. Decoding costs
// memory for every value a message holds rather than for every byte, so the
// agent decodes through protocol.Decode alone, which counts them first.
var decodesWhole = map[string][]string{"proto": {"Unmarshal", "UnmarshalOptions"}, "protojson": {"Unmarshal", "UnmarshalOptions"}, "prototext": {"Unmarshal", "UnmarshalOptions"}}

const counting = "internal/protocol/decode.go"

func called(expression ast.Expr, names map[string][]string) bool {
	selector, ok := expression.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	held, ok := selector.X.(*ast.Ident)
	return ok && slices.Contains(names[held.Name], selector.Sel.Name)
}

func callOf(expression ast.Expr, pkg string, names ...string) bool {
	call, ok := expression.(*ast.CallExpr)
	return ok && called(call.Fun, map[string][]string{pkg: names})
}

func unboundedReads(file *ast.File) []token.Pos {
	var found []token.Pos
	ast.Inspect(file, func(node ast.Node) bool {
		var body *ast.BlockStmt
		switch held := node.(type) {
		case *ast.FuncDecl:
			body = held.Body
		case *ast.FuncLit:
			body = held.Body
		case *ast.CallExpr:
			switch {
			case called(held.Fun, readsWhole):
				found = append(found, held.Pos())
			case called(held.Fun, map[string][]string{"io": {"ReadAll"}}) && (len(held.Args) != 1 || !callOf(held.Args[0], "io", "LimitReader")):
				found = append(found, held.Pos())
			case called(held.Fun, map[string][]string{"json": {"NewDecoder"}}) && (len(held.Args) != 1 || !callOf(held.Args[0], "bytes", "NewReader") && !callOf(held.Args[0], "strings", "NewReader")):
				found = append(found, held.Pos())
			}
			if selector, ok := held.Fun.(*ast.SelectorExpr); ok && (selector.Sel.Name == "ReadString" || selector.Sel.Name == "ReadBytes") {
				found = append(found, held.Pos())
			}
		}
		if body != nil {
			found = append(found, unbufferedScanners(body)...)
		}
		return true
	})
	slices.Sort(found)
	return slices.Compact(found)
}

func unbufferedScanners(body *ast.BlockStmt) []token.Pos {
	scanners, buffered := map[string]token.Pos{}, map[string]bool{}
	ast.Inspect(body, func(node ast.Node) bool {
		switch held := node.(type) {
		case *ast.FuncLit:
			return false
		case *ast.AssignStmt:
			for i, value := range held.Rhs {
				if name, ok := held.Lhs[min(i, len(held.Lhs)-1)].(*ast.Ident); ok && callOf(value, "bufio", "NewScanner") {
					scanners[name.Name] = value.Pos()
				}
			}
		case *ast.CallExpr:
			if selector, ok := held.Fun.(*ast.SelectorExpr); ok && selector.Sel.Name == "Buffer" {
				if name, ok := selector.X.(*ast.Ident); ok {
					buffered[name.Name] = true
				}
			}
		}
		return true
	})
	var found []token.Pos
	for name, position := range scanners {
		if !buffered[name] {
			found = append(found, position)
		}
	}
	return found
}

func uncountedDecodes(file *ast.File) []token.Pos {
	var found []token.Pos
	ast.Inspect(file, func(node ast.Node) bool {
		switch held := node.(type) {
		case *ast.CallExpr:
			if called(held.Fun, decodesWhole) {
				found = append(found, held.Pos())
			}
		case *ast.CompositeLit:
			if called(held.Type, decodesWhole) {
				found = append(found, held.Pos())
			}
		}
		return true
	})
	return found
}

func TestReadingWithoutABoundIsRecognised(t *testing.T) {
	cases := map[string]int{
		`package p; import "os"; func f() ([]byte, error) { return os.ReadFile("/etc/seagull-agent/agent.json") }`:                                         1,
		`package p; import ("io"; "os"); func f(file *os.File) ([]byte, error) { return io.ReadAll(file) }`:                                                1,
		`package p; import ("io"; "os"); func f(file *os.File) ([]byte, error) { return io.ReadAll(io.LimitReader(file, 1<<20)) }`:                         0,
		`package p; import ("encoding/json"; "os"); func f(file *os.File, v any) error { return json.NewDecoder(file).Decode(v) }`:                         1,
		`package p; import ("bytes"; "encoding/json"); func f(content []byte, v any) error { return json.NewDecoder(bytes.NewReader(content)).Decode(v) }`: 0,
		`package p; import ("bufio"; "io"); func f(r io.Reader) { lines := bufio.NewScanner(r); for lines.Scan() {} }`:                                     1,
		`package p; import ("bufio"; "io"); func f(r io.Reader) { lines := bufio.NewScanner(r); lines.Buffer(nil, 4096); for lines.Scan() {} }`:            0,
		`package p; import ("bufio"; "io"); func f(r io.Reader) (string, error) { return bufio.NewReader(r).ReadString('\n') }`:                            1,
		`package p; import ("io"; "io/ioutil"); func f(r io.Reader) ([]byte, error) { return ioutil.ReadAll(r) }`:                                          1,
	}
	for source, want := range cases {
		file, err := parser.ParseFile(token.NewFileSet(), "p.go", source, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %q: %v", source, err)
		}
		if found := len(unboundedReads(file)); found != want {
			t.Errorf("%q: found %d unbounded reads, want %d", source, found, want)
		}
	}
}

func TestDecodingWithoutCountingIsRecognised(t *testing.T) {
	cases := map[string]int{
		`package p; import "google.golang.org/protobuf/proto"; func f(b []byte, m proto.Message) error { return proto.Unmarshal(b, m) }`:                                        1,
		`package p; import "google.golang.org/protobuf/proto"; func f(b []byte, m proto.Message) error { return proto.UnmarshalOptions{DiscardUnknown: true}.Unmarshal(b, m) }`: 1,
		`package p; import "google.golang.org/protobuf/encoding/protojson"; func f(b []byte, m any) error { return protojson.Unmarshal(b, nil) }`:                               1,
		`package p; import "google.golang.org/protobuf/proto"; func f(m proto.Message) ([]byte, error) { return proto.Marshal(m) }`:                                             0,
		`package p; func f(b []byte, m any) error { return protocol.Decode(b, m, 1024) }`:                                                                                       0,
	}
	for source, want := range cases {
		file, err := parser.ParseFile(token.NewFileSet(), "p.go", source, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %q: %v", source, err)
		}
		if found := len(uncountedDecodes(file)); found != want {
			t.Errorf("%q: found %d uncounted decodes, want %d", source, found, want)
		}
	}
}

func TestTheAgentReadsAndDecodesOnlyWithinBounds(t *testing.T) {
	root := moduleRoot(t)
	files := token.NewFileSet()
	for _, source := range goSources(t, root) {
		name := relative(root, source)
		if strings.HasSuffix(name, "_test.go") || !strings.HasPrefix(name, "cmd/") && !strings.HasPrefix(name, "internal/") {
			continue
		}
		parsed, err := parser.ParseFile(files, source, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, position := range unboundedReads(parsed) {
			t.Errorf("%s:%d reads without a bound: read through io.LimitReader, give a scanner its buffer, or decode bytes already held", name, files.Position(position).Line)
		}
		if name == counting {
			continue
		}
		for _, position := range uncountedDecodes(parsed) {
			t.Errorf("%s:%d decodes a message without counting its values: decode it through protocol.Decode", name, files.Position(position).Line)
		}
	}
}
