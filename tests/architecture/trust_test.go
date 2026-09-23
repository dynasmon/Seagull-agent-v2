package architecture_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"slices"
	"strings"
	"testing"
)

// What would let the agent send to a platform it did not authenticate, or let
// the environment it was started in choose a proxy for it: the defaults of
// net/http follow the proxy variables of the environment and bound nothing.
var (
	unverified = "InsecureSkipVerify"
	implicit   = []string{"DefaultClient", "DefaultTransport", "ProxyFromEnvironment", "Get", "Head", "Post", "PostForm"}
)

func trustsUnverified(file *ast.File) []token.Pos {
	var found []token.Pos
	ast.Inspect(file, func(node ast.Node) bool {
		switch held := node.(type) {
		case *ast.Ident:
			if held.Name == unverified {
				found = append(found, held.Pos())
			}
		case *ast.SelectorExpr:
			if named, ok := held.X.(*ast.Ident); ok && named.Name == "http" && slices.Contains(implicit, held.Sel.Name) {
				found = append(found, held.Pos())
			}
		}
		return true
	})
	return found
}

func TestTrustingAnUnverifiedPlatformIsRecognised(t *testing.T) {
	cases := map[string]int{
		`package p; import "crypto/tls"; var c = &tls.Config{InsecureSkipVerify: true}`:                                 1,
		`package p; import "crypto/tls"; func f(c *tls.Config) { c.InsecureSkipVerify = true }`:                         1,
		`package p; import "net/http"; func f() (*http.Response, error) { return http.Get("https://gateway.example") }`: 1,
		`package p; import "net/http"; var t = &http.Transport{Proxy: http.ProxyFromEnvironment}`:                       1,
		`package p; import "net/http"; func f(r *http.Request) { http.DefaultClient.Do(r) }`:                            1,
		`package p; import "crypto/tls"; var c = &tls.Config{MinVersion: tls.VersionTLS13}`:                             0,
		`package p; import "net/http"; var t = &http.Transport{Proxy: nil}; var m = http.MethodPost`:                    0,
	}
	for source, want := range cases {
		file, err := parser.ParseFile(token.NewFileSet(), "p.go", source, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %q: %v", source, err)
		}
		if found := len(trustsUnverified(file)); found != want {
			t.Errorf("%q: found %d, want %d", source, found, want)
		}
	}
}

func TestNoProductionCodeTrustsAPlatformItDidNotAuthenticate(t *testing.T) {
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
		for _, position := range trustsUnverified(parsed) {
			t.Errorf("%s:%d skips verifying the platform or lets the environment choose how to reach it: the agent sends only to a platform it authenticated, over a client whose every bound it set",
				relative(root, source), files.Position(position).Line)
		}
	}
}
