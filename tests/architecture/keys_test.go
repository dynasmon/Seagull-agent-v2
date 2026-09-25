package architecture_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const keyProvider = "internal/pki"

// What draws a private key, writes one out or reads one in. The key provider
// alone does any of it, so no other code holds a key it could write down, send
// or hand over, and a certificate request carries the public half of a key
// that never leaves the provider.
var keyMaterial = []string{
	"GenerateKey",
	"MarshalPKCS8PrivateKey", "MarshalECPrivateKey", "MarshalPKCS1PrivateKey",
	"ParsePKCS8PrivateKey", "ParseECPrivateKey", "ParsePKCS1PrivateKey",
}

func handlesKeys(file *ast.File) []token.Pos {
	var found []token.Pos
	ast.Inspect(file, func(node ast.Node) bool {
		if selected, ok := node.(*ast.SelectorExpr); ok && slices.Contains(keyMaterial, selected.Sel.Name) {
			found = append(found, selected.Pos())
		}
		return true
	})
	return found
}

func TestHandlingAPrivateKeyIsRecognised(t *testing.T) {
	cases := map[string]int{
		`package p; import ("crypto/ecdsa"; "crypto/elliptic"; "crypto/rand"); func f() { ecdsa.GenerateKey(elliptic.P256(), rand.Reader) }`: 1,
		`package p; import ("crypto/ecdh"; "crypto/rand"); func f() { ecdh.P256().GenerateKey(rand.Reader) }`:                                1,
		`package p; import "crypto/x509"; func f(k any) ([]byte, error) { return x509.MarshalPKCS8PrivateKey(k) }`:                           1,
		`package p; import "crypto/x509"; func f(b []byte) (any, error) { return x509.ParseECPrivateKey(b) }`:                                1,
		`package p; import "crypto/x509"; func f(b []byte) (any, error) { return x509.ParsePKIXPublicKey(b) }`:                               0,
		`package p; import "crypto/x509"; func f(k any) ([]byte, error) { return x509.MarshalPKIXPublicKey(k) }`:                             0,
	}
	for source, want := range cases {
		file, err := parser.ParseFile(token.NewFileSet(), "p.go", source, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %q: %v", source, err)
		}
		if found := len(handlesKeys(file)); found != want {
			t.Errorf("%q: found %d, want %d", source, found, want)
		}
	}
}

func TestOnlyTheKeyProviderDrawsWritesOrReadsAPrivateKey(t *testing.T) {
	root := moduleRoot(t)
	files := token.NewFileSet()
	for _, source := range goSources(t, root) {
		name := relative(root, source)
		if strings.HasSuffix(source, "_test.go") || within(filepath.ToSlash(filepath.Dir(name)), keyProvider) {
			continue
		}
		parsed, err := parser.ParseFile(files, source, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, position := range handlesKeys(parsed) {
			t.Errorf("%s:%d draws, writes or reads a private key: keys are held by the provider in %s and used through crypto.Signer alone",
				name, files.Position(position).Line, keyProvider)
		}
	}
}
