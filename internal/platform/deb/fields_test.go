package deb

import (
	"fmt"
	"testing"
)

// Whatever dpkg-deb writes of a package's fields, what is read is the name,
// version and architecture writing them again reads as.
func FuzzFields(f *testing.F) {
	f.Add([]byte("Package: seagull-agent\nVersion: 0.1.0~rc.1-1\nArchitecture: amd64\n"))
	f.Add([]byte("Version: 1:2.0-1\nArchitecture: all\nPackage: a: b\n"))
	f.Add([]byte("Package: seagull-agent\nDepends: systemd\n"))
	f.Fuzz(func(t *testing.T, written []byte) {
		held, err := fieldsOf(written)
		if err != nil {
			return
		}
		again, err := fieldsOf(fmt.Appendf(nil, "Package: %s\nVersion: %s\nArchitecture: %s\n", held.Package, held.Version, held.Architecture))
		if err != nil || again != held {
			t.Fatalf("the fields %+v were written again as fields that read as %+v: %v", held, again, err)
		}
	})
}
