package sockets

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// Whatever the link of a process to its network namespace says, it names a
// namespace only as procfs writes one.
func FuzzIdentified(f *testing.F) {
	for _, seed := range []string{"net:[4026531840]", "net:[]", "mnt:[4026531841]", "net:[4026531840", "net:[-1]", "net:[01]"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, target string) {
		root := t.TempDir()
		if err := os.MkdirAll(filepath.Join(root, "42", "ns"), 0o755); err != nil {
			t.Fatal(err)
		}
		if os.Symlink(target, filepath.Join(root, "42", "ns", "net")) != nil {
			return
		}
		named := identified(root, "42")
		if named == "" {
			return
		}
		number, err := strconv.ParseUint(named[len("net:["):len(named)-1], 10, 64)
		if err != nil || named != "net:["+strconv.FormatUint(number, 10)+"]" {
			t.Fatalf("%q was taken for namespace %q", target, named)
		}
	})
}
