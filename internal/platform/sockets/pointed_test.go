package sockets

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// Whatever a descriptor links to, it is taken for a socket only when it names
// one by its inode as procfs writes it.
func FuzzPointed(f *testing.F) {
	for _, seed := range []string{"socket:[4026531993]", "socket:[0]", "pipe:[12]", "socket:[18446744073709551616]", "socket:[ 7]", "socket:[7]x"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, target string) {
		if inode, ok := pointed(target); ok && (inode == 0 || target != "socket:["+strconv.FormatUint(inode, 10)+"]") {
			t.Fatalf("%q was taken for socket %d", target, inode)
		}
	})
}

// Whatever procfs says the boot is, it is told only as a boot identifier.
func FuzzBooted(f *testing.F) {
	for _, seed := range []string{"3f1c2b4a-5d6e-4f70-8192-a3b4c5d6e7f8\n", "", "../../etc/passwd", "3F1C2B4A-5D6E-4F70-8192-A3B4C5D6E7F8"} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, content []byte) {
		directory := t.TempDir()
		if err := os.MkdirAll(filepath.Join(directory, "sys", "kernel", "random"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "sys", "kernel", "random", "boot_id"), content, 0o644); err != nil {
			t.Fatal(err)
		}
		held, err := os.OpenRoot(directory)
		if err != nil {
			t.Fatal(err)
		}
		defer held.Close()
		if told := booted(held); told != "" && (len(told) != 36 || told[8] != '-' || told[13] != '-' || told[18] != '-' || told[23] != '-') {
			t.Fatalf("%q was told as boot %q", content, told)
		}
	})
}
