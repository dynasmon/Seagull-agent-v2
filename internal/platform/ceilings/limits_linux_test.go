//go:build linux

package ceilings

import (
	"os"
	"path/filepath"
	"testing"
)

// Whatever a cgroup says of its memory, tasks and processors, a ceiling read
// from it is a positive amount it wrote, none when it says max or nothing, or
// the cgroup is refused as one that does not read.
func FuzzLimits(f *testing.F) {
	f.Add("536870912\n", "256\n", "50000 100000\n")
	f.Add("max\n", "max\n", "max 100000\n")
	f.Add("0\n", "-1\n", "100000 0\n")
	f.Add("", "", "")
	f.Fuzz(func(t *testing.T, memory, tasks, cpus string) {
		directory := t.TempDir()
		for name, content := range map[string]string{"memory.max": memory, "pids.max": tasks, "cpu.max": cpus} {
			if err := os.WriteFile(filepath.Join(directory, name), []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		root, err := os.OpenRoot(directory)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		for name := range map[string]bool{"memory.max": true, "pids.max": true} {
			if held, err := quantity(root, ".", name); err == nil && held < 0 {
				t.Fatalf("%s was read as %d", name, held)
			}
		}
		if held, err := processors(root, "."); err == nil && (held < 0 || held != held) {
			t.Fatalf("cpu.max %q was read as %v processors", cpus, held)
		}
	})
}
