package kmod

import (
	"path/filepath"
	"strings"
	"testing"
)

// A module is named by a policy the agent was handed: whatever the name, the
// one the agent looks for is a single name within /sys/module, and naming it
// again names the same module.
func FuzzName(f *testing.F) {
	for _, seed := range []string{"usb-storage", "cramfs", "..", "../../etc", "a/b", "", strings.Repeat("x", 56)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, name string) {
		normal, err := Name(name)
		if err != nil {
			return
		}
		if again, err := Name(normal); err != nil || again != normal {
			t.Fatalf("module %q is named %q, which is named %q: %v", name, normal, again, err)
		}
		if filepath.Dir(filepath.Join(sysModule, normal)) != sysModule || normal == ".." || normal == "." {
			t.Fatalf("module %q is looked for at %s", name, filepath.Join(sysModule, normal))
		}
	})
}
