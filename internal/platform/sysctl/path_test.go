package sysctl

import (
	"path/filepath"
	"strings"
	"testing"
)

// A parameter is named by a policy the agent was handed: whatever the name,
// the file read for it is one within /proc/sys, one component per component
// of the name.
func FuzzPath(f *testing.F) {
	for _, seed := range []string{"net.ipv4.ip_forward", "net.ipv4.conf.eth0/100.rp_filter", "kernel.randomize_va_space", "..", "net/../../etc.shadow", "a..b", "-.-"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, name string) {
		held, err := Path(name)
		if err != nil {
			return
		}
		within, err := filepath.Rel(root, held)
		if err != nil || within == ".." || strings.HasPrefix(within, "../") || filepath.Clean(held) != held ||
			len(strings.Split(within, string(filepath.Separator))) != len(strings.Split(name, ".")) {
			t.Fatalf("parameter %q is read from %s", name, held)
		}
	})
}
