//go:build linux

package ceilings

import (
	"path"
	"strings"
	"testing"
)

// Whatever /proc/self/cgroup says, the cgroup the agent walks up from is one
// within the hierarchy it opened, never a path out of it.
func FuzzMember(f *testing.F) {
	for _, seed := range []string{"0::/system.slice/seagull-agent.service\n", "0::/\n", "1:name=systemd:/\n0::/user.slice/../..\n", "0::relative\n", "12:pids:/a\n"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, content string) {
		leaf, err := member(content)
		if err != nil {
			return
		}
		if leaf != "." && (path.Clean(leaf) != leaf || path.IsAbs(leaf) || leaf == ".." || strings.HasPrefix(leaf, "../")) {
			t.Fatalf("%q names the cgroup %q, which leads out of the hierarchy", content, leaf)
		}
	})
}
