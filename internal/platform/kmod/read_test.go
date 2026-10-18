package kmod

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

// Whatever the files modprobe reads hold, the install and blacklist rules read
// from them are what writing them again, one line each that a backslash cannot
// carry on to the next, reads as.
func FuzzRead(f *testing.F) {
	f.Add("# a comment\ninstall usb-storage /bin/false\nblacklist cramfs\ninstall dccp \\\n /bin/true\noptions snd-hda-intel model=auto\n")
	f.Add("install [a-z]-mod /bin/false # keep it out\nblacklist\nalias net-pf-33 off\n\\")
	f.Fuzz(func(t *testing.T, content string) {
		var held Configuration
		held.read("modprobe.conf", content)
		lines := strings.Count(content, "\n") + 1
		var again strings.Builder
		for _, rule := range held.install {
			if rule.Line < 1 || rule.Line > lines || rule.Command == "" || rule.Module != underscores(rule.Module) {
				t.Fatalf("an install rule was read as %+v", rule)
			}
			fmt.Fprintf(&again, "install %s %s \n", rule.Module, rule.Command)
		}
		for _, rule := range held.blacklist {
			if rule.Line < 1 || rule.Line > lines || rule.Module != underscores(rule.Module) {
				t.Fatalf("a blacklist rule was read as %+v", rule)
			}
			fmt.Fprintf(&again, "blacklist %s \n", rule.Module)
		}
		var reread Configuration
		reread.read("modprobe.conf", again.String())
		same := func(a, b Rule) bool { return a.Module == b.Module && a.Command == b.Command }
		if !slices.EqualFunc(reread.install, held.install, same) || !slices.EqualFunc(reread.blacklist, held.blacklist, same) {
			t.Fatalf("the rules read were written again as %q, which reads as other rules", again.String())
		}
	})
}
