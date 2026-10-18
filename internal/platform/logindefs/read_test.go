package logindefs

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Whatever login.defs holds, each item read is named without white space and
// valued without a quote, as the shadow utilities read it, and is what writing
// it again on a line of its own, its value quoted, reads as.
func FuzzRead(f *testing.F) {
	f.Add([]byte("# login.defs\nPASS_MAX_DAYS\t99999\nUMASK\t\t022\nENCRYPT_METHOD \"SHA512\" trailing\nPASS_MAX_DAYS 90\nLOG_OK_LOGINS\n"))
	f.Add([]byte("  \"quoted name\" value\r\n\tTRAILING   \t\n"))
	f.Fuzz(func(t *testing.T, content []byte) {
		kept := path
		t.Cleanup(func() { path = kept })
		path = filepath.Join(t.TempDir(), "login.defs")
		if err := os.WriteFile(path, content, 0o644); err != nil {
			t.Fatal(err)
		}
		held, err := Read()
		if err != nil {
			t.Fatalf("login.defs of %d bytes could not be read: %v", len(content), err)
		}
		var again strings.Builder
		for name, setting := range held {
			if name == "" || strings.ContainsAny(name, " \t\n") || strings.ContainsAny(setting.Value, "\"\n") || setting.Line < 1 {
				t.Fatalf("item %q was read as %+v", name, setting)
			}
			fmt.Fprintf(&again, "%s \"%s\"\n", name, setting.Value)
		}
		if err := os.WriteFile(path, []byte(again.String()), 0o644); err != nil {
			t.Fatal(err)
		}
		reread, err := Read()
		if err != nil || !maps.EqualFunc(reread, held, func(a, b Setting) bool { return a.Value == b.Value }) {
			t.Fatalf("the items read were written again as %q, which reads as %v: %v", again.String(), reread, err)
		}
	})
}
