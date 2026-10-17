package command

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"
)

// Whatever a program writes to its standard error, in whatever pieces, the
// agent repeats of it its last line, on one line and within what a message
// carries.
func FuzzComplaint(f *testing.F) {
	f.Add([]byte("Failed to connect to bus: No such file or directory\n"), []byte(""))
	f.Add([]byte("warning: one\n\n"), []byte("  error: the last one  \n\n"))
	f.Add(bytes.Repeat([]byte("x"), 3000), []byte("\xff\x1b[2Ksaid\n"))
	f.Fuzz(func(t *testing.T, first, second []byte) {
		said := &complaint{}
		said.Write(first)
		said.Write(second)
		last := said.last()
		if strings.ContainsAny(last, "\n\r") || len(last) > 1<<10 || !utf8.ValidString(last) {
			t.Fatalf("%q and %q were repeated as %q", first, second, last)
		}
		if len(first)+len(second) <= maxComplaint && strings.TrimSpace(string(first)+string(second)) != "" && last == "" {
			t.Fatalf("%q and %q were repeated as nothing", first, second)
		}
	})
}
