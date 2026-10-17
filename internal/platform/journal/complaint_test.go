package journal

import (
	"errors"
	"strings"
	"testing"
	"unicode/utf8"
)

// Whatever journalctl complains with, the agent repeats its last line on one
// line within what a message carries, and takes it for a refusal of access
// only when journalctl said so.
func FuzzComplaint(f *testing.F) {
	f.Add([]byte("Hint: You are currently not seeing messages from other users and the system.\n"), []byte("No journal files were opened due to insufficient permissions.\n"))
	f.Add([]byte("Failed to get boot id: \xff\n"), []byte{})
	f.Fuzz(func(t *testing.T, first, second []byte) {
		said := &complaint{}
		said.Write(first)
		said.Write(second)
		explained := said.explain(errors.New("exit status 1"))
		message := explained.Error()
		if strings.ContainsAny(message, "\n\r") || !utf8.ValidString(message) || len(message) > 1<<10 {
			t.Fatalf("%q and %q were repeated as %q", first, second, message)
		}
		if errors.Is(explained, ErrDenied) && !strings.Contains(string(said.held), denied) {
			t.Fatalf("%q and %q were taken for a refusal of access", first, second)
		}
	})
}

// A cursor is handed to journalctl as an argument and written down in the
// place the collector keeps: whatever is taken for one holds nothing but what
// journald writes in a cursor.
func FuzzCursor(f *testing.F) {
	f.Add("s=0123456789abcdef0123456789abcdef;i=1a2b;b=fedcba9876543210fedcba9876543210;m=3c4d5e;t=6129a8b7c6d5e;x=7f8e9dacbbecfd0e")
	f.Add("s=0;i=0;b=0;m=0;t=0;x=0")
	f.Fuzz(func(t *testing.T, cursor string) {
		if Cursor(cursor) && (strings.Trim(cursor, "0123456789abcdef;=sibmtx") != "" || len(cursor) > 200) {
			t.Fatalf("%q was taken for a cursor of the journal", cursor)
		}
	})
}
