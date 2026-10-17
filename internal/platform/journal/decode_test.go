package journal

import (
	"encoding/json"
	"errors"
	"maps"
	"strconv"
	"testing"
	"unicode/utf8"
)

// What journalctl writes of an entry is what any account that logs chose to
// say: whatever a line holds, the entry read from it is the one journalctl
// would write as the same line, its fields as text or as the bytes they are.
func FuzzDecode(f *testing.F) {
	cursor := "s=0123456789abcdef0123456789abcdef;i=1a2b;b=fedcba9876543210fedcba9876543210;m=3c4d5e;t=6129a8b7c6d5e;x=7f8e9dacbbecfd0e"
	f.Add([]byte(entry(cursor, 1759320000123456, `,"MESSAGE":"Failed password for invalid user admin from 203.0.113.10 port 52144 ssh2","_COMM":"sshd-session","_UID":"0"`)))
	f.Add([]byte(entry(cursor, 1759320000123456, `,"MESSAGE":[70,97,105,108,101,100,255,0],"_COMM":"sshd"`)))
	f.Add([]byte(entry(cursor, 1759320000123456, `,"MESSAGE":null,"_HOSTNAME":["web",1]`)))
	f.Add([]byte(entry("not a cursor", 1, ``)))
	f.Add([]byte(`{"__CURSOR":"` + cursor + `","__REALTIME_TIMESTAMP":"-1"}`))
	reader := &Reader{wanted: []string{"MESSAGE", "_COMM", "_UID", "_HOSTNAME", "SYSLOG_IDENTIFIER"}}
	f.Fuzz(func(t *testing.T, line []byte) {
		read, err := reader.decode(line)
		if err != nil {
			if !errors.Is(err, ErrUnreadable) || len(err.Error()) > 1<<10 {
				t.Fatalf("a line was refused for no reason it names, or a long one: %.200v", err)
			}
			return
		}
		if !cursorPattern.MatchString(read.Cursor) || read.Realtime.UnixMicro() <= 0 {
			t.Fatalf("an entry at %q, %s was read", read.Cursor, read.Realtime)
		}
		written := map[string]any{"__CURSOR": read.Cursor, "__REALTIME_TIMESTAMP": strconv.FormatInt(read.Realtime.UnixMicro(), 10)}
		for name, value := range read.Fields {
			if utf8.ValidString(value) {
				written[name] = value
				continue
			}
			octets := make([]int, len(value))
			for i := range len(value) {
				octets[i] = int(value[i])
			}
			written[name] = octets
		}
		again, err := json.Marshal(written)
		if err != nil {
			t.Fatal(err)
		}
		reread, err := reader.decode(again)
		if err != nil || reread.Cursor != read.Cursor || !reread.Realtime.Equal(read.Realtime) || !maps.Equal(reread.Fields, read.Fields) {
			t.Fatalf("an entry written again as %s reads as %+v, not %+v: %v", again, reread, read, err)
		}
	})
}
