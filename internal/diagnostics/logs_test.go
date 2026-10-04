package diagnostics_test

import (
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/dynasmon/Seagull-agent-v2/internal/diagnostics"
)

var written = time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)

func TestAnEntryIsKeptAsJournaldWroteItDown(t *testing.T) {
	entry := diagnostics.Logged("s=1", written, map[string]string{
		"MESSAGE":         `{"level":"INFO","msg":"installation_replaced"}`,
		"PRIORITY":        "4",
		"_PID":            "4242",
		"_UID":            "998",
		"_AUDIT_LOGINUID": "1000",
		"_COMM":           "seagull-agent",
	})
	if entry.At != written || entry.Priority != 4 || entry.Process != 4242 || entry.User == nil || *entry.User != 998 ||
		entry.Login == nil || *entry.Login != 1000 || entry.Command != "seagull-agent" || entry.Message != `{"level":"INFO","msg":"installation_replaced"}` {
		t.Errorf("the entry was kept as %+v", entry)
	}
	unsaid := diagnostics.Logged("s=2", written, map[string]string{"PRIORITY": "9", "_AUDIT_LOGINUID": "4294967295", "_UID": "-1"})
	if unsaid.Priority != 6 || unsaid.Login != nil || unsaid.User != nil || unsaid.Process != 0 || unsaid.Message != "" {
		t.Errorf("an entry that says nothing of itself was kept as %+v", unsaid)
	}
	for _, message := range []string{strings.Repeat("x", 64<<10), strings.Repeat("ü", 32<<10)} {
		kept := diagnostics.Logged("s=3", written, map[string]string{"MESSAGE": message}).Message
		if len(kept) > 4<<10+len("...") || !strings.HasSuffix(kept, "...") || !utf8.ValidString(kept) {
			t.Errorf("a message of %d bytes was kept as %d bytes", len(message), len(kept))
		}
	}
}

func TestEntriesAreKeptOnceEachInTheOrderTheyWereWritten(t *testing.T) {
	logged := func(cursor string, second int) diagnostics.Entry {
		return diagnostics.Logged(cursor, written.Add(time.Duration(second)*time.Second), map[string]string{"MESSAGE": cursor})
	}
	kept, complete := diagnostics.Kept([]diagnostics.Entry{logged("c", 3), logged("a", 1), logged("b", 2), logged("c", 3), logged("a", 1), logged("d", 2)})
	var order []string
	for _, entry := range kept {
		order = append(order, entry.Message)
	}
	if strings.Join(order, " ") != "a b d c" || !complete {
		t.Errorf("the entries were kept as %q, complete %t", order, complete)
	}
}

func TestTheLatestEntriesThatFitInABundleAreKept(t *testing.T) {
	var many []diagnostics.Entry
	for n := range diagnostics.MaxEntries + 500 {
		many = append(many, diagnostics.Logged(fmt.Sprint(n), written.Add(time.Duration(n)*time.Millisecond), map[string]string{"MESSAGE": fmt.Sprint(n)}))
	}
	kept, complete := diagnostics.Kept(many)
	if len(kept) != diagnostics.MaxEntries || complete || kept[0].Message != "500" || kept[len(kept)-1].Message != fmt.Sprint(diagnostics.MaxEntries+499) {
		t.Errorf("of %d entries %d were kept, from %s, complete %t", len(many), len(kept), kept[0].Message, complete)
	}

	var long []diagnostics.Entry
	for n := range 1500 {
		long = append(long, diagnostics.Logged(fmt.Sprint(n), written.Add(time.Duration(n)*time.Millisecond), map[string]string{"MESSAGE": strings.Repeat("x", 8<<10)}))
	}
	kept, complete = diagnostics.Kept(long)
	spent := 0
	for _, entry := range kept {
		spent += len(entry.Message)
	}
	if complete || spent > 4<<20 || spent < 4<<20-(4<<10+3) || !kept[len(kept)-1].At.Equal(long[len(long)-1].At) {
		t.Errorf("of 1500 long entries %d were kept, holding %d bytes, complete %t", len(kept), spent, complete)
	}
}
