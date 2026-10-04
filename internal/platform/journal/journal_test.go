package journal

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	first  = "s=0123456789abcdef0123456789abcdef;i=1fe952;b=fedcba9876543210fedcba9876543210;m=a7e901;t=65cc96285e8e5;x=12873fe04103c3b3"
	second = "s=0123456789abcdef0123456789abcdef;i=1fe953;b=fedcba9876543210fedcba9876543210;m=a7ea33;t=65cc96285ea18;x=92aa049ee3243583"
)

var sshd = Query{
	Matches: []Match{{Field: "_COMM", Value: "sshd"}, {Field: "_COMM", Value: "sshd-session"}, {Field: "_UID", Value: "0"}},
	Fields:  []string{"MESSAGE", "_COMM", "_UID", "_HOSTNAME"},
}

type fake struct {
	directory string
}

// A journalctl that writes what the test hands it and keeps the arguments it
// was given, run as the agent runs journalctl: with nothing in its environment.
func faked(t *testing.T, entries string) fake {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("the agent reads the system journal on linux alone")
	}
	directory := t.TempDir()
	script := fmt.Sprintf(`#!/bin/sh
for argument in "$@"; do printf '%%s\n' "$argument"; done > '%[1]s/arguments'
/bin/cat '%[1]s/entries'
if [ -f '%[1]s/complaint' ]; then /bin/cat '%[1]s/complaint' >&2; fi
if [ -f '%[1]s/follow' ]; then exec /bin/sleep 600; fi
if [ -f '%[1]s/status' ]; then exit "$(/bin/cat '%[1]s/status')"; fi
exit 0
`, directory)
	write(t, filepath.Join(directory, "journalctl"), script)
	if err := os.Chmod(filepath.Join(directory, "journalctl"), 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(directory, "entries"), entries)
	held := program
	program = filepath.Join(directory, "journalctl")
	t.Cleanup(func() { program = held })
	return fake{directory: directory}
}

func (f fake) complain(t *testing.T, said string, status int) {
	t.Helper()
	write(t, filepath.Join(f.directory, "complaint"), said)
	write(t, filepath.Join(f.directory, "status"), fmt.Sprint(status))
}

func (f fake) follow(t *testing.T) {
	t.Helper()
	write(t, filepath.Join(f.directory, "follow"), "")
}

func (f fake) arguments(t *testing.T) []string {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(f.directory, "arguments"))
	if err != nil {
		t.Fatalf("journalctl kept no arguments: %v", err)
	}
	return strings.Split(strings.TrimSuffix(string(content), "\n"), "\n")
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func entry(cursor string, realtime int64, fields string) string {
	return fmt.Sprintf(`{"__CURSOR":%q,"__REALTIME_TIMESTAMP":"%d","__MONOTONIC_TIMESTAMP":"11004161","_BOOT_ID":"fedcba9876543210fedcba9876543210"%s}`+"\n", cursor, realtime, fields)
}

func open(t *testing.T, from Position, follow bool) *Reader {
	t.Helper()
	held, err := New(sshd)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := held.Open(t.Context(), from, follow)
	if err != nil {
		t.Fatalf("open the journal: %v", err)
	}
	t.Cleanup(func() { reader.Close() })
	return reader
}

func TestAQueryNamesFieldsAndValuesJournalctlReads(t *testing.T) {
	for name, query := range map[string]Query{
		"no match":              {Fields: []string{"MESSAGE"}},
		"no field to read":      {Matches: []Match{{Field: "_UID", Value: "0"}}},
		"a lowercase field":     {Matches: []Match{{Field: "_comm", Value: "sshd"}}, Fields: []string{"MESSAGE"}},
		"an empty value":        {Matches: []Match{{Field: "_COMM", Value: ""}}, Fields: []string{"MESSAGE"}},
		"a value of two lines":  {Matches: []Match{{Field: "_COMM", Value: "sshd\n_UID=0"}}, Fields: []string{"MESSAGE"}},
		"a field read as a key": {Matches: []Match{{Field: "_UID", Value: "0"}}, Fields: []string{"MESSAGE=sshd"}},
		"too many fields":       {Matches: []Match{{Field: "_UID", Value: "0"}}, Fields: slices.Repeat([]string{"MESSAGE"}, maxFields+1)},
		"a unit that is a flag": {Unit: "--merge", Fields: []string{"MESSAGE"}},
		"a unit with a space":   {Unit: "seagull agent.service", Fields: []string{"MESSAGE"}},
		"a unit of a path":      {Unit: "../seagull-agent.service", Fields: []string{"MESSAGE"}},
		"a socket":              {Unit: "seagull-agent.socket", Fields: []string{"MESSAGE"}},
	} {
		if _, err := New(query); err == nil {
			t.Errorf("%s: the query was taken", name)
		}
	}
	for _, query := range []Query{sshd, {Unit: "seagull-agent.service", Fields: []string{"MESSAGE"}}, {Unit: "getty@tty1.service", Fields: []string{"MESSAGE"}}} {
		if _, err := New(query); err != nil {
			t.Errorf("the query %+v was refused: %v", query, err)
		}
	}
}

func TestJournalctlIsAskedForTheSystemJournalFromAPosition(t *testing.T) {
	journal := faked(t, "")
	since := time.Date(2026, 10, 1, 15, 51, 11, 388_814_123, time.UTC)
	for _, reading := range []struct {
		from   Position
		follow bool
		start  string
	}{
		{from: Position{Cursor: first}, start: "--cursor=" + first},
		{from: Position{Since: since}, start: "--since=@1790869871.388814"},
		{from: Position{Since: since}, follow: true, start: "--since=@1790869871.388814"},
		{from: Position{Last: 1000}, start: "--lines=1000"},
	} {
		reader := open(t, reading.from, reading.follow)
		if _, err := reader.Next(); !errors.Is(err, io.EOF) {
			t.Fatalf("a journal with nothing to read said %v", err)
		}
		want := []string{"--system", "--no-pager", "--output=json", "--output-fields=MESSAGE,_COMM,_UID,_HOSTNAME", reading.start}
		if reading.follow {
			want = append(want, "--follow")
		}
		want = append(want, "_COMM=sshd", "_COMM=sshd-session", "_UID=0")
		if got := journal.arguments(t); !slices.Equal(got, want) {
			t.Errorf("journalctl was run with\n%q, want\n%q", got, want)
		}
	}
}

// What journalctl reads for a unit is what the service's processes wrote and
// what the service manager wrote about it, which matching on fields cannot
// say in one reading.
func TestAUnitIsReadAsJournalctlReadsOne(t *testing.T) {
	journal := faked(t, "")
	held, err := New(Query{Unit: "seagull-agent.service", Matches: []Match{{Field: "PRIORITY", Value: "3"}}, Fields: []string{"MESSAGE", "_PID"}})
	if err != nil {
		t.Fatal(err)
	}
	reader, err := held.Open(t.Context(), Position{Last: 25}, false)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if _, err := reader.Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("a journal with nothing to read said %v", err)
	}
	want := []string{"--system", "--no-pager", "--output=json", "--output-fields=MESSAGE,_PID", "--lines=25", "--unit=seagull-agent.service", "PRIORITY=3"}
	if got := journal.arguments(t); !slices.Equal(got, want) {
		t.Errorf("journalctl was run with\n%q, want\n%q", got, want)
	}
}

func TestAReadingStartsAtOneCursorOrMoment(t *testing.T) {
	held, err := New(sshd)
	if err != nil {
		t.Fatal(err)
	}
	for name, from := range map[string]Position{
		"nowhere":                    {},
		"both":                       {Cursor: first, Since: time.Now()},
		"a cursor and its last ones": {Cursor: first, Last: 10},
		"a moment and its last ones": {Since: time.Now(), Last: 10},
		"fewer than none":            {Last: -1},
		"more than it reads":         {Last: MaxLast + 1},
		"a damaged cursor":           {Cursor: strings.Replace(first, "i=", "j=", 1)},
		"a cursor and a flag":        {Cursor: first + " --merge"},
		"before 1970":                {Since: time.Date(1969, 12, 31, 0, 0, 0, 0, time.UTC)},
	} {
		if reader, err := held.Open(t.Context(), from, false); err == nil {
			reader.Close()
			t.Errorf("%s: journalctl was started", name)
		}
	}
	if !Cursor(first) || Cursor(first+";") || Cursor("") {
		t.Error("cursors are not told from what is not one")
	}
}

func TestEntriesAreReadAsJournalctlWritesThem(t *testing.T) {
	faked(t, entry(first, 1790869871388901, `,"MESSAGE":"Accepted publickey for nathan from 192.0.2.7 port 65196 ssh2","_COMM":"sshd","_UID":"0","_HOSTNAME":"web-01"`)+
		entry(second, 1790869871389208, `,"MESSAGE":[98,97,100,1,255],"_COMM":null,"_UID":["0","1000"],"_HOSTNAME":[300]`))
	reader := open(t, Position{Cursor: first}, false)
	read, err := reader.Next()
	if err != nil {
		t.Fatal(err)
	}
	if read.Cursor != first || !read.Realtime.Equal(time.UnixMicro(1790869871388901)) || len(read.Fields) != 4 ||
		read.Fields["MESSAGE"] != "Accepted publickey for nathan from 192.0.2.7 port 65196 ssh2" || read.Fields["_COMM"] != "sshd" ||
		read.Fields["_UID"] != "0" || read.Fields["_HOSTNAME"] != "web-01" {
		t.Errorf("the first entry was read as %+v", read)
	}
	read, err = reader.Next()
	if err != nil {
		t.Fatal(err)
	}
	if read.Cursor != second || len(read.Fields) != 1 || read.Fields["MESSAGE"] != "bad\x01\xff" {
		t.Errorf("a binary value is its bytes, and one withheld, repeated or out of range is none: %+v", read)
	}
	if _, err := reader.Next(); !errors.Is(err, io.EOF) {
		t.Errorf("the end of the journal was read as %v", err)
	}
	if _, err := reader.Next(); !errors.Is(err, io.EOF) {
		t.Errorf("the end of the journal was read once and then as %v", err)
	}
}

func TestAnEntryThatCannotBeReadLeavesTheNextOneRead(t *testing.T) {
	long := `{"MESSAGE":"` + strings.Repeat("x", MaxLine) + `"}` + "\n"
	faked(t, "not json\n"+
		`{"__REALTIME_TIMESTAMP":"1790869871388901"}`+"\n"+
		strings.Replace(entry(first, 1, ""), first, strings.Replace(first, "x=", "y=", 1), 1)+
		entry(first, 0, "")+
		fmt.Sprintf(`{"__CURSOR":%q,"__REALTIME_TIMESTAMP":1790869871388901}`, first)+"\n"+
		long+
		entry(second, 1790869871389208, `,"MESSAGE":"Server listening on :: port 22."`))
	reader := open(t, Position{Cursor: first}, false)
	for range 6 {
		if read, err := reader.Next(); !errors.Is(err, ErrUnreadable) {
			t.Fatalf("an entry journalctl could not have written was read as %+v, %v", read, err)
		}
	}
	read, err := reader.Next()
	if err != nil || read.Cursor != second || read.Fields["MESSAGE"] != "Server listening on :: port 22." {
		t.Fatalf("the entry after them was read as %+v, %v", read, err)
	}
}

func TestWhyJournalctlStoppedIsWhatItSaid(t *testing.T) {
	journal := faked(t, entry(first, 1790869871388901, ""))
	journal.complain(t, "Hint: some journal files may be missing.\nNo journal files were opened due to insufficient permissions.\n", 1)
	reader := open(t, Position{Cursor: first}, true)
	if _, err := reader.Next(); err != nil {
		t.Fatalf("the entry written before journalctl stopped was read as %v", err)
	}
	_, err := reader.Next()
	if !errors.Is(err, ErrDenied) || !strings.Contains(err.Error(), "exit status 1") || !strings.Contains(err.Error(), "No journal files were opened due to insufficient permissions.") {
		t.Errorf("journalctl stopped for want of permissions and the reader said %v", err)
	}
	journal.complain(t, "Failed to seek to cursor: Invalid argument\n", 1)
	reader = open(t, Position{Cursor: first}, false)
	reader.Next()
	if _, err := reader.Next(); err == nil || errors.Is(err, ErrDenied) || errors.Is(err, io.EOF) || !strings.Contains(err.Error(), "Failed to seek to cursor") {
		t.Errorf("journalctl refused the cursor and the reader said %v", err)
	}
	journal.complain(t, strings.Repeat("x", 4*maxComplaint), 3)
	reader = open(t, Position{Cursor: first}, false)
	reader.Next()
	if _, err := reader.Next(); err == nil || len(err.Error()) > 256 {
		t.Errorf("what journalctl said was kept as %v", err)
	}
}

func TestClosingStopsAJournalctlThatFollows(t *testing.T) {
	journal := faked(t, entry(first, 1790869871388901, "")+entry(second, 1790869871389208, ""))
	journal.follow(t)
	reader := open(t, Position{Cursor: first}, true)
	if read, err := reader.Next(); err != nil || read.Cursor != first {
		t.Fatalf("the first entry was read as %+v, %v", read, err)
	}
	if !reader.Pending() {
		t.Error("an entry journalctl already wrote is not pending")
	}
	if read, err := reader.Next(); err != nil || read.Cursor != second {
		t.Fatalf("the second entry was read as %+v, %v", read, err)
	}
	closed := make(chan struct{})
	go func() {
		reader.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("closing the reader left journalctl running")
	}
	if _, err := reader.Next(); !errors.Is(err, context.Canceled) {
		t.Errorf("a closed reader said %v", err)
	}
}

func TestTheEndOfItsContextStopsJournalctl(t *testing.T) {
	journal := faked(t, entry(first, 1790869871388901, ""))
	journal.follow(t)
	held, err := New(sshd)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	reader, err := held.Open(ctx, Position{Cursor: first}, true)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	reader.Next()
	time.AfterFunc(100*time.Millisecond, cancel)
	if _, err := reader.Next(); !errors.Is(err, context.Canceled) {
		t.Errorf("a reader whose context ended said %v", err)
	}
}

// What the journal of this host holds, read with the journalctl it runs: the
// format the agent reads is the one systemd writes, not the one a test wrote.
func TestTheJournalOfThisHostReadsAsItsJournalctlWritesIt(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the agent reads the system journal on linux alone")
	}
	if _, err := os.Stat(program); err != nil {
		t.Skipf("this host has no %s", program)
	}
	held, err := New(Query{Matches: []Match{{Field: "_PID", Value: "1"}}, Fields: []string{"MESSAGE", "_PID", "_UID"}})
	if err != nil {
		t.Fatal(err)
	}
	reader, err := held.Open(t.Context(), Position{Since: time.Now().Add(-30 * 24 * time.Hour)}, false)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	read := 0
	for {
		found, err := reader.Next()
		if errors.Is(err, ErrDenied) {
			t.Skipf("this account may not read the system journal: %v", err)
		}
		if errors.Is(err, io.EOF) || read == 200 {
			break
		}
		if err != nil {
			t.Fatalf("after %d entries: %v", read, err)
		}
		if !Cursor(found.Cursor) || found.Realtime.Before(time.Now().Add(-31*24*time.Hour)) || found.Fields["_PID"] != "1" {
			t.Fatalf("an entry was read as %+v", found)
		}
		read++
	}
	if read == 0 {
		t.Skip("the system journal of this host holds nothing systemd wrote in a month")
	}
}
