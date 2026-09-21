package spool

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

var (
	errNoSpace = errors.New("no space left on device")
	errIO      = errors.New("input/output error")
)

// A faulty host fails the write or the sync it is told to, counting from now,
// and behaves as the system does otherwise. A write that fails still writes
// the first cut bytes it was given, as a disk that fills up part way does.
type faulty struct {
	system
	writes int
	syncs  int
	cut    int
}

func healthy() *faulty { return &faulty{writes: -1, syncs: -1} }

func (f *faulty) write(file *os.File, content []byte) (int, error) {
	if f.writes == 0 {
		f.writes = -1
		written, _ := file.Write(content[:min(f.cut, len(content))])
		return written, errNoSpace
	}
	if f.writes > 0 {
		f.writes--
	}
	return file.Write(content)
}

func (f *faulty) sync(file *os.File) error {
	if f.syncs == 0 {
		f.syncs = -1
		return errIO
	}
	if f.syncs > 0 {
		f.syncs--
	}
	return file.Sync()
}

func TestAWriteThatFailsAdmitsNothingAndTheSpoolAdmitsAgain(t *testing.T) {
	directory := spoolDirectory(t)
	disk := healthy()
	held, _ := openWith(t, directory, disk)
	first := admitted(t, held, "event-1", 100)
	before := segmentSize(t, directory)

	disk.writes, disk.cut = 1, 1000
	if receipt, err := held.Admit(Events, Record{ID: "event-2", Payload: make([]byte, 300<<10)}); err == nil || errors.Is(err, ErrUnavailable) {
		t.Fatalf("a write that ran out of space admitted %+v: %v", receipt, err)
	}
	if after := segmentSize(t, directory); after != before {
		t.Fatalf("the segment holds %d bytes after the failed write, and %d before it", after, before)
	}
	if next := admitted(t, held, "event-3", 100); next.First != first.Last+1 {
		t.Fatalf("the record admitted after the failed write became %d", next.First)
	}
	closed(t, held)

	held, logs := openWith(t, directory, healthy())
	if logs.Len() != 0 {
		t.Fatalf("a spool that undid its failed write reported:\n%s", logs)
	}
	if got := identifiers(t, held); !slices.Equal(got, []string{"event-1", "event-3"}) {
		t.Fatalf("read back %q", got)
	}
}

func TestASyncThatFailsStopsTheStreamAdmittingUntilItIsReopened(t *testing.T) {
	directory := spoolDirectory(t)
	disk := healthy()
	held, logs := openWith(t, directory, disk)
	admitted(t, held, "event-1", 100)

	disk.syncs = 0
	if _, err := held.Admit(Events, Record{ID: "event-2", Payload: []byte("unconfirmed")}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("a record whose sync failed was admitted with %v", err)
	}
	if !strings.Contains(logs.String(), `"msg":"spool_unavailable"`) {
		t.Fatalf("the spool did not report that it stopped admitting:\n%s", logs)
	}
	if _, err := held.Admit(Events, Record{ID: "event-3", Payload: []byte("refused")}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("the stream kept admitting after a sync failed: %v", err)
	}
	if got := identifiers(t, held); !slices.Equal(got, []string{"event-1"}) {
		t.Fatalf("a record whose sync failed was read back: %q", got)
	}
	if err := held.Acknowledge(Events, 1); err != nil {
		t.Fatalf("the stream could not acknowledge what it holds: %v", err)
	}
	if _, err := held.Admit(Inventory, Record{ID: "inventory-1", Payload: []byte("kept")}); err != nil {
		t.Fatalf("a sync that failed in one stream stopped another: %v", err)
	}
	for _, stream := range held.Stats().Streams {
		if (stream.Unavailable != nil) != (stream.Stream == Events) {
			t.Errorf("%s reports %v", stream.Stream, stream.Unavailable)
		}
	}
	closed(t, held)

	held, _ = openWith(t, directory, healthy())
	receipt := admitted(t, held, "event-4", 100)
	if got := identifiers(t, held); got[len(got)-1] != "event-4" || slices.Contains(got, "event-1") || slices.Contains(got, "event-3") {
		t.Fatalf("after reopening, read back %q", got)
	}
	if receipt.First < 2 {
		t.Fatalf("after reopening, the next record became %d", receipt.First)
	}
}

func TestAnAcknowledgementThatCannotBeWrittenLeavesTheRecordsOutstanding(t *testing.T) {
	for name, fail := range map[string]func(disk *faulty){
		"a write that fails": func(disk *faulty) { disk.writes = 0 },
		"a sync that fails":  func(disk *faulty) { disk.syncs = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			directory := spoolDirectory(t)
			disk := healthy()
			held, _ := openWith(t, directory, disk)
			admitted(t, held, "event-1", 100)
			admitted(t, held, "event-2", 100)

			fail(disk)
			if err := held.Acknowledge(Events, 1); err == nil {
				t.Fatal("an acknowledgement that was never written was accepted")
			}
			if got := identifiers(t, held); !slices.Equal(got, []string{"event-1", "event-2"}) {
				t.Fatalf("read back %q after the acknowledgement failed", got)
			}
			left, err := filepath.Glob(filepath.Join(directory, "events", ".ledger.*.tmp"))
			if err != nil || len(left) > 0 {
				t.Fatalf("the failed acknowledgement left %q behind: %v", left, err)
			}
			closed(t, held)

			held, _ = openWith(t, directory, healthy())
			if got := identifiers(t, held); !slices.Equal(got, []string{"event-1", "event-2"}) {
				t.Fatalf("after reopening, read back %q", got)
			}
		})
	}
}

func TestASegmentThatCannotBeCreatedWholeIsNotKept(t *testing.T) {
	directory := spoolDirectory(t)
	disk := healthy()
	held, _ := openWith(t, directory, disk)
	disk.syncs = 0
	if _, err := held.Admit(Events, Record{ID: "event-1", Payload: []byte("first")}); err == nil {
		t.Fatal("a record was admitted into a segment that was never synced")
	}
	if left, _ := filepath.Glob(filepath.Join(directory, "events", "*.seg")); len(left) > 0 {
		t.Fatalf("the segment that could not be created is still there: %q", left)
	}
	if receipt := admitted(t, held, "event-2", 100); receipt.First != 1 {
		t.Fatalf("the first record admitted became %d", receipt.First)
	}
}

func spoolDirectory(t *testing.T) string {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "spool")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatalf("create %s: %v", directory, err)
	}
	return directory
}

func openWith(t *testing.T, directory string, disk host) (*Spool, *strings.Builder) {
	t.Helper()
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatalf("open %s: %v", directory, err)
	}
	t.Cleanup(func() { root.Close() })
	logs := &strings.Builder{}
	held, err := open(root, Limits{MaxBytes: 64 << 20}, slog.New(slog.NewJSONHandler(logs, nil)), disk)
	if err != nil {
		t.Fatalf("open the spool: %v", err)
	}
	t.Cleanup(func() { held.Close() })
	return held, logs
}

func admitted(t *testing.T, held *Spool, id string, length int) Receipt {
	t.Helper()
	receipt, err := held.Admit(Events, Record{ID: id, Payload: []byte(strings.Repeat("p", length))})
	if err != nil {
		t.Fatalf("admit %s: %v", id, err)
	}
	return receipt
}

func closed(t *testing.T, held *Spool) {
	t.Helper()
	if err := held.Close(); err != nil {
		t.Fatalf("close the spool: %v", err)
	}
}

func identifiers(t *testing.T, held *Spool) []string {
	t.Helper()
	entries, err := held.Read(Events, 1, 1<<10, 64<<20)
	if err != nil {
		t.Fatalf("read the spool: %v", err)
	}
	var ids []string
	for _, entry := range entries {
		ids = append(ids, entry.ID)
	}
	return ids
}

func segmentSize(t *testing.T, directory string) int64 {
	t.Helper()
	described, err := os.Stat(filepath.Join(directory, "events", fmt.Sprintf("%020d.seg", 1)))
	if err != nil {
		t.Fatalf("inspect the segment: %v", err)
	}
	return described.Size()
}
