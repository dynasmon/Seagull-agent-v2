package spool

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

var start = time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC)

// A pressured host keeps the time and the room left on its filesystem where a
// test sets them, and writes and syncs as the system does unless it is quick.
type pressured struct {
	system
	quick bool
	mu    sync.Mutex
	clock time.Time
	free  int64
}

func (p *pressured) sync(file *os.File) error {
	if p.quick {
		return nil
	}
	return file.Sync()
}

func newPressured() *pressured { return &pressured{clock: start, free: 1 << 40} }

func (p *pressured) now() time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.clock
}

func (p *pressured) available(*os.File) (int64, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.free, nil
}

func (p *pressured) advance(by time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.clock = p.clock.Add(by)
}

func (p *pressured) set(at time.Time, free int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.clock, p.free = at, free
}

func aged(bytes int64, events, inventory time.Duration) Limits {
	return Limits{MaxBytes: bytes, MaxAge: map[Stream]time.Duration{Events: events, Inventory: inventory}}
}

func TestRecordsThatOutliveTheirAgeExpireAndAreCountedApart(t *testing.T) {
	directory := spoolDirectory(t)
	clock := newPressured()
	held, logs := openPressured(t, directory, aged(64<<20, time.Hour, 24*time.Hour), clock)
	admitAll(t, held, Events, "event", 1, 3)
	clock.advance(30 * time.Minute)
	admitAll(t, held, Events, "event", 4, 2)
	admitAll(t, held, Inventory, "inventory", 1, 1)
	clock.advance(45 * time.Minute)

	if got := sequences(t, held, Events); !slices.Equal(got, []uint64{4, 5}) {
		t.Fatalf("outstanding events %v once the first three were older than an hour", got)
	}
	expired, found := entry(t, logs, "spool_records_expired")
	if !found || expired["first"] != float64(1) || expired["records"] != float64(3) || expired["stream"] != "events" {
		t.Fatalf("the spool reported %v:\n%s", expired, logs)
	}
	if got := sequences(t, held, Inventory); !slices.Equal(got, []uint64{1}) {
		t.Fatalf("inventory kept for a day expired after 75 minutes: %v", got)
	}
	if held := streamStats(t, held, Events); held.Expired != 3 || held.Outstanding != 2 || held.Delivered != 0 {
		t.Fatalf("the spool reports %+v", held)
	}
	closed(t, held)

	held, logs = openPressured(t, directory, aged(64<<20, time.Hour, 24*time.Hour), clock)
	if logs.Len() != 0 {
		t.Fatalf("records that already expired were reported again:\n%s", logs)
	}
	if expired := streamStats(t, held, Events).Expired; expired != 3 {
		t.Fatalf("after a restart the spool counts %d expired records", expired)
	}
}

func TestAClockSetBackKeepsRecordsLongerAndNeverExpiresThemSooner(t *testing.T) {
	clock := newPressured()
	held, _ := openPressured(t, spoolDirectory(t), aged(64<<20, 2*time.Hour, 2*time.Hour), clock)
	admitAll(t, held, Events, "event", 1, 1)
	clock.advance(-8 * time.Hour)
	admitAll(t, held, Events, "event", 2, 1)
	clock.advance(time.Hour)
	admitAll(t, held, Events, "event", 3, 1)

	clock.set(start.Add(time.Hour), 1<<40)
	if got := sequences(t, held, Events); !slices.Equal(got, []uint64{1, 2, 3}) {
		t.Fatalf("records admitted while the clock was behind expired before the one admitted before them: %v", got)
	}
	clock.set(start.Add(2*time.Hour+30*time.Minute), 1<<40)
	if got := sequences(t, held, Events); len(got) != 0 {
		t.Fatalf("records older than their age are still outstanding: %v", got)
	}
}

func TestAFullSpoolPausesWhereItCanBeSeenAndExpiresBeforeItRefuses(t *testing.T) {
	clock := newPressured()
	held, logs := openPressured(t, spoolDirectory(t), aged(4<<20, time.Hour, time.Hour), clock)
	admitted := crowd(t, held, Events, 0)
	for range 3 {
		if _, err := held.Admit(Events, sizedRecord("event", admitted, 256<<10)); !errors.Is(err, ErrFull) {
			t.Fatalf("a full spool admitted a record: %v", err)
		}
	}
	if count := strings.Count(logs.String(), `"msg":"spool_admission_paused"`); count != 1 {
		t.Fatalf("a pause was reported %d times:\n%s", count, logs)
	}
	paused := streamStats(t, held, Events)
	if !paused.Paused.Equal(start) || paused.Refused != 4 {
		t.Fatalf("the spool reports %+v", paused)
	}

	clock.advance(2 * time.Hour)
	if _, err := held.Admit(Events, sizedRecord("event", admitted, 256<<10)); err != nil {
		t.Fatalf("a spool whose records outlived their age refused another: %v", err)
	}
	resumed, found := entry(t, logs, "spool_admission_resumed")
	if !found || resumed["paused"] != float64(2*time.Hour) || resumed["refused"] != float64(4) {
		t.Fatalf("the spool reported %v:\n%s", resumed, logs)
	}
	after := streamStats(t, held, Events)
	if after.Expired != uint64(admitted) || !after.Paused.IsZero() || after.Outstanding != 1 {
		t.Fatalf("the spool reports %+v after %d records expired", after, admitted)
	}
}

func TestASpoolKeptFullReportsWhatExpiresAtMostOnceAMinute(t *testing.T) {
	clock := newPressured()
	clock.quick = true
	held, logs := openPressured(t, spoolDirectory(t), aged(4<<20, time.Hour, time.Hour), clock)
	for n := range 2 * 3600 {
		if _, err := held.Admit(Events, sizedRecord("event", n, 16<<10)); err != nil && !errors.Is(err, ErrFull) {
			t.Fatalf("admission %d: %v", n, err)
		}
		clock.advance(time.Second)
	}
	expiries := strings.Count(logs.String(), `"msg":"spool_records_expired"`)
	if kept := streamStats(t, held, Events); expiries == 0 || expiries > 61 || kept.Refused == 0 {
		t.Fatalf("an hour of a full spool reported %d expiries and the spool reports %+v", expiries, kept)
	}
}

func TestTheSpoolLeavesTheFilesystemRoomForWhatTheAgentMustStillWrite(t *testing.T) {
	clock := newPressured()
	held, logs := openPressured(t, spoolDirectory(t), aged(64<<20, time.Hour, time.Hour), clock)
	admitAll(t, held, Events, "event", 1, 3)

	clock.set(start, minFree+1024)
	_, err := held.Admit(Events, sizedRecord("event", 4, 2048))
	if !errors.Is(err, ErrFull) || !strings.Contains(err.Error(), "filesystem") {
		t.Fatalf("a record that would leave the filesystem less than the agent needs was admitted: %v", err)
	}
	if paused, _ := entry(t, logs, "spool_admission_paused"); !strings.Contains(fmt.Sprint(paused["reason"]), "filesystem") {
		t.Fatalf("the spool paused for %v", paused["reason"])
	}
	if err := held.Acknowledge(Events, 1); err != nil {
		t.Fatalf("an acknowledgement could not be written on a filesystem the spool keeps room on: %v", err)
	}
	if err := held.Quarantine(Events, "refused", 2); err != nil {
		t.Fatalf("a quarantine could not be written on a filesystem the spool keeps room on: %v", err)
	}
	clock.set(start, 1<<40)
	if _, err := held.Admit(Events, sizedRecord("event", 4, 2048)); err != nil {
		t.Fatalf("the spool refused a record once the filesystem had room again: %v", err)
	}
}

func TestQuarantinedRecordsAreNeverReadAndAreCountedApart(t *testing.T) {
	directory := spoolDirectory(t)
	held, logs := openPressured(t, directory, aged(64<<20, 0, 0), newPressured())
	admitAll(t, held, Events, "event", 1, 5)
	reason := "the platform refused record 1: invalid_event: time.event_time\x1b[2J " + strings.Repeat("is older than the window ", 20)
	if err := held.Quarantine(Events, reason, 4, 2); err != nil {
		t.Fatalf("quarantine: %v", err)
	}
	if got := sequences(t, held, Events); !slices.Equal(got, []uint64{1, 3, 5}) {
		t.Fatalf("read %v after records 2 and 4 were quarantined", got)
	}
	quarantine, found := entry(t, logs, "spool_records_quarantined")
	shown, _ := quarantine["reason"].(string)
	if !found || quarantine["first"] != float64(2) || quarantine["records"] != float64(2) {
		t.Fatalf("the spool reported %v:\n%s", quarantine, logs)
	}
	if strings.Contains(shown, "\x1b") || len(shown) > 128 {
		t.Fatalf("the spool wrote the platform's reason as %q", shown)
	}
	if err := held.Quarantine(Events, "again", 2); err != nil || strings.Count(logs.String(), "spool_records_quarantined") != 1 {
		t.Fatalf("a record was quarantined twice: %v\n%s", err, logs)
	}
	if err := held.Quarantine(Events, "never admitted", 9); !errors.Is(err, ErrRefused) {
		t.Fatalf("a record never admitted was quarantined: %v", err)
	}
	closed(t, held)

	held, _ = openPressured(t, directory, aged(64<<20, 0, 0), newPressured())
	if kept := streamStats(t, held, Events); kept.Quarantined != 2 || kept.Delivered != 0 || kept.Outstanding != 3 {
		t.Fatalf("after a restart the spool reports %+v", kept)
	}
}

func TestARecordNoBatchCanCarryIsRefused(t *testing.T) {
	limits := aged(64<<20, 0, 0)
	limits.MaxRecordBytes = 1000
	held, _ := openPressured(t, spoolDirectory(t), limits, newPressured())
	if _, err := held.Admit(Events, Record{ID: "event", Payload: make([]byte, 1000)}); err != nil {
		t.Fatalf("a record a batch carries was refused: %v", err)
	}
	if _, err := held.Admit(Events, Record{ID: "event", Payload: make([]byte, 1001)}); !errors.Is(err, ErrRefused) {
		t.Fatalf("a record no batch carries was admitted: %v", err)
	}
	limits.MaxRecordBytes = 2000
	held.Limit(limits)
	if _, err := held.Admit(Events, Record{ID: "event", Payload: make([]byte, 1001)}); err != nil {
		t.Fatalf("a record the new limit allows was refused: %v", err)
	}
	limits.MaxRecordBytes = 1 << 40
	held.Limit(limits)
	if _, err := held.Admit(Events, Record{ID: "event", Payload: make([]byte, MaxPayloadBytes+1)}); !errors.Is(err, ErrRefused) {
		t.Fatalf("a record larger than a frame holds was admitted: %v", err)
	}
}

func TestALedgerOfTheFirstFormatIsReadAndWrittenInTheSecond(t *testing.T) {
	directory := spoolDirectory(t)
	held, _ := openPressured(t, directory, aged(64<<20, 0, 0), newPressured())
	admitAll(t, held, Events, "event", 1, 4)
	closed(t, held)
	path := filepath.Join(directory, "events", ledgerName)
	if err := os.WriteFile(path, firstFormat(Events, 3, 1, 1), 0o600); err != nil {
		t.Fatalf("write a ledger of the first format: %v", err)
	}

	held, logs := openPressured(t, directory, aged(64<<20, 0, 0), newPressured())
	if logs.Len() != 0 {
		t.Fatalf("a ledger of the first format was reported:\n%s", logs)
	}
	if kept := streamStats(t, held, Events); kept.Delivered != 1 || kept.Lost != 1 || kept.Expired != 0 || kept.Outstanding != 2 {
		t.Fatalf("a ledger of the first format reads as %+v", kept)
	}
	if err := held.Acknowledge(Events, 3); err != nil {
		t.Fatalf("acknowledge: %v", err)
	}
	written, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the ledger: %v", err)
	}
	if format := binary.LittleEndian.Uint16(written[4:]); format != ledgerFormat {
		t.Fatalf("the ledger was written in format %d", format)
	}
	if kept := streamStats(t, held, Events); kept.Delivered != 2 || kept.Lost != 1 {
		t.Fatalf("rewriting the ledger lost what it counted: %+v", kept)
	}
}

func TestAnOutageKeepsTheSpoolWithinItsBudgetAndTheAgeOfWhatItHolds(t *testing.T) {
	directory := spoolDirectory(t)
	clock := newPressured()
	held, logs := openPressured(t, directory, aged(16<<20, 24*time.Hour, 24*time.Hour), clock)
	var before runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	admitted, refused := uint64(0), 0
	for n := range 600 {
		receipt, err := held.Admit(Events, sizedRecord("event", n, 64<<10))
		switch {
		case errors.Is(err, ErrFull):
			refused++
		case err != nil:
			t.Fatalf("admission %d: %v", n, err)
		default:
			admitted += receipt.Last - receipt.First + 1
		}
		if used := held.Stats().Bytes; used > 16<<20 {
			t.Fatalf("after %s without delivery the spool holds %d bytes of its 16MiB", clock.now().Sub(start), used)
		}
		clock.advance(5 * time.Minute)
	}
	if on := onDisk(t, directory); on > 16<<20 {
		t.Fatalf("the spool keeps %d bytes on disk with a budget of 16MiB", on)
	}
	kept := streamStats(t, held, Events)
	if refused == 0 || kept.Expired == 0 || kept.Outstanding+kept.Expired != admitted {
		t.Fatalf("admitted %d, refused %d, and the spool reports %+v", admitted, refused, kept)
	}
	if oldest := sequences(t, held, Events); len(oldest) == 0 {
		t.Fatal("the spool holds nothing after an outage it was admitting through")
	}
	for _, message := range []string{"spool_admission_paused", "spool_admission_resumed", "spool_records_expired"} {
		if !strings.Contains(logs.String(), message) {
			t.Errorf("an outage never reported %s", message)
		}
	}
	var after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&after)
	if grown := int64(after.HeapInuse) - int64(before.HeapInuse); grown > 8<<20 {
		t.Fatalf("admitting through an outage grew the heap by %d bytes", grown)
	}
}

func TestEverySettledRecordIsCountedOnceUnderItsOwnReason(t *testing.T) {
	directory := spoolDirectory(t)
	clock := newPressured()
	held, _ := openPressured(t, directory, aged(64<<20, 3*time.Hour, 3*time.Hour), clock)
	admitAll(t, held, Events, "event", 1, 12)
	clock.advance(2 * time.Hour)
	admitAll(t, held, Events, "event", 13, 8)

	if err := held.Acknowledge(Events, 1, 2, 3, 4, 5); err != nil {
		t.Fatalf("acknowledge: %v", err)
	}
	if err := held.Quarantine(Events, "refused", 6, 7); err != nil {
		t.Fatalf("quarantine: %v", err)
	}
	record := int64(frameHeaderBytes + len("event-000001") + 100)
	damaged, err := os.OpenFile(filepath.Join(directory, "events", fmt.Sprintf("%020d.seg", 1)), os.O_RDWR, 0)
	if err == nil {
		_, err = damaged.WriteAt([]byte("damaged"), segmentHeaderBytes+7*record+frameHeaderBytes+20)
	}
	if err := errors.Join(err, damaged.Close()); err != nil {
		t.Fatalf("damage record 8: %v", err)
	}
	if got := sequences(t, held, Events); !slices.Equal(got, []uint64{9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}) {
		t.Fatalf("outstanding %v", got)
	}
	clock.advance(90 * time.Minute)
	if got := sequences(t, held, Events); !slices.Equal(got, []uint64{13, 14, 15, 16, 17, 18, 19, 20}) {
		t.Fatalf("outstanding %v once records 9 to 12 outlived their age", got)
	}
	if err := held.Acknowledge(Events, 9, 13); err != nil {
		t.Fatalf("acknowledge: %v", err)
	}

	kept := streamStats(t, held, Events)
	want := StreamStats{Stream: Events, Delivered: 6, Quarantined: 2, Lost: 1, Expired: 4, Outstanding: 7}
	if kept.Delivered != want.Delivered || kept.Quarantined != want.Quarantined || kept.Lost != want.Lost ||
		kept.Expired != want.Expired || kept.Outstanding != want.Outstanding {
		t.Fatalf("the spool reports %+v, want %+v", kept, want)
	}
	if total := kept.Delivered + kept.Quarantined + kept.Lost + kept.Expired + kept.Outstanding; total != 20 {
		t.Fatalf("the spool accounts for %d of the 20 records it admitted", total)
	}
}

func openPressured(t *testing.T, directory string, limits Limits, clock host) (*Spool, *strings.Builder) {
	t.Helper()
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatalf("open %s: %v", directory, err)
	}
	t.Cleanup(func() { root.Close() })
	logs := &strings.Builder{}
	held, err := open(root, limits, slog.New(slog.NewJSONHandler(logs, nil)), clock)
	if err != nil {
		t.Fatalf("open the spool: %v", err)
	}
	t.Cleanup(func() { held.Close() })
	return held, logs
}

func sizedRecord(prefix string, n, length int) Record {
	return Record{ID: fmt.Sprintf("%s-%06d", prefix, n+1), Payload: []byte(strings.Repeat("p", length))}
}

func admitAll(t *testing.T, held *Spool, stream Stream, prefix string, first, count int) {
	t.Helper()
	for n := first; n < first+count; n++ {
		if _, err := held.Admit(stream, sizedRecord(prefix, n-1, 100)); err != nil {
			t.Fatalf("admit %s %d: %v", stream, n, err)
		}
	}
}

func crowd(t *testing.T, held *Spool, stream Stream, from int) int {
	t.Helper()
	for admitted := from; ; admitted++ {
		if _, err := held.Admit(stream, sizedRecord("event", admitted, 256<<10)); err != nil {
			if !errors.Is(err, ErrFull) {
				t.Fatalf("admit %d: %v", admitted, err)
			}
			return admitted - from
		}
	}
}

func sequences(t *testing.T, held *Spool, stream Stream) []uint64 {
	t.Helper()
	entries, err := held.Read(stream, 1, 1<<10, 64<<20)
	if err != nil {
		t.Fatalf("read %s: %v", stream, err)
	}
	var read []uint64
	for _, entry := range entries {
		read = append(read, entry.Sequence)
	}
	return read
}

func streamStats(t *testing.T, held *Spool, stream Stream) StreamStats {
	t.Helper()
	for _, kept := range held.Stats().Streams {
		if kept.Stream == stream {
			return kept
		}
	}
	t.Fatalf("the spool reports nothing about %s", stream)
	return StreamStats{}
}

func entry(t *testing.T, logs *strings.Builder, message string) (map[string]any, bool) {
	t.Helper()
	for line := range strings.Lines(logs.String()) {
		held := map[string]any{}
		if err := json.Unmarshal([]byte(line), &held); err != nil {
			t.Fatalf("decode the log line %q: %v", line, err)
		}
		if held["msg"] == message {
			return held, true
		}
	}
	return nil, false
}

func onDisk(t *testing.T, directory string) int64 {
	t.Helper()
	var total int64
	err := filepath.WalkDir(directory, func(path string, found fs.DirEntry, err error) error {
		if err != nil || found.IsDir() {
			return err
		}
		described, err := found.Info()
		if err == nil {
			total += described.Size()
		}
		return err
	})
	if err != nil {
		t.Fatalf("walk %s: %v", directory, err)
	}
	return total
}
