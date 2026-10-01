package authentication_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-agent-v2/internal/governor"
	"github.com/dynasmon/Seagull-agent-v2/internal/modules/authentication"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/journal"
	"github.com/dynasmon/Seagull-agent-v2/internal/protocol"
	"github.com/dynasmon/Seagull-agent-v2/internal/spool"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

const installation = "5d0f6c9e-6a4b-4f43-9a3f-2f5a8f8f7c11"

var uuid = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-8[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

type opening struct {
	from   journal.Position
	follow bool
}

// A journal that answers as journalctl does: from the entry a cursor names when
// it holds it and from where that entry was otherwise, or from a moment on, and
// following, it waits for what is written next.
type fakeJournal struct {
	mu         sync.Mutex
	entries    []journal.Entry
	unreadable map[string]bool
	grown      chan struct{}
	opened     []opening
	refusal    error
}

func newJournal(entries ...journal.Entry) *fakeJournal {
	return &fakeJournal{entries: entries, unreadable: map[string]bool{}, grown: make(chan struct{})}
}

func (f *fakeJournal) write(entries ...journal.Entry) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.entries = append(f.entries, entries...)
	close(f.grown)
	f.grown = make(chan struct{})
}

func (f *fakeJournal) vacuum(before int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.entries = slices.DeleteFunc(f.entries, func(entry journal.Entry) bool { return sequence(entry.Cursor) < before })
}

func (f *fakeJournal) openings() []opening {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.opened)
}

func (f *fakeJournal) Open(ctx context.Context, from journal.Position, follow bool) (authentication.Entries, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.opened = append(f.opened, opening{from: from, follow: follow})
	if f.refusal != nil {
		return nil, f.refusal
	}
	start := len(f.entries)
	for i, entry := range f.entries {
		if (from.Cursor != "" && sequence(entry.Cursor) >= sequence(from.Cursor)) || (from.Cursor == "" && !entry.Realtime.Before(from.Since)) {
			start = i
			break
		}
	}
	at := 0
	if start < len(f.entries) {
		at = sequence(f.entries[start].Cursor)
	} else if len(f.entries) > 0 {
		at = sequence(f.entries[len(f.entries)-1].Cursor) + 1
	}
	return &fakeEntries{journal: f, ctx: ctx, at: at, follow: follow}, nil
}

type fakeEntries struct {
	journal *fakeJournal
	ctx     context.Context
	at      int
	follow  bool
	closed  bool
}

func (e *fakeEntries) pending() (journal.Entry, chan struct{}, bool) {
	for _, entry := range e.journal.entries {
		if sequence(entry.Cursor) >= e.at {
			return entry, nil, true
		}
	}
	return journal.Entry{}, e.journal.grown, false
}

func (e *fakeEntries) Next() (journal.Entry, error) {
	for {
		e.journal.mu.Lock()
		entry, grown, found := e.pending()
		broken := e.journal.unreadable[entry.Cursor]
		e.journal.mu.Unlock()
		if e.closed {
			return journal.Entry{}, context.Canceled
		}
		if found {
			e.at = sequence(entry.Cursor) + 1
			if broken {
				return journal.Entry{}, fmt.Errorf("%w: a test said so", journal.ErrUnreadable)
			}
			return entry, nil
		}
		if !e.follow {
			return journal.Entry{}, io.EOF
		}
		select {
		case <-e.ctx.Done():
			return journal.Entry{}, e.ctx.Err()
		case <-grown:
		}
	}
}

func (e *fakeEntries) Pending() bool {
	e.journal.mu.Lock()
	defer e.journal.mu.Unlock()
	_, _, found := e.pending()
	return found
}

func (e *fakeEntries) Close() error {
	e.closed = true
	return nil
}

func cursor(sequence int) string {
	return fmt.Sprintf("s=%032x;i=%x;b=%032x;m=%x;t=%x;x=%x", 0x5eed, sequence, 0xb007, sequence*1000, 0x65cc96285e8e5+sequence, sequence*7)
}

func sequence(cursor string) int {
	for part := range strings.SplitSeq(cursor, ";") {
		if hexadecimal, ok := strings.CutPrefix(part, "i="); ok {
			value, _ := strconv.ParseInt(hexadecimal, 16, 64)
			return int(value)
		}
	}
	return -1
}

func sshd(sequence int, at time.Time, message string) journal.Entry {
	return journal.Entry{Cursor: cursor(sequence), Realtime: at, Fields: map[string]string{
		"MESSAGE": message, "_COMM": "sshd", "_UID": "0", "_HOSTNAME": "web-01",
		"_SOURCE_REALTIME_TIMESTAMP": strconv.FormatInt(at.Add(-time.Millisecond).UnixMicro(), 10),
	}}
}

func failed(sequence int, at time.Time) journal.Entry {
	return sshd(sequence, at, fmt.Sprintf("Failed password for invalid user admin from 203.0.113.10 port %d ssh2", 40000+sequence))
}

type harness struct {
	t         *testing.T
	directory string
	spool     *spool.Spool
	governor  *governor.Governor
	journal   *fakeJournal
	log       *logged
	now       func() time.Time
}

type logged struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (l *logged) Write(content []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buffer.Write(content)
}

func (l *logged) lines(message string) []map[string]any {
	l.mu.Lock()
	defer l.mu.Unlock()
	var found []map[string]any
	for line := range strings.SplitSeq(l.buffer.String(), "\n") {
		entry := map[string]any{}
		if json.Unmarshal([]byte(line), &entry) == nil && entry["msg"] == message {
			found = append(found, entry)
		}
	}
	return found
}

func prepare(t *testing.T, held *fakeJournal, limits spool.Limits) *harness {
	t.Helper()
	base := t.TempDir()
	for _, name := range []string{"spool", "collection"} {
		if err := os.Mkdir(filepath.Join(base, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.OpenRoot(filepath.Join(base, "spool"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	log := &logged{}
	logger := slog.New(slog.NewJSONHandler(log, nil))
	kept, err := spool.Open(root, limits, logger)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { kept.Close() })
	governed, err := governor.New(logger, installation, governor.Budget{Scans: 1, ScanBytesPerSecond: 1 << 20, Uploads: 1, UploadBytesPerSecond: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	return &harness{t: t, directory: filepath.Join(base, "collection"), spool: kept, governor: governed, journal: held, log: log}
}

func (h *harness) collector(admitted authentication.Spool) *authentication.Collector {
	h.t.Helper()
	directory, err := os.OpenRoot(h.directory)
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { directory.Close() })
	if admitted == nil {
		admitted = h.spool
	}
	collector, err := authentication.New(authentication.Options{
		Installation: installation,
		Spool:        admitted,
		Governor:     h.governor,
		Directory:    directory,
		Logger:       slog.New(slog.NewJSONHandler(h.log, nil)),
		Open:         h.journal.Open,
		Now:          h.now,
	})
	if err != nil {
		h.t.Fatal(err)
	}
	return collector
}

type running struct {
	cancel context.CancelFunc
	done   chan error
}

func (h *harness) run(collector *authentication.Collector) *running {
	ctx, cancel := context.WithCancel(h.t.Context())
	done := make(chan error, 1)
	go func() { done <- collector.Collect(ctx) }()
	return &running{cancel: cancel, done: done}
}

func (r *running) stop(t *testing.T) {
	t.Helper()
	r.cancel()
	select {
	case err := <-r.done:
		if err != nil {
			t.Fatalf("the collector stopped with %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the collector did not return once asked to stop")
	}
}

func (h *harness) admitted() []spool.Entry {
	h.t.Helper()
	held, err := h.spool.Read(spool.Events, 1, 1<<16, 64<<20)
	if err != nil {
		h.t.Fatal(err)
	}
	return held
}

func (h *harness) await(count int) []spool.Entry {
	h.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		held := h.admitted()
		if len(held) >= count {
			return held
		}
		if time.Now().After(deadline) {
			h.t.Fatalf("the spool holds %d events, want %d:\n%s", len(held), count, h.log.buffer.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (h *harness) place() map[string]any {
	h.t.Helper()
	content, err := os.ReadFile(filepath.Join(h.directory, authentication.Name+".json"))
	if err != nil {
		h.t.Fatalf("read the place the collector wrote down: %v", err)
	}
	held := map[string]any{}
	if err := json.Unmarshal(content, &held); err != nil {
		h.t.Fatalf("read the place the collector wrote down: %v", err)
	}
	return held
}

func (h *harness) writePlace(t *testing.T, content string, mode os.FileMode) {
	t.Helper()
	path := filepath.Join(h.directory, authentication.Name+".json")
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func event(t *testing.T, held spool.Entry) *eventv1.Event {
	t.Helper()
	read := &eventv1.Event{}
	if err := proto.Unmarshal(held.Payload, read); err != nil {
		t.Fatalf("the spool holds %q, which is not an event: %v", held.ID, err)
	}
	if read.GetEventId() != held.ID {
		t.Fatalf("the spool holds event %s as %s", read.GetEventId(), held.ID)
	}
	return read
}

func port(t *testing.T, held spool.Entry) int {
	t.Helper()
	return int(event(t, held).GetAuthentication().GetNetwork().GetSource().GetPort())
}

func TestTheFirstRunReadsTheJournalFromThatMomentOn(t *testing.T) {
	began := time.Now().UTC()
	h := prepare(t, newJournal(failed(1, began.Add(-time.Minute)), failed(2, began.Add(-time.Second))), spool.Limits{MaxBytes: 64 << 20})
	collecting := h.run(h.collector(nil))
	deadline := time.Now().Add(5 * time.Second)
	for len(h.journal.openings()) < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	opened := h.journal.openings()
	if len(opened) != 2 || opened[0].follow || !opened[1].follow || opened[0].from.Cursor != "" || opened[0].from.Since.Before(began) || opened[1].from != opened[0].from {
		t.Fatalf("the journal was read from %+v", opened)
	}
	started := h.log.lines("collection_started")
	if len(started) != 1 || started[0]["module"] != authentication.Name || started[0]["source"] != "journal" {
		t.Errorf("the collector reported its start as %v", started)
	}
	place := h.place()
	if since, err := time.Parse(time.RFC3339Nano, fmt.Sprint(place["since"])); err != nil || since.Before(began) || place["cursor"] != nil {
		t.Errorf("before it read anything the collector wrote down %v", place)
	}
	h.journal.write(failed(3, time.Now().UTC()), sshd(4, time.Now().UTC(), "pam_unix(sshd:session): session opened for user nathan(uid=1000) by nathan(uid=0)"))
	held := h.await(1)
	collecting.stop(t)
	if len(held) != 1 || port(t, held[0]) != 40003 {
		t.Fatalf("the spool holds %d events, the first from port %d, and only the failure written after the collector started is one", len(held), port(t, held[0]))
	}
	if place := h.place(); place["cursor"] != cursor(4) || place["since"] != nil {
		t.Errorf("after reading the journal the collector wrote down %v, and the last entry it read is %s", place, cursor(4))
	}
}

func TestEachOutcomeSshdDecidesIsOneAuthenticationEvent(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	accepted := sshd(2, now, "Accepted publickey for nathan from 2001:db8::7 port 65196 ssh2: ED25519 SHA256:Eb5UakuU4YIHuQnWHylWxpNy0vbtHzMOUGbdwAxDkBM")
	accepted.Fields["_COMM"] = "sshd-session"
	h := prepare(t, newJournal(failed(1, now), accepted), spool.Limits{MaxBytes: 64 << 20})
	h.writePlace(t, `{"format":1,"since":"`+now.Add(-time.Hour).Format(time.RFC3339Nano)+`"}`, 0o600)
	collecting := h.run(h.collector(nil))
	held := h.await(2)
	collecting.stop(t)

	failure, success := event(t, held[0]), event(t, held[1])
	for _, read := range []*eventv1.Event{failure, success} {
		if !uuid.MatchString(read.GetEventId()) || read.GetSchemaVersion() != protocol.EventSchemaVersion || read.GetEventClass() != eventv1.EventClass_EVENT_CLASS_AUTHENTICATION ||
			read.GetOrigin().GetAgentId() != "" || read.GetOrigin().GetTenantId() != "" || read.GetReception() != nil ||
			read.GetOrigin().GetHost().GetHostname() != "web-01" || read.GetOrigin().GetHost().GetOs() != "linux" || read.GetOrigin().GetHost().GetArchitecture() != runtime.GOARCH ||
			read.GetOrigin().GetHost().GetIp() != "" || read.GetCollection().GetCollector() != authentication.Name || read.GetCollection().GetSequence() != 0 {
			t.Errorf("an event was written as %v", read)
		}
		body := read.GetAuthentication()
		if body.GetActivity() != eventv1.Authentication_ACTIVITY_LOGON || body.GetService().GetName() != "sshd" || body.GetService().GetProtocol() != "ssh" ||
			body.GetNetwork().GetTransport() != eventv1.Transport_TRANSPORT_TCP || body.GetNetwork().GetDestination() != nil {
			t.Errorf("an authentication was written as %v", body)
		}
	}
	if failure.GetEventId() == success.GetEventId() {
		t.Error("two entries made one event")
	}
	body := failure.GetAuthentication()
	if body.GetOutcome() != eventv1.Outcome_OUTCOME_FAILURE || body.GetOutcomeReason() != "invalid user" || body.GetMethod() != "password" || body.GetUser().GetName() != "admin" ||
		body.GetNetwork().GetSource().GetIp() != "203.0.113.10" || body.GetNetwork().GetSource().GetPort() != 40001 || failure.GetCollection().GetSource() != "journal:sshd" ||
		body.GetRawRecord() != "Failed password for invalid user admin from 203.0.113.10 port 40001 ssh2" ||
		!failure.GetTime().GetEventTime().AsTime().Equal(now.Add(-time.Millisecond)) || !failure.GetTime().GetObservedTime().AsTime().Equal(now) {
		t.Errorf("the failure was written as %v", failure)
	}
	body = success.GetAuthentication()
	if body.GetOutcome() != eventv1.Outcome_OUTCOME_SUCCESS || body.GetOutcomeReason() != "" || body.GetMethod() != "publickey" || body.GetUser().GetName() != "nathan" ||
		body.GetNetwork().GetSource().GetIp() != "2001:db8::7" || body.GetNetwork().GetSource().GetPort() != 65196 || success.GetCollection().GetSource() != "journal:sshd-session" {
		t.Errorf("the success was written as %v", success)
	}
}

func TestOnlyWhatSshdWroteAsTheSuperuserIsAnOutcome(t *testing.T) {
	now := time.Now().UTC()
	forged := failed(1, now)
	forged.Fields["_UID"] = "1000"
	logger := failed(2, now)
	logger.Fields["_COMM"] = "logger"
	nameless := failed(3, now)
	delete(nameless.Fields, "_COMM")
	h := prepare(t, newJournal(forged, logger, nameless,
		sshd(4, now, "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.10  user=root"),
		sshd(5, now, "Invalid user admin from 203.0.113.10 port 40005"),
		sshd(6, now, "Server listening on 0.0.0.0 port 22."),
		failed(7, now)), spool.Limits{MaxBytes: 64 << 20})
	h.writePlace(t, `{"format":1,"since":"`+now.Add(-time.Hour).Format(time.RFC3339Nano)+`"}`, 0o600)
	collecting := h.run(h.collector(nil))
	held := h.await(1)
	collecting.stop(t)
	if len(held) != 1 || port(t, held[0]) != 40007 {
		t.Fatalf("the spool holds %d events, and only the failure sshd wrote as the superuser is one", len(held))
	}
	if place := h.place(); place["cursor"] != cursor(7) {
		t.Errorf("the collector wrote down %v after reading every entry", place)
	}
}

func TestEventsAreAdmittedBeforeTheirPlaceIsWrittenDown(t *testing.T) {
	now := time.Now().UTC()
	var entries []journal.Entry
	for i := 1; i <= 600; i++ {
		entries = append(entries, failed(i, now))
	}
	h := prepare(t, newJournal(entries...), spool.Limits{MaxBytes: 64 << 20})
	h.writePlace(t, `{"format":1,"since":"`+now.Add(-time.Hour).Format(time.RFC3339Nano)+`"}`, 0o600)
	checking := &checking{t: t, harness: h}
	collecting := h.run(h.collector(checking))
	h.await(600)
	collecting.stop(t)
	checking.mu.Lock()
	defer checking.mu.Unlock()
	if checking.admissions < 3 || checking.largest > 256 {
		t.Errorf("600 events were admitted in %d admissions of at most %d", checking.admissions, checking.largest)
	}
}

type checking struct {
	t          *testing.T
	harness    *harness
	mu         sync.Mutex
	admissions int
	largest    int
}

func (c *checking) Admit(stream spool.Stream, records ...spool.Record) (spool.Receipt, error) {
	place := c.harness.place()
	reached := sequence(fmt.Sprint(place["cursor"]))
	for _, record := range records {
		if at := port(c.t, spool.Entry{ID: record.ID, Payload: record.Payload}) - 40000; at <= reached {
			c.t.Errorf("the collector wrote down entry %d before the event of entry %d was admitted", reached, at)
		}
	}
	c.mu.Lock()
	c.admissions++
	c.largest = max(c.largest, len(records))
	c.mu.Unlock()
	return c.harness.spool.Admit(stream, records...)
}

func (c *checking) Room(stream spool.Stream) int64 { return c.harness.spool.Room(stream) }

func TestAStartResumesAfterTheLastEntryWrittenDown(t *testing.T) {
	now := time.Now().UTC()
	h := prepare(t, newJournal(failed(1, now), failed(2, now)), spool.Limits{MaxBytes: 64 << 20})
	h.writePlace(t, `{"format":1,"since":"`+now.Add(-time.Hour).Format(time.RFC3339Nano)+`"}`, 0o600)
	collector := h.collector(nil)
	collecting := h.run(collector)
	h.await(2)
	collecting.stop(t)
	h.journal.write(failed(3, now), failed(4, now))
	collecting = h.run(collector)
	held := h.await(4)
	collecting.stop(t)
	if len(held) != 4 || port(t, held[2]) != 40003 || port(t, held[3]) != 40004 {
		t.Fatalf("after a restart the spool holds %d events", len(held))
	}
	opened := h.journal.openings()
	if len(opened) != 4 || opened[2].from.Cursor != cursor(2) || opened[2].follow || opened[3].from.Cursor != cursor(4) || !opened[3].follow {
		t.Errorf("the journal was read from %+v", opened)
	}
	if resumed := h.log.lines("collection_resumed"); len(resumed) != 1 {
		t.Errorf("the collector reported resuming as %v", resumed)
	}
	if gaps := h.log.lines("collection_gap"); len(gaps) != 0 {
		t.Errorf("the collector reported a gap where there was none: %v", gaps)
	}
	if stats := collector.Stats(); stats.Admitted != 4 || stats.Gaps != 0 || !stats.Reached.Equal(now) {
		t.Errorf("the collector counted %+v", stats)
	}
}

func TestAnEntryReadAgainIsTheSameEventByteForByte(t *testing.T) {
	now := time.Now().UTC()
	h := prepare(t, newJournal(failed(1, now), failed(2, now), failed(3, now)), spool.Limits{MaxBytes: 64 << 20})
	written := `{"format":1,"since":"` + now.Add(-time.Hour).Format(time.RFC3339Nano) + `"}`
	h.writePlace(t, written, 0o600)
	collecting := h.run(h.collector(nil))
	h.await(3)
	collecting.stop(t)
	h.writePlace(t, written, 0o600)
	collecting = h.run(h.collector(nil))
	held := h.await(6)
	collecting.stop(t)
	for i := range 3 {
		if held[i].ID != held[i+3].ID || !bytes.Equal(held[i].Payload, held[i+3].Payload) {
			t.Errorf("entry %d read twice was admitted as %s and as %s", i+1, held[i].ID, held[i+3].ID)
		}
	}
}

func TestAPlaceTheJournalNoLongerHoldsIsReportedAsAGap(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	h := prepare(t, newJournal(failed(1, now), failed(2, now)), spool.Limits{MaxBytes: 64 << 20})
	h.writePlace(t, `{"format":1,"since":"`+now.Add(-time.Hour).Format(time.RFC3339Nano)+`"}`, 0o600)
	collecting := h.run(h.collector(nil))
	h.await(2)
	collecting.stop(t)
	h.journal.write(failed(3, now.Add(time.Second)), failed(4, now.Add(2*time.Second)))
	h.journal.vacuum(4)
	collecting = h.run(h.collector(nil))
	held := h.await(3)
	collecting.stop(t)
	if len(held) != 3 || port(t, held[2]) != 40004 {
		t.Fatalf("after the journal dropped entries the spool holds %d events", len(held))
	}
	gaps := h.log.lines("collection_gap")
	if len(gaps) != 1 || gaps[0]["level"] != "WARN" || gaps[0]["after"] != now.Format(time.RFC3339Nano) ||
		gaps[0]["next"] != now.Add(2*time.Second).Format(time.RFC3339Nano) || gaps[0]["recovery"] == nil {
		t.Errorf("the collector reported the gap as %v", gaps)
	}
	h.journal.vacuum(100)
	collecting = h.run(h.collector(nil))
	deadline := time.Now().Add(5 * time.Second)
	for len(h.log.lines("collection_gap")) < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	collecting.stop(t)
	if gaps := h.log.lines("collection_gap"); len(gaps) != 2 || gaps[1]["next"] != nil {
		t.Errorf("a journal that holds nothing after the place was reported as %v", gaps)
	}
}

func TestAPlaceThatCannotBeReadIsReadAgainFromWhatThePlatformAdmits(t *testing.T) {
	now := time.Now().UTC()
	for name, content := range map[string]string{
		"not json":           "{",
		"no format":          `{"cursor":"` + cursor(1) + `","read":"` + now.Format(time.RFC3339Nano) + `"}`,
		"a damaged cursor":   `{"format":1,"cursor":"s=1","read":"` + now.Format(time.RFC3339Nano) + `"}`,
		"a cursor and since": `{"format":1,"cursor":"` + cursor(1) + `","read":"` + now.Format(time.RFC3339Nano) + `","since":"` + now.Format(time.RFC3339Nano) + `"}`,
		"neither":            `{"format":1}`,
		"an unknown setting": `{"format":1,"since":"` + now.Format(time.RFC3339Nano) + `","offset":3}`,
		"two places":         `{"format":1,"since":"` + now.Format(time.RFC3339Nano) + `"}{"format":1}`,
	} {
		t.Run(name, func(t *testing.T) {
			h := prepare(t, newJournal(failed(1, now.Add(-100*time.Hour)), failed(2, now.Add(-200*time.Hour))), spool.Limits{MaxBytes: 64 << 20})
			h.writePlace(t, content, 0o600)
			collecting := h.run(h.collector(nil))
			held := h.await(1)
			collecting.stop(t)
			if len(held) != 1 || port(t, held[0]) != 40001 {
				t.Errorf("the collector admitted %d events from the week the platform admits", len(held))
			}
			lost := h.log.lines("collection_place_lost")
			opened := h.journal.openings()
			if len(lost) != 1 || lost[0]["level"] != "WARN" || len(opened) == 0 || opened[0].from.Since.After(now.Add(-protocol.MaxEventAge+time.Minute)) {
				t.Errorf("the collector reported %v and read from %+v", lost, opened)
			}
		})
	}
}

func TestAPlaceTheCollectorCannotTrustStopsIt(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the agent keeps its installation private on unix")
	}
	for name, written := range map[string]struct {
		content string
		mode    os.FileMode
		want    error
	}{
		"newer":           {content: `{"format":2,"since":"2026-10-01T00:00:00Z","read_from":"elsewhere"}`, mode: 0o600, want: authentication.ErrNewer},
		"open to others":  {content: `{"format":1,"since":"2026-10-01T00:00:00Z"}`, mode: 0o644, want: authentication.ErrInsecure},
		"open to a group": {content: `{"format":1,"since":"2026-10-01T00:00:00Z"}`, mode: 0o640, want: authentication.ErrInsecure},
	} {
		t.Run(name, func(t *testing.T) {
			h := prepare(t, newJournal(), spool.Limits{MaxBytes: 64 << 20})
			h.writePlace(t, written.content, written.mode)
			err := h.collector(nil).Collect(t.Context())
			if !errors.Is(err, written.want) || len(h.journal.openings()) != 0 {
				t.Errorf("the collector returned %v and read the journal from %+v", err, h.journal.openings())
			}
		})
	}
	h := prepare(t, newJournal(), spool.Limits{MaxBytes: 64 << 20})
	if err := os.Symlink("/etc/hostname", filepath.Join(h.directory, authentication.Name+".json")); err != nil {
		t.Fatal(err)
	}
	if err := h.collector(nil).Collect(t.Context()); !errors.Is(err, authentication.ErrInsecure) {
		t.Errorf("a place that is a link was read, and the collector returned %v", err)
	}
}

func TestAnInterruptedWriteOfThePlaceIsDiscarded(t *testing.T) {
	now := time.Now().UTC()
	h := prepare(t, newJournal(failed(1, now)), spool.Limits{MaxBytes: 64 << 20})
	h.writePlace(t, `{"format":1,"since":"`+now.Add(-time.Hour).Format(time.RFC3339Nano)+`"}`, 0o600)
	left := filepath.Join(h.directory, "."+authentication.Name+".json.0123456789abcdef.tmp")
	other := filepath.Join(h.directory, "inventory.json")
	for _, path := range []string{left, other} {
		if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	collecting := h.run(h.collector(nil))
	h.await(1)
	collecting.stop(t)
	if _, err := os.Stat(left); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the interrupted write was left: %v", err)
	}
	if _, err := os.Stat(other); err != nil {
		t.Errorf("what another collector keeps beside it was taken: %v", err)
	}
	listed, err := os.ReadDir(h.directory)
	if err != nil || len(listed) != 2 {
		t.Errorf("the collector left %v: %v", listed, err)
	}
}

func TestEntriesOlderThanThePlatformAdmitsAreReadPastAndReported(t *testing.T) {
	now := time.Now().UTC()
	h := prepare(t, newJournal(failed(1, now.Add(-protocol.MaxEventAge-time.Hour)), failed(2, now.Add(-protocol.MaxEventAge-time.Minute)), failed(3, now)), spool.Limits{MaxBytes: 64 << 20})
	h.writePlace(t, `{"format":1,"since":"`+now.Add(-30*24*time.Hour).Format(time.RFC3339Nano)+`"}`, 0o600)
	collector := h.collector(nil)
	collecting := h.run(collector)
	held := h.await(1)
	collecting.stop(t)
	if len(held) != 1 || port(t, held[0]) != 40003 {
		t.Fatalf("the spool holds %d events", len(held))
	}
	if old := h.log.lines("collection_entries_too_old"); len(old) != 2 || old[1]["too_old"] != float64(2) || collector.Stats().Aged != 2 {
		t.Errorf("the collector reported old entries as %v", old)
	}
}

func TestTheCollectorJudgesAgesAndStartsByItsClock(t *testing.T) {
	recorded := time.Date(2026, 10, 1, 16, 0, 0, 0, time.UTC)
	clock := func() time.Time { return recorded.Add(protocol.MaxEventAge).Add(-30 * time.Second) }
	h := prepare(t, newJournal(failed(1, recorded.Add(-time.Minute)), failed(2, recorded), failed(3, recorded.Add(time.Minute))), spool.Limits{MaxBytes: 64 << 20})
	h.now = clock
	h.writePlace(t, `{"format":1,"since":"`+recorded.Add(-time.Hour).Format(time.RFC3339Nano)+`"}`, 0o600)
	collecting := h.run(h.collector(nil))
	held := h.await(2)
	collecting.stop(t)
	if len(held) != 2 || port(t, held[0]) != 40002 || port(t, held[1]) != 40003 {
		t.Errorf("by a clock a week after the entries the collector admitted %d events", len(held))
	}

	h = prepare(t, newJournal(failed(1, recorded)), spool.Limits{MaxBytes: 64 << 20})
	h.now = clock
	collecting = h.run(h.collector(nil))
	deadline := time.Now().Add(5 * time.Second)
	for len(h.journal.openings()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	collecting.stop(t)
	if opened := h.journal.openings(); len(opened) == 0 || !opened[0].from.Since.Equal(clock()) {
		t.Errorf("a collector that never ran started reading at %+v, and its clock says %s", opened, clock())
	}
}

func TestAnEntryThatCannotBeReadIsCountedAndReadPast(t *testing.T) {
	now := time.Now().UTC()
	var entries []journal.Entry
	for i := 1; i <= 6; i++ {
		entries = append(entries, failed(i, now))
	}
	held := newJournal(entries...)
	for _, broken := range []int{1, 2, 3, 4, 5} {
		held.unreadable[cursor(broken)] = true
	}
	h := prepare(t, held, spool.Limits{MaxBytes: 64 << 20})
	h.writePlace(t, `{"format":1,"since":"`+now.Add(-time.Hour).Format(time.RFC3339Nano)+`"}`, 0o600)
	collector := h.collector(nil)
	collecting := h.run(collector)
	admitted := h.await(1)
	collecting.stop(t)
	if len(admitted) != 1 || port(t, admitted[0]) != 40006 {
		t.Fatalf("the spool holds %d events", len(admitted))
	}
	if reported := h.log.lines("collection_entry_unreadable"); len(reported) != 3 || collector.Stats().Unreadable != 5 {
		t.Errorf("five entries that could not be read were reported %d times: %v", len(reported), reported)
	}
}

func TestAFullSpoolHoldsThePlaceUntilItTakesTheEvents(t *testing.T) {
	now := time.Now().UTC()
	h := prepare(t, newJournal(), spool.Limits{MaxBytes: 16 << 20, MaxRecordBytes: 1 << 20})
	filler := make([]byte, 1<<20-1<<10)
	var filled []uint64
	for i := 0; ; i++ {
		receipt, err := h.spool.Admit(spool.Events, spool.Record{ID: fmt.Sprintf("filler-%d", i), Payload: filler})
		if errors.Is(err, spool.ErrFull) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		filled = append(filled, receipt.First)
	}
	room := h.spool.Room(spool.Events)
	h.writePlace(t, `{"format":1,"since":"`+now.Add(-time.Hour).Format(time.RFC3339Nano)+`"}`, 0o600)
	var entries []journal.Entry
	for i := 1; int64(i*300) < room+64<<10; i++ {
		entries = append(entries, failed(i, now))
	}
	h.journal.write(entries...)
	collector := h.collector(nil)
	collecting := h.run(collector)
	deadline := time.Now().Add(5 * time.Second)
	for collector.Stats().Waiting.IsZero() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if collector.Stats().Waiting.IsZero() {
		t.Fatalf("the collector did not wait for room in a full spool:\n%s", h.log.buffer.String())
	}
	if place := h.place(); place["cursor"] != nil {
		t.Errorf("while its events waited for room the collector wrote down %v", place)
	}
	if err := h.spool.Acknowledge(spool.Events, filled[:4]...); err != nil {
		t.Fatal(err)
	}
	held := h.await(len(filled) - 4 + len(entries))
	collecting.stop(t)
	if place := h.place(); place["cursor"] != cursor(len(entries)) || !collector.Stats().Waiting.IsZero() || len(held) != len(filled)-4+len(entries) {
		t.Errorf("once the spool took the events the collector wrote down %v", place)
	}
}

func TestAJournalTheAgentMayNotReadStopsTheCollector(t *testing.T) {
	held := newJournal()
	held.refusal = fmt.Errorf("%w: journalctl stopped, exit status 1: No journal files were opened due to insufficient permissions.", journal.ErrDenied)
	h := prepare(t, held, spool.Limits{MaxBytes: 64 << 20})
	err := h.collector(nil).Collect(t.Context())
	if !errors.Is(err, journal.ErrDenied) || !strings.Contains(err.Error(), "systemd-journal") {
		t.Errorf("the collector returned %v", err)
	}
}

func TestACollectorNeedsWhatItWorksWith(t *testing.T) {
	h := prepare(t, newJournal(), spool.Limits{MaxBytes: 64 << 20})
	directory, err := os.OpenRoot(h.directory)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	logger := slog.New(slog.DiscardHandler)
	for name, options := range map[string]authentication.Options{
		"no installation": {Spool: h.spool, Governor: h.governor, Directory: directory, Logger: logger},
		"no spool":        {Installation: installation, Governor: h.governor, Directory: directory, Logger: logger},
		"no governor":     {Installation: installation, Spool: h.spool, Directory: directory, Logger: logger},
		"no directory":    {Installation: installation, Spool: h.spool, Governor: h.governor, Logger: logger},
		"no logger":       {Installation: installation, Spool: h.spool, Governor: h.governor, Directory: directory},
	} {
		if _, err := authentication.New(options); err == nil {
			t.Errorf("%s: the collector was composed", name)
		}
	}
	if _, err := authentication.New(authentication.Options{Installation: installation, Spool: h.spool, Governor: h.governor, Directory: directory, Logger: logger}); err != nil {
		t.Errorf("a collector that reads the journal of this host was refused: %v", err)
	}
}
