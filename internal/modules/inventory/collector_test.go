package inventory_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-agent-v2/internal/governor"
	"github.com/dynasmon/Seagull-agent-v2/internal/modules/inventory"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/accounts"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/dpkg"
	"github.com/dynasmon/Seagull-agent-v2/internal/spool"
	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
)

var every = []string{"operating_system", "kernel", "hardware", "package", "service", "network_interface", "user"}

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

func (l *logged) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buffer.String()
}

type harness struct {
	t         *testing.T
	directory string
	spool     *spool.Spool
	governor  *governor.Governor
	host      *fakeHost
	log       *logged
}

func prepare(t *testing.T, limits spool.Limits) *harness {
	t.Helper()
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("the collector keeps its baseline where it can tell who owns it")
	}
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
	governed, err := governor.New(logger, installation, governor.Budget{Scans: 1, ScanBytesPerSecond: 64 << 20, Uploads: 1, UploadBytesPerSecond: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	return &harness{t: t, directory: filepath.Join(base, "collection"), spool: kept, governor: governed, host: newHost(), log: log}
}

func (h *harness) collector(adjust func(*inventory.Options)) *inventory.Collector {
	h.t.Helper()
	directory, err := os.OpenRoot(h.directory)
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { directory.Close() })
	options := inventory.Options{
		Installation: installation,
		Spool:        h.spool,
		Governor:     h.governor,
		Directory:    directory,
		Logger:       slog.New(slog.NewJSONHandler(h.log, nil)),
		Host:         h.host,
	}
	if adjust != nil {
		adjust(&options)
	}
	collector, err := inventory.New(options)
	if err != nil {
		h.t.Fatal(err)
	}
	return collector
}

type running struct {
	cancel context.CancelFunc
	done   chan error
}

func run(t *testing.T, collector *inventory.Collector) *running {
	ctx, cancel := context.WithCancel(t.Context())
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

func rounds(t *testing.T, collector *inventory.Collector, count int, log *logged) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	seen, last := 0, time.Time{}
	for seen < count {
		if round := collector.Stats().Round; !round.Equal(last) {
			seen, last = seen+1, round
			continue
		}
		if time.Now().After(deadline) {
			t.Fatalf("the collector finished %d rounds, want %d:\n%s", seen, count, log)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// round runs a collector of its own for one round at the moment given, as
// the agent would after starting again, and stops it.
func (h *harness) round(at time.Time, adjust ...func(*inventory.Options)) *inventory.Collector {
	h.t.Helper()
	collector := h.collector(func(options *inventory.Options) {
		options.Now = func() time.Time { return at }
		for _, adjusted := range adjust {
			adjusted(options)
		}
	})
	collecting := run(h.t, collector)
	deadline := time.Now().Add(10 * time.Second)
	for collector.Stats().Round.IsZero() {
		select {
		case err := <-collecting.done:
			h.t.Fatalf("the collector stopped in its first round with %v:\n%s", err, h.log)
		default:
		}
		if time.Now().After(deadline) {
			h.t.Fatalf("the collector did not finish a round:\n%s", h.log)
		}
		time.Sleep(5 * time.Millisecond)
	}
	collecting.stop(h.t)
	return collector
}

func (h *harness) admitted() []*inventoryv1.Record {
	h.t.Helper()
	held, err := h.spool.Read(spool.Inventory, 1, 1<<16, 64<<20)
	if err != nil {
		h.t.Fatal(err)
	}
	records := make([]*inventoryv1.Record, 0, len(held))
	for _, entry := range held {
		record := &inventoryv1.Record{}
		if err := proto.Unmarshal(entry.Payload, record); err != nil || record.GetRecordId() != entry.ID {
			h.t.Fatalf("the spool holds %q, which is no inventory record of that name: %v", entry.ID, err)
		}
		records = append(records, record)
	}
	return records
}

func kindsOf(records []*inventoryv1.Record) []string {
	var named []string
	for _, record := range records {
		named = append(named, inventory.KindName(record.GetKind()))
	}
	return named
}

func (h *harness) baseline() map[string]map[string]any {
	h.t.Helper()
	content, err := os.ReadFile(filepath.Join(h.directory, inventory.Name+".json"))
	if err != nil {
		h.t.Fatalf("read the baseline: %v", err)
	}
	var held struct {
		Kinds map[string]map[string]any `json:"kinds"`
	}
	if err := json.Unmarshal(content, &held); err != nil {
		h.t.Fatalf("read the baseline: %v", err)
	}
	return held.Kinds
}

func TestTheFirstRoundAdmitsAWholeSnapshotOfEveryKindTheHostHas(t *testing.T) {
	h := prepare(t, spool.Limits{MaxBytes: 64 << 20})
	at := time.Date(2026, 10, 5, 13, 0, 0, 0, time.UTC)
	collector := h.round(at)
	records := h.admitted()
	if !slices.Equal(kindsOf(records), every) {
		t.Fatalf("the first round admitted %v", kindsOf(records))
	}
	held := h.baseline()
	for _, record := range records {
		name := inventory.KindName(record.GetKind())
		if record.GetMode() != inventoryv1.Mode_MODE_SNAPSHOT || !record.GetCollectedAt().AsTime().Equal(at) || held[name]["record_id"] != record.GetRecordId() {
			t.Errorf("the %s was admitted as %v and written down as %v", name, record, held[name])
		}
		if want := taken(t, h.host, record.GetKind(), at); !proto.Equal(record, want.Record) {
			t.Errorf("the %s was admitted as\n%v\nand taken as\n%v", name, record, want.Record)
		}
	}
	stats := collector.Stats()
	if len(stats.Kinds) != len(every) || stats.Kinds[3].Kind != "package" || stats.Kinds[3].Items != 4 || !stats.Kinds[3].Sent.Equal(at) || stats.Kinds[3].Failure != nil {
		t.Errorf("the collector says %+v", stats)
	}
	if admitted := h.log.lines("inventory_admitted"); len(admitted) != len(every) || admitted[0]["because"] != "first" {
		t.Errorf("the collector logged %v", admitted)
	}
}

func TestAnUnchangedHostIsAdmittedAgainOnlyBeforeWhatThePlatformHoldsIsADayOld(t *testing.T) {
	h := prepare(t, spool.Limits{MaxBytes: 64 << 20})
	at := time.Date(2026, 10, 5, 13, 0, 0, 0, time.UTC)
	h.round(at)
	h.round(at.Add(time.Hour))
	h.round(at.Add(23*time.Hour + 29*time.Minute))
	if records := h.admitted(); len(records) != len(every) {
		t.Fatalf("an unchanged host was admitted again within a day: %v", kindsOf(records))
	}
	h.round(at.Add(23*time.Hour + 30*time.Minute))
	records := h.admitted()
	if again := kindsOf(records[len(every):]); !slices.Equal(again, every) {
		t.Fatalf("before the snapshots were a day old the collector admitted %v", again)
	}
	if logged := h.log.lines("inventory_admitted"); logged[len(logged)-1]["because"] != "refreshed" {
		t.Errorf("the collector logged %v", logged[len(logged)-1])
	}
	h.round(at.Add(23*time.Hour+31*time.Minute), func(options *inventory.Options) { options.Interval = func() time.Duration { return 24 * time.Hour } })
	if records := h.admitted(); len(records) != 2*len(every) {
		t.Errorf("a minute after a refresh the collector admitted %v", kindsOf(records[2*len(every):]))
	}
}

func TestOnlyTheKindThatChangedIsAdmittedAgain(t *testing.T) {
	h := prepare(t, spool.Limits{MaxBytes: 64 << 20})
	at := time.Date(2026, 10, 5, 13, 0, 0, 0, time.UTC)
	h.round(at)
	h.host.change(func(host *fakeHost) {
		host.packages[0].Version, host.packages[0].SourceVersion = "3.0.13-0ubuntu3.5", "3.0.13-0ubuntu3.5"
	})
	h.round(at.Add(time.Hour))
	records := h.admitted()
	if again := kindsOf(records[len(every):]); !slices.Equal(again, []string{"package"}) {
		t.Fatalf("after an upgrade the collector admitted %v", again)
	}
	upgraded := records[len(records)-1]
	if !slices.ContainsFunc(upgraded.GetItems(), func(item *inventoryv1.Item) bool { return item.GetPackage().GetVersion() == "3.0.13-0ubuntu3.5" }) ||
		!upgraded.GetCollectedAt().AsTime().Equal(at.Add(time.Hour)) || upgraded.GetRecordId() == records[3].GetRecordId() {
		t.Errorf("the upgrade was admitted as %v", upgraded)
	}
	if logged := h.log.lines("inventory_admitted"); logged[len(logged)-1]["because"] != "changed" {
		t.Errorf("the collector logged %v", logged[len(logged)-1])
	}

	h.host.change(func(host *fakeHost) {
		host.packages = slices.DeleteFunc(host.packages, func(held dpkg.Package) bool { return held.Name == "openssl" })
	})
	h.round(at.Add(2 * time.Hour))
	if records := h.admitted(); len(records) != len(every)+2 || len(records[len(records)-1].GetItems()) != 3 {
		t.Errorf("after a removal the collector admitted %v", kindsOf(records[len(every):]))
	}
}

type checking struct {
	t       *testing.T
	harness *harness
}

func (c *checking) Admit(stream spool.Stream, records ...spool.Record) (spool.Receipt, error) {
	content, err := os.ReadFile(filepath.Join(c.harness.directory, inventory.Name+".json"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		c.t.Error(err)
	}
	for _, record := range records {
		if bytes.Contains(content, []byte(record.ID)) {
			c.t.Errorf("the baseline named %s before the spool took it", record.ID)
		}
	}
	return c.harness.spool.Admit(stream, records...)
}

func (c *checking) Room(stream spool.Stream) int64 { return c.harness.spool.Room(stream) }

func TestASnapshotIsDurableBeforeTheBaselineNamesIt(t *testing.T) {
	h := prepare(t, spool.Limits{MaxBytes: 64 << 20})
	at := time.Date(2026, 10, 5, 13, 0, 0, 0, time.UTC)
	checked := func(options *inventory.Options) { options.Spool = &checking{t: t, harness: h} }
	h.round(at, checked)
	h.host.change(func(host *fakeHost) { host.hostname = "web-02" })
	h.round(at.Add(time.Hour), checked)
	if records := h.admitted(); len(records) != 2*len(every) {
		t.Errorf("the collector admitted %v", kindsOf(records))
	}
}

func TestAKindThatCannotBeTakenLeavesWhatThePlatformHoldsAndSaysWhyOnce(t *testing.T) {
	h := prepare(t, spool.Limits{MaxBytes: 64 << 20})
	h.host.change(func(host *fakeHost) {
		host.failures["user"] = fmt.Errorf("%w: open /etc/group: permission denied", accounts.ErrUnreadable)
	})
	collector := h.collector(func(options *inventory.Options) { options.Interval = func() time.Duration { return time.Second } })
	collecting := run(t, collector)
	rounds(t, collector, 2, h.log)
	if records := h.admitted(); !slices.Equal(kindsOf(records), every[:6]) {
		t.Errorf("with its account files unreadable the collector admitted %v", kindsOf(records))
	}
	stats := collector.Stats()
	if failure := stats.Kinds[6].Failure; !errors.Is(failure, accounts.ErrUnreadable) {
		t.Errorf("the collector says the users are %+v", stats.Kinds[6])
	}
	if refused := h.log.lines("inventory_not_collected"); len(refused) != 1 || refused[0]["kind"] != "user" || refused[0]["level"] != "WARN" || refused[0]["recovery"] == nil {
		t.Errorf("over two rounds the collector logged %v", refused)
	}
	h.host.change(func(host *fakeHost) { delete(host.failures, "user") })
	rounds(t, collector, 2, h.log)
	collecting.stop(t)
	if records := h.admitted(); !slices.Equal(kindsOf(records), every) || collector.Stats().Kinds[6].Failure != nil {
		t.Errorf("once it could read them the collector admitted %v", kindsOf(records))
	}
	if again := h.log.lines("inventory_collected_again"); len(again) != 1 || again[0]["kind"] != "user" {
		t.Errorf("the collector logged %v", again)
	}
}

func TestAKindTheHostDoesNotHaveIsNotTakenAndSaidOnce(t *testing.T) {
	h := prepare(t, spool.Limits{MaxBytes: 64 << 20})
	h.host.change(func(host *fakeHost) { host.failures["package"] = fmt.Errorf("%w: no dpkg-query", dpkg.ErrAbsent) })
	collector := h.round(time.Date(2026, 10, 5, 13, 0, 0, 0, time.UTC))
	if records := h.admitted(); slices.Contains(kindsOf(records), "package") || len(records) != len(every)-1 {
		t.Errorf("on a host without dpkg the collector admitted %v", kindsOf(records))
	}
	if !errors.Is(collector.Stats().Kinds[3].Failure, inventory.ErrUnsupported) {
		t.Errorf("the collector says the packages are %+v", collector.Stats().Kinds[3])
	}
	if refused := h.log.lines("inventory_not_collected"); len(refused) != 1 || refused[0]["level"] != "INFO" || refused[0]["recovery"] != "none: this kind is not taken on this host" {
		t.Errorf("the collector logged %v", refused)
	}
}

func TestASnapshotLargerThanABatchCarriesWaitsForALargerBatch(t *testing.T) {
	h := prepare(t, spool.Limits{MaxBytes: 64 << 20})
	collector := h.round(time.Date(2026, 10, 5, 13, 0, 0, 0, time.UTC), func(options *inventory.Options) { options.Largest = func() int64 { return 300 } })
	records := h.admitted()
	if slices.Contains(kindsOf(records), "package") || !slices.Contains(kindsOf(records), "operating_system") {
		t.Errorf("with batches of 300 bytes the collector admitted %v", kindsOf(records))
	}
	if failure := collector.Stats().Kinds[3].Failure; !errors.Is(failure, inventory.ErrBeyondBatch) {
		t.Errorf("the collector says the packages are %v", failure)
	}
	if refused := h.log.lines("inventory_not_collected"); len(refused) == 0 || !strings.Contains(fmt.Sprint(refused[0]["recovery"]), "transport.max_batch_bytes") {
		t.Errorf("the collector logged %v", refused)
	}
}

func TestASnapshotTakenNoLaterThanTheLastIsHeldBackUntilTheClockPassesIt(t *testing.T) {
	h := prepare(t, spool.Limits{MaxBytes: 64 << 20})
	at := time.Date(2026, 10, 5, 13, 0, 0, 0, time.UTC)
	h.round(at)
	h.host.change(func(host *fakeHost) { host.packages = host.packages[1:] })
	for _, behind := range []time.Time{at.Add(500 * time.Microsecond), at.Add(-2 * time.Minute)} {
		collector := h.round(behind)
		if records := h.admitted(); len(records) != len(every) {
			t.Fatalf("a snapshot taken at %s, after one at %s, was admitted: %v", behind, at, kindsOf(records[len(every):]))
		}
		if !errors.Is(collector.Stats().Kinds[3].Failure, inventory.ErrClockBehind) {
			t.Errorf("the collector says the packages are %+v", collector.Stats().Kinds[3])
		}
	}
	if deferred := h.log.lines("inventory_deferred"); len(deferred) != 2 || deferred[0]["kind"] != "package" {
		t.Errorf("the collector logged %v", deferred)
	}
	h.round(at.Add(time.Millisecond))
	if records := h.admitted(); len(records) != len(every)+1 || !records[len(records)-1].GetCollectedAt().AsTime().Equal(at.Add(time.Millisecond)) {
		t.Errorf("once the clock passed the last snapshot the collector admitted %v", kindsOf(records[len(every):]))
	}
}

func TestASnapshotAfterTheClockWentFarBackIsAdmittedAtTheTimeTheClockReads(t *testing.T) {
	h := prepare(t, spool.Limits{MaxBytes: 64 << 20})
	ahead := time.Date(2027, 10, 5, 13, 0, 0, 0, time.UTC)
	h.round(ahead)
	at := time.Date(2026, 10, 5, 13, 0, 0, 0, time.UTC)
	h.host.change(func(host *fakeHost) { host.packages = host.packages[1:] })
	h.round(at)
	records := h.admitted()
	if again := kindsOf(records[len(every):]); !slices.Equal(again, every) || !records[len(records)-1].GetCollectedAt().AsTime().Equal(at) {
		t.Fatalf("a year before snapshots dated a year ahead the collector admitted %v", again)
	}
	if regressed := h.log.lines("inventory_clock_regressed"); len(regressed) != len(every) || regressed[3]["kind"] != "package" {
		t.Errorf("the collector logged %v", regressed)
	}
	h.round(at.Add(time.Hour))
	if records := h.admitted(); len(records) != 2*len(every) {
		t.Errorf("an hour later the collector admitted %v", kindsOf(records[2*len(every):]))
	}
}

func TestAccountsThePlatformWouldHoldAsOneAreAdmittedAndNamed(t *testing.T) {
	h := prepare(t, spool.Limits{MaxBytes: 64 << 20})
	h.host.change(func(host *fakeHost) {
		host.accounts.Accounts = append(host.accounts.Accounts, accounts.Account{Name: "toor", Home: "/root", Shell: "/bin/sh"})
	})
	collector := h.round(time.Date(2026, 10, 5, 13, 0, 0, 0, time.UTC))
	records := h.admitted()
	if users := records[6]; len(users.GetItems()) != 3 {
		t.Errorf("the collector admitted the accounts as %v", users)
	}
	merged := h.log.lines("inventory_items_merged")
	if len(merged) != 1 || merged[0]["level"] != "WARN" || !strings.Contains(fmt.Sprint(merged[0]["merged"]), `user "0": "root", "toor"`) {
		t.Errorf("the collector logged %v", merged)
	}
	if held := collector.Stats().Kinds[6].Merged; !slices.Equal(held, []string{`user "0": "root", "toor"`}) {
		t.Errorf("the collector says %q were merged", held)
	}
}

func TestABaselineThatCannotBeReadIsAdmittedAgainAndOneThatCannotBeTrustedStops(t *testing.T) {
	h := prepare(t, spool.Limits{MaxBytes: 64 << 20})
	at := time.Date(2026, 10, 5, 13, 0, 0, 0, time.UTC)
	h.round(at)
	path := filepath.Join(h.directory, inventory.Name+".json")
	if err := os.WriteFile(path, []byte(`{"format":1,"kinds":`), 0o600); err != nil {
		t.Fatal(err)
	}
	h.round(at.Add(time.Hour))
	if records := h.admitted(); len(records) != 2*len(every) {
		t.Errorf("after its baseline was damaged the collector admitted %v", kindsOf(records[len(every):]))
	}
	if lost := h.log.lines("inventory_baseline_lost"); len(lost) != 1 || lost[0]["level"] != "WARN" {
		t.Errorf("the collector logged %v", lost)
	}
	for name, content := range map[string]struct {
		written string
		mode    os.FileMode
		want    error
	}{
		"newer":       {written: `{"format":2,"kinds":{}}`, mode: 0o600, want: inventory.ErrNewer},
		"open to all": {written: `{"format":1,"kinds":{}}`, mode: 0o644, want: inventory.ErrInsecure},
	} {
		if err := os.WriteFile(path, []byte(content.written), content.mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, content.mode); err != nil {
			t.Fatal(err)
		}
		if err := h.collector(nil).Collect(t.Context()); !errors.Is(err, content.want) {
			t.Errorf("a baseline %s stopped the collector with %v", name, err)
		}
	}
}

func TestABaselineThatCannotBeWrittenStopsTheCollectorAndItsSnapshotsAreAdmittedAgain(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the superuser writes a directory whatever its mode")
	}
	h := prepare(t, spool.Limits{MaxBytes: 64 << 20})
	if err := os.Chmod(h.directory, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(h.directory, 0o700) })
	at := time.Date(2026, 10, 5, 13, 0, 0, 0, time.UTC)
	err := h.collector(func(options *inventory.Options) { options.Now = func() time.Time { return at } }).Collect(t.Context())
	if err == nil || !strings.Contains(err.Error(), inventory.Name+".json") {
		t.Fatalf("a collector that could not write its baseline returned %v", err)
	}
	if records := h.admitted(); len(records) != len(every) {
		t.Fatalf("before it failed the collector admitted %v", kindsOf(records))
	}
	if err := os.Chmod(h.directory, 0o700); err != nil {
		t.Fatal(err)
	}
	h.round(at.Add(time.Hour))
	if records := h.admitted(); len(records) != 2*len(every) || h.baseline()["package"]["record_id"] != records[len(every)+3].GetRecordId() {
		t.Errorf("started again, the collector admitted %v", kindsOf(records[len(every):]))
	}
}

type refusing struct {
	spool   *spool.Spool
	mu      sync.Mutex
	refused int
}

func (r *refusing) Admit(stream spool.Stream, records ...spool.Record) (spool.Receipt, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.refused < 2 {
		r.refused++
		return spool.Receipt{}, spool.ErrFull
	}
	return r.spool.Admit(stream, records...)
}

func (r *refusing) Room(stream spool.Stream) int64 { return r.spool.Room(stream) }

func TestASpoolWithNoRoomKeepsTheSnapshotsUntilItTakesThem(t *testing.T) {
	h := prepare(t, spool.Limits{MaxBytes: 64 << 20})
	full := &refusing{spool: h.spool}
	h.round(time.Date(2026, 10, 5, 13, 0, 0, 0, time.UTC), func(options *inventory.Options) { options.Spool = full })
	if records := h.admitted(); len(records) != len(every) || full.refused != 2 || len(h.baseline()) != len(every) {
		t.Errorf("after two refusals for room the collector admitted %v", kindsOf(records))
	}

	h = prepare(t, spool.Limits{MaxBytes: 16 << 20, MaxRecordBytes: 1 << 20})
	var filled []uint64
	for _, size := range []int{1<<20 - 1<<10, 16 << 10} {
		filler := make([]byte, size)
		for i := 0; ; i++ {
			receipt, err := h.spool.Admit(spool.Inventory, spool.Record{ID: fmt.Sprintf("filler-%d-%d", size, i), Payload: filler})
			if errors.Is(err, spool.ErrFull) {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			filled = append(filled, receipt.First)
		}
	}
	collector := h.collector(nil)
	collecting := run(t, collector)
	deadline := time.Now().Add(5 * time.Second)
	for len(h.log.lines("scan_deferred")) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if deferred := h.log.lines("scan_deferred"); len(deferred) != 1 || deferred[0]["module"] != inventory.Name {
		t.Fatalf("with no room in the spool the collector logged %v", deferred)
	}
	if err := h.spool.Acknowledge(spool.Inventory, filled...); err != nil {
		t.Fatal(err)
	}
	rounds(t, collector, 1, h.log)
	collecting.stop(t)
	if records := h.admitted(); !slices.Equal(kindsOf(records), every) {
		t.Errorf("once the spool had room the collector admitted %v", kindsOf(records))
	}
}

func TestACollectorStopsAsItWaitsForItsNextRound(t *testing.T) {
	h := prepare(t, spool.Limits{MaxBytes: 64 << 20})
	collector := h.collector(nil)
	collecting := run(t, collector)
	rounds(t, collector, 1, h.log)
	began := time.Now()
	collecting.stop(t)
	if took := time.Since(began); took > time.Second {
		t.Errorf("the collector took %s to stop", took)
	}
}

func TestACollectorNeedsWhatItWorksWith(t *testing.T) {
	h := prepare(t, spool.Limits{MaxBytes: 64 << 20})
	directory, err := os.OpenRoot(h.directory)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	logger := slog.New(slog.DiscardHandler)
	for name, options := range map[string]inventory.Options{
		"no installation": {Spool: h.spool, Governor: h.governor, Directory: directory, Logger: logger},
		"no spool":        {Installation: installation, Governor: h.governor, Directory: directory, Logger: logger},
		"no governor":     {Installation: installation, Spool: h.spool, Directory: directory, Logger: logger},
		"no directory":    {Installation: installation, Spool: h.spool, Governor: h.governor, Logger: logger},
		"no logger":       {Installation: installation, Spool: h.spool, Governor: h.governor, Directory: directory},
	} {
		if _, err := inventory.New(options); err == nil {
			t.Errorf("a collector with %s was composed", name)
		}
	}
}
