package spool_test

import (
	"bytes"
	"crypto/sha256"
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
	"sync/atomic"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/platform/files"
	"github.com/dynasmon/Seagull-agent-v2/internal/spool"
)

const (
	segmentHeaderBytes = 20
	frameHeaderBytes   = 32
	budget             = 64 << 20
)

func TestAdmittedRecordsAreReadBackInOrderAfterTheSpoolIsReopened(t *testing.T) {
	directory := spoolDirectory(t)
	held, _ := open(t, directory, budget)
	before := time.Now().UTC().Add(-time.Second)
	var admitted []spool.Record
	for batch := range 4 {
		records := numbered("event", batch*3, 3)
		receipt, err := held.Admit(spool.Events, records...)
		if err != nil {
			t.Fatalf("admit batch %d: %v", batch, err)
		}
		if receipt.Stream != spool.Events || receipt.First != uint64(batch*3+1) || receipt.Last != uint64(batch*3+3) {
			t.Fatalf("batch %d was admitted as %+v", batch, receipt)
		}
		admitted = append(admitted, records...)
	}
	closeSpool(t, held)

	held, logs := open(t, directory, budget)
	entries := drain(t, held, spool.Events)
	if len(entries) != len(admitted) {
		t.Fatalf("read back %d records of the %d admitted", len(entries), len(admitted))
	}
	for i, entry := range entries {
		if entry.Sequence != uint64(i+1) || entry.ID != admitted[i].ID || !bytes.Equal(entry.Payload, admitted[i].Payload) {
			t.Fatalf("record %d read back as %d %q (%d bytes), admitted as %q (%d bytes)",
				i, entry.Sequence, entry.ID, len(entry.Payload), admitted[i].ID, len(admitted[i].Payload))
		}
		if entry.Admitted.Before(before) || entry.Admitted.After(time.Now()) {
			t.Fatalf("record %d says it was admitted at %s", i, entry.Admitted)
		}
	}
	if outstanding := stream(t, held, spool.Events).Outstanding; outstanding != uint64(len(admitted)) {
		t.Fatalf("the spool counts %d outstanding records, it holds %d", outstanding, len(admitted))
	}
	if reported := logs.String(); reported != "" {
		t.Fatalf("a spool that was closed cleanly reported:\n%s", reported)
	}
}

func TestEachStreamKeepsItsOwnOrderAndSettlesApart(t *testing.T) {
	held, _ := open(t, spoolDirectory(t), budget)
	events := admit(t, held, spool.Events, numbered("event", 0, 5)...)
	inventory := admit(t, held, spool.Inventory, numbered("inventory", 0, 2)...)
	if events.First != 1 || inventory.First != 1 || inventory.Last != 2 {
		t.Fatalf("the streams were admitted as %+v and %+v", events, inventory)
	}
	acknowledge(t, held, spool.Events, 1, 2, 3, 4, 5)
	if left := drain(t, held, spool.Events); len(left) != 0 {
		t.Fatalf("delivered events are still outstanding: %d", len(left))
	}
	left := drain(t, held, spool.Inventory)
	if len(left) != 2 || left[0].ID != "inventory-000001" {
		t.Fatalf("acknowledging events settled inventory: %+v", left)
	}
}

func TestAcknowledgedRecordsAreNotReadAgainAndTheirSegmentsAreReclaimed(t *testing.T) {
	directory := spoolDirectory(t)
	held, _ := open(t, directory, 16<<20)
	var last spool.Receipt
	for batch := range 12 {
		last = admit(t, held, spool.Events, sized("event", batch, 256<<10))
	}
	if segments := segmentFiles(t, directory, spool.Events); len(segments) < 3 {
		t.Fatalf("12 records of 256KiB in 1MiB segments filled %d segments", len(segments))
	}
	var sequences []uint64
	for sequence := uint64(1); sequence < last.Last; sequence++ {
		sequences = append(sequences, sequence)
	}
	acknowledge(t, held, spool.Events, sequences...)
	entries := drain(t, held, spool.Events)
	if len(entries) != 1 || entries[0].Sequence != last.Last {
		t.Fatalf("after acknowledging all but the last record, %d are outstanding", len(entries))
	}
	segments := segmentFiles(t, directory, spool.Events)
	if len(segments) != 1 {
		t.Fatalf("the spool kept %d segments for one outstanding record: %q", len(segments), segments)
	}
	acknowledge(t, held, spool.Events, last.Last)
	if segments := segmentFiles(t, directory, spool.Events); len(segments) != 0 {
		t.Fatalf("the spool kept %q once everything was delivered", segments)
	}
	statistics := stream(t, held, spool.Events)
	if statistics.Delivered != 12 || statistics.Outstanding != 0 || statistics.Lost != 0 {
		t.Fatalf("the spool reports %+v", statistics)
	}
	closeSpool(t, held)

	held, _ = open(t, directory, 16<<20)
	if receipt := admit(t, held, spool.Events, numbered("event", 100, 1)...); receipt.First != 13 {
		t.Fatalf("after reclaiming records 1 to 12, the next record was admitted as %d", receipt.First)
	}
	if delivered := stream(t, held, spool.Events).Delivered; delivered != 12 {
		t.Fatalf("the spool forgot what it delivered: %d", delivered)
	}
}

func TestRecordsAcknowledgedOutOfOrderKeepTheOnesBetweenThem(t *testing.T) {
	directory := spoolDirectory(t)
	held, _ := open(t, directory, budget)
	admit(t, held, spool.Events, numbered("event", 0, 10)...)
	acknowledge(t, held, spool.Events, 6, 7, 8, 2, 10)
	acknowledge(t, held, spool.Events, 7)
	want := []uint64{1, 3, 4, 5, 9}
	if got := sequencesOf(drain(t, held, spool.Events)); !slices.Equal(got, want) {
		t.Fatalf("outstanding %v, want %v", got, want)
	}
	closeSpool(t, held)

	held, _ = open(t, directory, budget)
	if got := sequencesOf(drain(t, held, spool.Events)); !slices.Equal(got, want) {
		t.Fatalf("after a restart, outstanding %v, want %v", got, want)
	}
	statistics := stream(t, held, spool.Events)
	if statistics.Delivered != 5 || statistics.Outstanding != 5 {
		t.Fatalf("the spool reports %+v", statistics)
	}
}

func TestRecordsAdmittedWhileOthersAreDeliveredAreAllDeliveredOnce(t *testing.T) {
	held, _ := open(t, spoolDirectory(t), 16<<20)
	streams := []spool.Stream{spool.Events, spool.Inventory}
	admitted := map[spool.Stream]*atomic.Uint64{spool.Events: {}, spool.Inventory: {}}
	var writers sync.WaitGroup
	for writer := range 4 {
		writers.Go(func() {
			for n := range 30 {
				stream := streams[(writer+n)%len(streams)]
				receipt, err := held.Admit(stream, sized(fmt.Sprintf("writer%d", writer), n, 512+n*97))
				if err != nil {
					t.Errorf("writer %d: admit to %s: %v", writer, stream, err)
					return
				}
				admitted[stream].Add(receipt.Last - receipt.First + 1)
			}
		})
	}
	done := make(chan struct{})
	go func() {
		writers.Wait()
		close(done)
	}()
	delivered := map[spool.Stream]map[uint64]bool{spool.Events: {}, spool.Inventory: {}}
	for finished := false; !finished; {
		select {
		case <-done:
			finished = true
		default:
		}
		for _, stream := range streams {
			for {
				entries, err := held.Read(stream, 1, 7, 64<<10)
				if err != nil {
					t.Fatalf("read %s: %v", stream, err)
				}
				if len(entries) == 0 {
					break
				}
				for _, entry := range entries {
					if delivered[stream][entry.Sequence] {
						t.Fatalf("%s record %d was read again after its acknowledgement", stream, entry.Sequence)
					}
					delivered[stream][entry.Sequence] = true
				}
				acknowledge(t, held, stream, sequencesOf(entries)...)
			}
		}
	}
	for _, kept := range held.Stats().Streams {
		if uint64(len(delivered[kept.Stream])) != admitted[kept.Stream].Load() || kept.Delivered != admitted[kept.Stream].Load() || kept.Outstanding != 0 {
			t.Fatalf("%s: admitted %d, read %d, and the spool reports %+v",
				kept.Stream, admitted[kept.Stream].Load(), len(delivered[kept.Stream]), kept)
		}
	}
}

func TestWhoeverWaitsForRecordsIsToldOnceTheStreamAdmitsMore(t *testing.T) {
	held, _ := open(t, spoolDirectory(t), budget)
	events, inventory := held.Admitted(spool.Events), held.Admitted(spool.Inventory)
	if signalled(events) || signalled(inventory) {
		t.Fatal("a spool that admitted nothing says it did")
	}
	if _, err := held.Admit(spool.Events, spool.Record{ID: "empty"}); err == nil {
		t.Fatal("the spool admitted a record that holds nothing")
	}
	if signalled(events) {
		t.Fatal("a refused admission says the stream admitted a record")
	}
	woken := make(chan struct{})
	go func() {
		<-events
		close(woken)
	}()
	admit(t, held, spool.Inventory, numbered("inventory", 0, 1)...)
	if signalled(events) || !signalled(inventory) {
		t.Fatalf("admitting inventory told events %t and inventory %t", signalled(events), signalled(inventory))
	}
	admit(t, held, spool.Events, numbered("event", 0, 2)...)
	<-woken
	after := held.Admitted(spool.Events)
	if signalled(after) {
		t.Fatal("a stream says it admitted what it admitted before it was asked")
	}
	acknowledge(t, held, spool.Events, 1, 2)
	if signalled(after) {
		t.Fatal("an acknowledgement says the stream admitted a record")
	}
	closeSpool(t, held)
	if !signalled(after) || !signalled(held.Admitted(spool.Events)) {
		t.Fatal("a closed spool leaves whoever waits for it waiting")
	}
}

func signalled(signal <-chan struct{}) bool {
	select {
	case <-signal:
		return true
	default:
		return false
	}
}

func TestAReadIsBoundedAndAlwaysReturnsTheFirstRecord(t *testing.T) {
	held, _ := open(t, spoolDirectory(t), budget)
	admit(t, held, spool.Events, sized("event", 0, 4096), sized("event", 1, 4096), sized("event", 2, 4096))
	for _, c := range []struct {
		from        uint64
		most, bytes int
		want        []uint64
	}{
		{from: 0, most: 10, bytes: 1 << 20, want: []uint64{1, 2, 3}},
		{from: 1, most: 2, bytes: 1 << 20, want: []uint64{1, 2}},
		{from: 1, most: 10, bytes: 8192, want: []uint64{1, 2}},
		{from: 1, most: 10, bytes: 1, want: []uint64{1}},
		{from: 3, most: 10, bytes: 1 << 20, want: []uint64{3}},
		{from: 4, most: 10, bytes: 1 << 20, want: nil},
	} {
		entries, err := held.Read(spool.Events, c.from, c.most, c.bytes)
		if err != nil {
			t.Fatalf("read from %d: %v", c.from, err)
		}
		if got := sequencesOf(entries); !slices.Equal(got, c.want) {
			t.Errorf("read from %d, %d records and %d bytes: %v, want %v", c.from, c.most, c.bytes, got, c.want)
		}
	}
}

func TestWhatTheSpoolCannotKeepIsRefused(t *testing.T) {
	held, _ := open(t, spoolDirectory(t), budget)
	admit(t, held, spool.Events, numbered("event", 0, 2)...)
	for name, attempt := range map[string]func() error{
		"nothing": func() error { _, err := held.Admit(spool.Events); return err },
		"an empty identifier": func() error {
			_, err := held.Admit(spool.Events, spool.Record{Payload: []byte("x")})
			return err
		},
		"an identifier longer than the spool keeps": func() error {
			_, err := held.Admit(spool.Events, spool.Record{ID: strings.Repeat("i", spool.MaxIDBytes+1), Payload: []byte("x")})
			return err
		},
		"an empty record": func() error { _, err := held.Admit(spool.Events, spool.Record{ID: "event"}); return err },
		"a record larger than the spool keeps": func() error {
			_, err := held.Admit(spool.Events, spool.Record{ID: "event", Payload: make([]byte, spool.MaxPayloadBytes+1)})
			return err
		},
		"a stream it does not keep": func() error {
			_, err := held.Admit(spool.Stream(9), numbered("event", 0, 1)...)
			return err
		},
		"an acknowledgement of a record never admitted": func() error { return held.Acknowledge(spool.Events, 2, 3) },
		"an acknowledgement of record 0":                func() error { return held.Acknowledge(spool.Events, 0) },
		"a read of no records":                          func() error { _, err := held.Read(spool.Events, 1, 0, 1); return err },
	} {
		if err := attempt(); !errors.Is(err, spool.ErrRefused) {
			t.Errorf("%s: %v, want %v", name, err, spool.ErrRefused)
		}
	}
	if got := sequencesOf(drain(t, held, spool.Events)); !slices.Equal(got, []uint64{1, 2}) {
		t.Fatalf("a refused request changed what the spool holds: %v", got)
	}
}

func TestTheBudgetBoundsWhatTheSpoolAdmits(t *testing.T) {
	directory := spoolDirectory(t)
	held, _ := open(t, directory, 4<<20)
	admitted := fill(t, held, spool.Events, "event")
	inventory := fill(t, held, spool.Inventory, "inventory")
	if admitted < 10 || admitted > 14 || inventory < 1 {
		t.Fatalf("a 4MiB spool admitted %d events and %d inventory records of 256KiB", admitted, inventory)
	}
	if used := held.Stats().Bytes; used > 4<<20 {
		t.Fatalf("the spool holds %d bytes of a 4MiB budget", used)
	}

	var sequences []uint64
	for sequence := range uint64(admitted) {
		sequences = append(sequences, sequence+1)
	}
	acknowledge(t, held, spool.Events, sequences...)
	if _, err := held.Admit(spool.Events, sized("event", admitted, 256<<10)); err != nil {
		t.Fatalf("the spool refused a record once what it held was delivered: %v", err)
	}

	held.Limit(spool.Limits{MaxBytes: 256 << 10})
	if _, err := held.Admit(spool.Events, sized("event", admitted+1, 1024)); !errors.Is(err, spool.ErrFull) {
		t.Fatalf("a spool whose budget was lowered below what it holds admitted more: %v", err)
	}
	if limit := held.Stats().MaxBytes; limit != 256<<10 {
		t.Fatalf("the spool keeps to %d bytes", limit)
	}
}

func TestEachStreamKeepsRoomTheOtherCannotTake(t *testing.T) {
	for name, c := range map[string]struct {
		first, second           spool.Stream
		firstShare, secondShare int64
	}{
		"events filling the spool first":    {first: spool.Events, second: spool.Inventory, firstShare: 7 << 20, secondShare: 1 << 20},
		"inventory filling the spool first": {first: spool.Inventory, second: spool.Events, firstShare: 4 << 20, secondShare: 4 << 20},
	} {
		t.Run(name, func(t *testing.T) {
			held, _ := open(t, spoolDirectory(t), 8<<20)
			fill(t, held, c.first, "first")
			fill(t, held, c.second, "second")
			first, second := stream(t, held, c.first).Bytes, stream(t, held, c.second).Bytes
			record := int64(frameHeaderBytes + len("first-000001") + 256<<10)
			if first > c.firstShare || first < c.firstShare-record {
				t.Fatalf("%s filled %d bytes of its share of %d", c.first, first, c.firstShare)
			}
			if second < c.secondShare-record-(64<<10) {
				t.Fatalf("%s found %d bytes once %s held %d, and it keeps %d the other cannot take", c.second, second, c.first, first, c.secondShare)
			}
			if total := held.Stats().Bytes; total > 8<<20 {
				t.Fatalf("the spool holds %d bytes of an 8MiB budget", total)
			}
		})
	}
}

func TestAnInterruptedWriteIsDiscardedWithoutCountingALoss(t *testing.T) {
	for name, interrupt := range map[string]func(t *testing.T, path string, last []byte){
		"a header cut short": func(t *testing.T, path string, last []byte) {
			appendBytes(t, path, last[:frameHeaderBytes/2])
		},
		"a record cut short": func(t *testing.T, path string, last []byte) {
			appendBytes(t, path, last[:len(last)-100])
		},
		"sectors the disk never wrote": func(t *testing.T, path string, last []byte) {
			written := slices.Clone(last)
			start := sectorAfter(t, path)
			clear(written[start : start+512])
			appendBytes(t, path, written)
		},
		"a segment created without its header": func(t *testing.T, path string, last []byte) {
			next := filepath.Join(filepath.Dir(path), fmt.Sprintf("%020d.seg", 2))
			if err := os.WriteFile(next, []byte("SG"), 0o600); err != nil {
				t.Fatalf("create %s: %v", next, err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			directory := spoolDirectory(t)
			held, _ := open(t, directory, budget)
			admit(t, held, spool.Events, sized("event", 0, 700), sized("event", 1, 2000))
			closeSpool(t, held)
			path, last := cutLastRecord(t, directory, spool.Events, 2000+len("event-000002"))
			interrupt(t, path, last)

			held, logs := open(t, directory, budget)
			if _, found := logged(t, logs, "spool_write_interrupted"); !found {
				t.Fatalf("the spool did not report the interrupted write:\n%s", logs)
			}
			if lost, found := logged(t, logs, "spool_records_lost"); found {
				t.Fatalf("an interrupted write was counted as a loss: %v", lost)
			}
			if got := sequencesOf(drain(t, held, spool.Events)); !slices.Equal(got, []uint64{1}) {
				t.Fatalf("read back %v after the interrupted write", got)
			}
			if receipt := admit(t, held, spool.Events, numbered("again", 0, 1)...); receipt.First != 2 {
				t.Fatalf("the record admitted after the interrupted write became %d", receipt.First)
			}
			closeSpool(t, held)
			held, logs = open(t, directory, budget)
			if logs.Len() != 0 {
				t.Fatalf("the spool reported the interrupted write again:\n%s", logs)
			}
			if entries := drain(t, held, spool.Events); len(entries) != 2 || entries[1].ID != "again-000001" {
				t.Fatalf("read back %+v", entries)
			}
		})
	}
}

func TestDamagedRecordsAreCountedAsLostOnceAndTheOthersAreDelivered(t *testing.T) {
	directory := spoolDirectory(t)
	held, _ := open(t, directory, 16<<20)
	for batch := range 8 {
		admit(t, held, spool.Events, sized("event", batch, 256<<10))
	}
	closeSpool(t, held)
	segments := segmentFiles(t, directory, spool.Events)
	if len(segments) < 2 {
		t.Fatalf("the records filled %d segments", len(segments))
	}
	record := int64(frameHeaderBytes + len("event-000001") + 256<<10)
	damage(t, segments[0], segmentHeaderBytes+record+frameHeaderBytes+4096)
	damage(t, segments[0], segmentHeaderBytes+2*record+10)

	held, logs := open(t, directory, 16<<20)
	if logs.Len() != 0 {
		t.Fatalf("a spool whose damage is inside a sealed segment reported as it opened:\n%s", logs)
	}
	entries := drain(t, held, spool.Events)
	if got := sequencesOf(entries); !slices.Equal(got, []uint64{1, 4, 5, 6, 7, 8}) {
		t.Fatalf("read back %v around the damaged records", got)
	}
	for _, entry := range entries {
		if want := sized("event", int(entry.Sequence)-1, 256<<10); entry.ID != want.ID || !bytes.Equal(entry.Payload, want.Payload) {
			t.Fatalf("record %d read back altered", entry.Sequence)
		}
	}
	lost, found := logged(t, logs, "spool_records_lost")
	if !found || lost["first"] != float64(2) || lost["records"] != float64(2) || lost["level"] != "ERROR" {
		t.Fatalf("the spool reported %v:\n%s", lost, logs)
	}
	if reported := strings.Count(logs.String(), "spool_records_lost"); reported != 1 {
		t.Fatalf("the records lost in one segment were reported on %d lines:\n%s", reported, logs)
	}
	if statistics := stream(t, held, spool.Events); statistics.Lost != 2 || statistics.Outstanding != 6 {
		t.Fatalf("the spool reports %+v", statistics)
	}
	closeSpool(t, held)

	held, logs = open(t, directory, 16<<20)
	if got := sequencesOf(drain(t, held, spool.Events)); !slices.Equal(got, []uint64{1, 4, 5, 6, 7, 8}) {
		t.Fatalf("after a restart, read back %v", got)
	}
	if logs.Len() != 0 {
		t.Fatalf("the loss was reported again:\n%s", logs)
	}
	if lost := stream(t, held, spool.Events).Lost; lost != 2 {
		t.Fatalf("after a restart the spool counts %d lost records", lost)
	}
	acknowledge(t, held, spool.Events, 1, 4, 5, 6, 7, 8)
	if left := segmentFiles(t, directory, spool.Events); len(left) != 0 {
		t.Fatalf("the damaged segment outlived every record it held: %q", left)
	}
}

func TestDamageAtTheEndOfTheLastSegmentIsALossRatherThanAnInterruptedWrite(t *testing.T) {
	for name, at := range map[string]int{
		"what the record holds": frameHeaderBytes + 300,
		"its header":            10,
	} {
		t.Run(name, func(t *testing.T) {
			directory := spoolDirectory(t)
			held, _ := open(t, directory, budget)
			admit(t, held, spool.Events, sized("event", 0, 700), sized("event", 1, 2000))
			closeSpool(t, held)
			path, last := cutLastRecord(t, directory, spool.Events, 2000+len("event-000002"))
			last[at] ^= 0x40
			appendBytes(t, path, last)

			held, logs := open(t, directory, budget)
			if interrupted, found := logged(t, logs, "spool_write_interrupted"); found {
				t.Fatalf("damage to a record written whole was taken for an interrupted write: %v", interrupted)
			}
			lost, found := logged(t, logs, "spool_records_lost")
			if !found || lost["first"] != float64(2) || lost["records"] != float64(1) {
				t.Fatalf("the spool reported %v:\n%s", lost, logs)
			}
			if got := sequencesOf(drain(t, held, spool.Events)); !slices.Equal(got, []uint64{1}) {
				t.Fatalf("read back %v", got)
			}
			if receipt := admit(t, held, spool.Events, numbered("again", 0, 1)...); receipt.First != 3 {
				t.Fatalf("the record admitted after the lost one became %d, and 2 was lost", receipt.First)
			}
		})
	}
}

func TestASegmentThatDisappearedIsCountedAsLost(t *testing.T) {
	directory := spoolDirectory(t)
	held, _ := open(t, directory, 16<<20)
	for batch := range 12 {
		admit(t, held, spool.Events, sized("event", batch, 256<<10))
	}
	closeSpool(t, held)
	segments := segmentFiles(t, directory, spool.Events)
	if len(segments) < 3 {
		t.Fatalf("the records filled %d segments", len(segments))
	}
	if err := os.Remove(segments[1]); err != nil {
		t.Fatalf("remove %s: %v", segments[1], err)
	}

	held, logs := open(t, directory, 16<<20)
	entries := drain(t, held, spool.Events)
	lost, found := logged(t, logs, "spool_records_lost")
	if !found {
		t.Fatalf("the records of a segment that disappeared were not reported:\n%s", logs)
	}
	statistics := stream(t, held, spool.Events)
	if statistics.Lost == 0 || uint64(len(entries))+statistics.Lost != 12 || statistics.Lost != uint64(lost["records"].(float64)) {
		t.Fatalf("read back %d records, the spool reports %+v and logged %v", len(entries), statistics, lost)
	}
}

func TestALedgerThatCannotBeReadBackDeliversEverythingAgain(t *testing.T) {
	for name, damageLedger := range map[string]func(t *testing.T, path string){
		"a ledger that is gone": func(t *testing.T, path string) {
			if err := os.Remove(path); err != nil {
				t.Fatalf("remove %s: %v", path, err)
			}
		},
		"a ledger whose checksum fails": func(t *testing.T, path string) { damage(t, path, 10) },
		"a ledger cut short":            func(t *testing.T, path string) { truncate(t, path, 20) },
	} {
		t.Run(name, func(t *testing.T) {
			directory := spoolDirectory(t)
			held, _ := open(t, directory, budget)
			admit(t, held, spool.Events, numbered("event", 0, 6)...)
			acknowledge(t, held, spool.Events, 1, 2, 4)
			closeSpool(t, held)
			damageLedger(t, filepath.Join(directory, "events", "ledger"))

			held, logs := open(t, directory, budget)
			if reported, found := logged(t, logs, "spool_acknowledgements_lost"); !found || reported["level"] != "WARN" {
				t.Fatalf("the spool reported %v:\n%s", reported, logs)
			}
			if got := sequencesOf(drain(t, held, spool.Events)); !slices.Equal(got, []uint64{1, 2, 3, 4, 5, 6}) {
				t.Fatalf("records whose acknowledgements are gone read back as %v", got)
			}
			if receipt := admit(t, held, spool.Events, numbered("again", 0, 1)...); receipt.First != 7 {
				t.Fatalf("the next record was admitted as %d", receipt.First)
			}
		})
	}
}

func TestAnInterruptedCompactionIsFinishedWhenTheSpoolOpens(t *testing.T) {
	directory := spoolDirectory(t)
	held, _ := open(t, directory, 16<<20)
	for batch := range 12 {
		admit(t, held, spool.Events, sized("event", batch, 256<<10))
	}
	closeSpool(t, held)
	kept := map[string][]byte{}
	for _, path := range segmentFiles(t, directory, spool.Events) {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		kept[path] = content
	}

	held, _ = open(t, directory, 16<<20)
	acknowledge(t, held, spool.Events, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10)
	closeSpool(t, held)
	for path, content := range kept {
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatalf("restore %s: %v", path, err)
		}
	}
	interrupted := filepath.Join(directory, "events", ".ledger.0123456789abcdef.tmp")
	if err := os.WriteFile(interrupted, []byte("SGLG"), 0o600); err != nil {
		t.Fatalf("interrupt a ledger write: %v", err)
	}

	held, logs := open(t, directory, 16<<20)
	if got := sequencesOf(drain(t, held, spool.Events)); !slices.Equal(got, []uint64{11, 12}) {
		t.Fatalf("after an interrupted compaction, outstanding %v", got)
	}
	if left := segmentFiles(t, directory, spool.Events); len(left) >= len(kept) {
		t.Fatalf("the spool kept %d of the %d segments whose records were delivered", len(left), len(kept))
	}
	if _, err := os.Lstat(interrupted); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the interrupted ledger write is still there: %v", err)
	}
	if logs.Len() != 0 {
		t.Fatalf("finishing a compaction reported:\n%s", logs)
	}
}

func TestOnlyOneProcessHoldsTheSpool(t *testing.T) {
	directory := spoolDirectory(t)
	held, _ := open(t, directory, budget)
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatalf("open %s: %v", directory, err)
	}
	defer root.Close()
	if second, err := spool.Open(root, spool.Limits{MaxBytes: budget}, slog.New(slog.DiscardHandler)); !errors.Is(err, spool.ErrLocked) {
		if second != nil {
			second.Close()
		}
		t.Fatalf("a second spool opened the same directory: %v", err)
	}
	closeSpool(t, held)
	if _, err := held.Admit(spool.Events, numbered("event", 0, 1)...); !errors.Is(err, spool.ErrClosed) {
		t.Fatalf("a closed spool admitted a record: %v", err)
	}
	second, err := spool.Open(root, spool.Limits{MaxBytes: budget}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("the spool was still held after it closed: %v", err)
	}
	second.Close()
}

func TestEverythingTheSpoolKeepsIsPrivate(t *testing.T) {
	directory := spoolDirectory(t)
	held, _ := open(t, directory, 16<<20)
	for batch := range 6 {
		admit(t, held, spool.Events, sized("event", batch, 256<<10))
		admit(t, held, spool.Inventory, sized("inventory", batch, 1024))
	}
	acknowledge(t, held, spool.Events, 1, 2)
	closeSpool(t, held)

	walked := 0
	err := filepath.WalkDir(directory, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		walked++
		described, err := entry.Info()
		if err != nil {
			return err
		}
		if err := files.Private(described); err != nil {
			if errors.Is(err, errors.ErrUnsupported) {
				t.Skipf("this platform cannot tell who may reach %s", path)
			}
			t.Errorf("%s %v", path, err)
		}
		switch permissions := described.Mode().Perm(); {
		case entry.IsDir() && permissions != 0o700:
			t.Errorf("%s is a directory granting %s", path, permissions)
		case !entry.IsDir() && permissions != 0o600:
			t.Errorf("%s grants %s", path, permissions)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", directory, err)
	}
	if walked < 7 {
		t.Fatalf("the spool holds %d files and directories", walked)
	}
}

func TestASpoolTheAgentCannotTrustIsRefused(t *testing.T) {
	for name, c := range map[string]struct {
		prepare func(t *testing.T, directory string)
		want    error
	}{
		"a segment another account can read": {
			prepare: func(t *testing.T, directory string) { chmod(t, segmentFiles(t, directory, spool.Events)[0], 0o640) },
			want:    spool.ErrInsecure,
		},
		"a ledger another account can read": {
			prepare: func(t *testing.T, directory string) { chmod(t, filepath.Join(directory, "inventory", "ledger"), 0o604) },
			want:    spool.ErrInsecure,
		},
		"a stream another account can list": {
			prepare: func(t *testing.T, directory string) { chmod(t, filepath.Join(directory, "events"), 0o750) },
			want:    spool.ErrInsecure,
		},
		"a segment written by a newer agent": {
			prepare: func(t *testing.T, directory string) {
				rewrite(t, segmentFiles(t, directory, spool.Events)[0], 4, []byte{2, 0})
			},
			want: spool.ErrNewer,
		},
		"a ledger written by a newer agent": {
			prepare: func(t *testing.T, directory string) {
				rewrite(t, filepath.Join(directory, "events", "ledger"), 4, []byte{3, 0})
			},
			want: spool.ErrNewer,
		},
		"a file the spool did not write": {
			prepare: func(t *testing.T, directory string) {
				write(t, filepath.Join(directory, "events", "notes.txt"), "kept")
			},
			want: spool.ErrDamaged,
		},
		"a stream this agent does not keep": {
			prepare: func(t *testing.T, directory string) {
				if err := os.Mkdir(filepath.Join(directory, "processes"), 0o700); err != nil {
					t.Fatalf("create a stream: %v", err)
				}
			},
			want: spool.ErrDamaged,
		},
		"a segment that is a link": {
			prepare: func(t *testing.T, directory string) {
				link := filepath.Join(directory, "events", fmt.Sprintf("%020d.seg", 99))
				if err := os.Symlink(filepath.Base(segmentFiles(t, directory, spool.Events)[0]), link); err != nil {
					t.Fatalf("link %s: %v", link, err)
				}
			},
			want: spool.ErrDamaged,
		},
		"a segment moved from another stream": {
			prepare: func(t *testing.T, directory string) {
				moved := filepath.Join(directory, "events", fmt.Sprintf("%020d.seg", 50))
				if err := os.Rename(segmentFiles(t, directory, spool.Inventory)[0], moved); err != nil {
					t.Fatalf("move a segment: %v", err)
				}
			},
			want: spool.ErrDamaged,
		},
	} {
		t.Run(name, func(t *testing.T) {
			directory := spoolDirectory(t)
			held, _ := open(t, directory, budget)
			admit(t, held, spool.Events, numbered("event", 0, 2)...)
			admit(t, held, spool.Inventory, numbered("inventory", 0, 2)...)
			closeSpool(t, held)
			c.prepare(t, directory)

			root, err := os.OpenRoot(directory)
			if err != nil {
				t.Fatalf("open %s: %v", directory, err)
			}
			defer root.Close()
			refused, err := spool.Open(root, spool.Limits{MaxBytes: budget}, slog.New(slog.DiscardHandler))
			if !errors.Is(err, c.want) {
				if refused != nil {
					refused.Close()
				}
				t.Fatalf("opened with %v, want %v", err, c.want)
			}
		})
	}
}

func TestReadingBackASpoolTakesNoMoreMemoryThanOneRecord(t *testing.T) {
	directory := spoolDirectory(t)
	held, _ := open(t, directory, budget)
	for batch := range 6 {
		records := make([]spool.Record, 0, 64)
		for n := range 64 {
			records = append(records, sized("event", batch*64+n, 64<<10))
		}
		admit(t, held, spool.Events, records...)
	}
	if segments := segmentFiles(t, directory, spool.Events); len(segments) < 5 {
		t.Fatalf("24MiB of records filled %d segments of 4MiB", len(segments))
	}
	closeSpool(t, held)

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	held, _ = open(t, directory, budget)
	entries, err := held.Read(spool.Events, 300, 1, 1)
	runtime.ReadMemStats(&after)
	if err != nil || len(entries) != 1 || entries[0].Sequence != 300 {
		t.Fatalf("read back %d records: %v", len(entries), err)
	}
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 2<<20 {
		t.Fatalf("opening a spool of 24MiB and reading one record of 64KiB back allocated %d bytes", allocated)
	}
}

// Records of 256KiB go into a stream until the spool refuses one for room, and
// the refusal is the only one it gives.
func fill(t *testing.T, held *spool.Spool, kept spool.Stream, prefix string) int {
	t.Helper()
	for admitted := 0; ; admitted++ {
		if _, err := held.Admit(kept, sized(prefix, admitted, 256<<10)); err != nil {
			if !errors.Is(err, spool.ErrFull) {
				t.Fatalf("%s refused record %d with %v", kept, admitted, err)
			}
			return admitted
		}
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

func open(t *testing.T, directory string, bytes int64) (*spool.Spool, *strings.Builder) {
	t.Helper()
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatalf("open %s: %v", directory, err)
	}
	t.Cleanup(func() { root.Close() })
	logs := &strings.Builder{}
	held, err := spool.Open(root, spool.Limits{MaxBytes: bytes}, slog.New(slog.NewJSONHandler(logs, nil)))
	if err != nil {
		t.Fatalf("open the spool in %s: %v\n%s", directory, err, logs)
	}
	t.Cleanup(func() { held.Close() })
	return held, logs
}

func closeSpool(t *testing.T, held *spool.Spool) {
	t.Helper()
	if err := held.Close(); err != nil {
		t.Fatalf("close the spool: %v", err)
	}
}

func admit(t *testing.T, held *spool.Spool, stream spool.Stream, records ...spool.Record) spool.Receipt {
	t.Helper()
	receipt, err := held.Admit(stream, records...)
	if err != nil {
		t.Fatalf("admit %d records to %s: %v", len(records), stream, err)
	}
	return receipt
}

func acknowledge(t *testing.T, held *spool.Spool, stream spool.Stream, sequences ...uint64) {
	t.Helper()
	if err := held.Acknowledge(stream, sequences...); err != nil {
		t.Fatalf("acknowledge %v of %s: %v", sequences, stream, err)
	}
}

func drain(t *testing.T, held *spool.Spool, stream spool.Stream) []spool.Entry {
	t.Helper()
	var entries []spool.Entry
	for from := uint64(1); ; {
		read, err := held.Read(stream, from, 3, 1<<20)
		if err != nil {
			t.Fatalf("read %s from %d: %v", stream, from, err)
		}
		if len(read) == 0 {
			return entries
		}
		entries = append(entries, read...)
		from = read[len(read)-1].Sequence + 1
	}
}

func stream(t *testing.T, held *spool.Spool, kept spool.Stream) spool.StreamStats {
	t.Helper()
	for _, statistics := range held.Stats().Streams {
		if statistics.Stream == kept {
			return statistics
		}
	}
	t.Fatalf("the spool reports nothing about %s", kept)
	return spool.StreamStats{}
}

func numbered(prefix string, from, count int) []spool.Record {
	records := make([]spool.Record, 0, count)
	for n := from; n < from+count; n++ {
		records = append(records, sized(prefix, n, 64+n%200))
	}
	return records
}

// A record's payload follows from its identifier, so whatever reads it back can
// tell whether it came back as it was admitted.
func sized(prefix string, n, length int) spool.Record {
	id := fmt.Sprintf("%s-%06d", prefix, n+1)
	return spool.Record{ID: id, Payload: payload(id, length)}
}

func payload(id string, length int) []byte {
	digest := sha256.Sum256([]byte(id))
	return bytes.Repeat(digest[:], length/len(digest)+1)[:length]
}

func sequencesOf(entries []spool.Entry) []uint64 {
	var sequences []uint64
	for _, entry := range entries {
		sequences = append(sequences, entry.Sequence)
	}
	return sequences
}

func segmentFiles(t *testing.T, directory string, stream spool.Stream) []string {
	t.Helper()
	found, err := filepath.Glob(filepath.Join(directory, stream.String(), "*.seg"))
	if err != nil {
		t.Fatalf("list the segments of %s: %v", stream, err)
	}
	slices.Sort(found)
	return found
}

func cutLastRecord(t *testing.T, directory string, stream spool.Stream, body int) (string, []byte) {
	t.Helper()
	segments := segmentFiles(t, directory, stream)
	path := segments[len(segments)-1]
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	cut := len(content) - frameHeaderBytes - body
	truncate(t, path, int64(cut))
	return path, content[cut:]
}

func sectorAfter(t *testing.T, path string) int {
	t.Helper()
	described, err := os.Stat(path)
	if err != nil {
		t.Fatalf("inspect %s: %v", path, err)
	}
	return int(512 - described.Size()%512)
}

func appendBytes(t *testing.T, path string, content []byte) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer file.Close()
	if _, err := file.Write(content); err != nil {
		t.Fatalf("append to %s: %v", path, err)
	}
}

func damage(t *testing.T, path string, at int64) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer file.Close()
	held := make([]byte, 1)
	if _, err := file.ReadAt(held, at); err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if _, err := file.WriteAt([]byte{held[0] ^ 0x5a}, at); err != nil {
		t.Fatalf("damage %s: %v", path, err)
	}
}

func rewrite(t *testing.T, path string, at int64, content []byte) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer file.Close()
	if _, err := file.WriteAt(content, at); err != nil {
		t.Fatalf("rewrite %s: %v", path, err)
	}
}

func truncate(t *testing.T, path string, size int64) {
	t.Helper()
	if err := os.Truncate(path, size); err != nil {
		t.Fatalf("truncate %s: %v", path, err)
	}
}

func chmod(t *testing.T, path string, mode fs.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod %s: %v", path, err)
	}
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func logged(t *testing.T, logs *strings.Builder, message string) (map[string]any, bool) {
	t.Helper()
	for line := range strings.Lines(logs.String()) {
		entry := map[string]any{}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("decode the log line %q: %v", line, err)
		}
		if entry["msg"] == message {
			return entry, true
		}
	}
	return nil, false
}
