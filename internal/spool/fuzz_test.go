package spool

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// Whatever the last segment holds, opening the spool reads back only records
// that verify, in order, and leaves the segment so that opening it again finds
// nothing more to discard or count and reads back the same records.
func FuzzRecover(f *testing.F) {
	whole := segmentOf(Events, 1, "event-1", "first", "event-2", strings.Repeat("second", 200), "event-3", "third")
	f.Add(whole)
	f.Add(whole[:len(whole)-7])
	f.Add(whole[:segmentHeaderBytes+frameHeaderBytes/2])
	f.Add(append(slices.Clone(whole), make([]byte, 1024)...))
	f.Add(flipped(whole, segmentHeaderBytes+frameHeaderBytes+10))
	f.Add(flipped(whole, 5))
	f.Add(flipped(whole, len(whole)-2))
	f.Add(whole[:segmentHeaderBytes])
	f.Add([]byte{})
	f.Add(segmentOf(Inventory, 1, "inventory-1", "moved"))
	f.Fuzz(func(t *testing.T, content []byte) {
		directory := spoolDirectory(t)
		if err := os.Mkdir(filepath.Join(directory, "events"), 0o700); err != nil {
			t.Fatalf("create the stream: %v", err)
		}
		if err := os.WriteFile(filepath.Join(directory, "events", fmt.Sprintf("%020d.seg", 1)), content, 0o600); err != nil {
			t.Fatalf("write the segment: %v", err)
		}
		root, err := os.OpenRoot(directory)
		if err != nil {
			t.Fatalf("open %s: %v", directory, err)
		}
		defer root.Close()
		held, err := open(root, Limits{MaxBytes: 64 << 20}, slog.New(slog.DiscardHandler), volatile{})
		if errors.Is(err, ErrNewer) || errors.Is(err, ErrDamaged) {
			return
		}
		if err != nil {
			t.Fatalf("open the spool: %v", err)
		}
		first := readBack(t, held)
		if err := held.Close(); err != nil {
			t.Fatalf("close the spool: %v", err)
		}

		var logs strings.Builder
		held, err = open(root, Limits{MaxBytes: 64 << 20}, slog.New(slog.NewJSONHandler(&logs, nil)), volatile{})
		if err != nil {
			t.Fatalf("reopen the spool: %v", err)
		}
		defer held.Close()
		if logs.Len() != 0 {
			t.Fatalf("reopening a recovered spool reported:\n%s", logs.String())
		}
		if second := readBack(t, held); !slices.EqualFunc(first, second, func(a, b Entry) bool {
			return a.Sequence == b.Sequence && a.ID == b.ID && bytes.Equal(a.Payload, b.Payload)
		}) {
			t.Fatalf("the spool read back %d records, and %d once reopened", len(first), len(second))
		}
		if receipt, err := held.Admit(Events, Record{ID: "after", Payload: []byte("recovery")}); err != nil {
			t.Fatalf("a recovered spool refused a record: %v", err)
		} else if len(first) > 0 && receipt.First <= first[len(first)-1].Sequence {
			t.Fatalf("record %d was admitted after record %d", receipt.First, first[len(first)-1].Sequence)
		}
	})
}

// Whatever a ledger holds, it is read back only when writing what was read
// gives the same bytes, so no two files read as the same ledger.
func FuzzLedger(f *testing.F) {
	f.Add(ledger{watermark: 1}.encode(Events))
	f.Add(ledger{watermark: 5, spans: []span{{first: 7, end: 9}, {first: 12, end: 13}}, delivered: 6, lost: 1}.encode(Events))
	f.Add(ledger{watermark: 3}.encode(Inventory))
	f.Fuzz(func(t *testing.T, content []byte) {
		read, err := decodeLedger(Events, content)
		if err != nil {
			return
		}
		if written := read.encode(Events); !bytes.Equal(written, content) {
			t.Fatalf("%x reads as a ledger that is written as %x", content, written)
		}
		if again, newly := read.settle(nil); newly != 0 || !bytes.Equal(again.encode(Events), content) {
			t.Fatalf("settling nothing changed the ledger")
		}
	})
}

func TestTheLedgerSettlesWhatWasSettledAndNothingElse(t *testing.T) {
	random := rand.New(rand.NewPCG(1, 2))
	for round := range 200 {
		held, reference := ledger{watermark: 1}, map[uint64]bool{}
		var counted uint64
		for range 1 + random.IntN(20) {
			var sequences []uint64
			for range 1 + random.IntN(8) {
				sequences = append(sequences, 1+random.Uint64N(64))
			}
			var newly uint64
			held, newly = held.settle(consecutive(sequences))
			for _, sequence := range sequences {
				if !reference[sequence] {
					reference[sequence], counted = true, counted+1
				}
			}
			if held.covered()-1 != counted || newly > counted {
				t.Fatalf("round %d: the ledger covers %d records, %d were settled", round, held.covered()-1, counted)
			}
		}
		for sequence := uint64(1); sequence <= 70; sequence++ {
			if held.settled(sequence) != reference[sequence] {
				t.Fatalf("round %d: record %d settled: %t, want %t", round, sequence, held.settled(sequence), reference[sequence])
			}
		}
		read, err := decodeLedger(Events, held.encode(Events))
		if err != nil || !bytes.Equal(read.encode(Events), held.encode(Events)) {
			t.Fatalf("round %d: the ledger does not read back as written: %v", round, err)
		}
		if got := held.count(10, 40); got != countIn(reference, 10, 40) {
			t.Fatalf("round %d: the ledger counts %d settled records between 10 and 40, want %d", round, got, countIn(reference, 10, 40))
		}
	}
}

// What recovery reads back does not depend on whether a sync reached the disk,
// so the fuzzer spends its time reading segments rather than waiting on one.
type volatile struct{}

func (volatile) write(file *os.File, content []byte) (int, error) { return file.Write(content) }

func (volatile) sync(*os.File) error { return nil }

func readBack(t *testing.T, held *Spool) []Entry {
	t.Helper()
	var entries []Entry
	for from := uint64(1); ; {
		read, err := held.Read(Events, from, 2, 1<<20)
		if err != nil {
			t.Fatalf("read the spool: %v", err)
		}
		if len(read) == 0 {
			return entries
		}
		for _, entry := range read {
			if len(entries) > 0 && entry.Sequence <= entries[len(entries)-1].Sequence {
				t.Fatalf("record %d was read back after record %d", entry.Sequence, entries[len(entries)-1].Sequence)
			}
			entries = append(entries, entry)
		}
		from = read[len(read)-1].Sequence + 1
	}
}

func segmentOf(stream Stream, first uint64, records ...string) []byte {
	content := encodeSegmentHeader(stream, first)
	for i := 0; i+1 < len(records); i += 2 {
		id, payload := records[i], []byte(records[i+1])
		content = append(content, encodeFrameHeader(stream, first+uint64(i/2), 1_700_000_000_000_000_000, id, payload)...)
		content = append(append(content, id...), payload...)
	}
	return content
}

func flipped(content []byte, at int) []byte {
	damaged := slices.Clone(content)
	damaged[at] ^= 0x10
	return damaged
}

func countIn(settled map[uint64]bool, first, end uint64) uint64 {
	var count uint64
	for sequence := first; sequence < end; sequence++ {
		if settled[sequence] {
			count++
		}
	}
	return count
}
