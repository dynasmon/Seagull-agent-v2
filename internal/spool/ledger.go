package spool

import (
	"bytes"
	"cmp"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
)

const (
	ledgerHeaderBytes = 36
	spanBytes         = 16
	maxLedgerBytes    = 16 << 20
)

var (
	ledgerMagic   = []byte("SGLG")
	errUnreadable = errors.New("it cannot be read back")
)

type span struct {
	first uint64
	end   uint64
}

// A ledger is what a stream has settled: every sequence below watermark, and
// the spans above it that settled out of order. A record settles once, as
// delivered when the platform acknowledged it or as lost when it could not be
// read back, and the counts of each outlive the records they counted.
type ledger struct {
	watermark uint64
	spans     []span
	delivered uint64
	lost      uint64
}

func (l ledger) clone() ledger {
	l.spans = slices.Clone(l.spans)
	return l
}

func (l ledger) settled(sequence uint64) bool {
	if sequence < l.watermark {
		return true
	}
	found, _ := slices.BinarySearchFunc(l.spans, sequence, func(held span, sequence uint64) int {
		if held.end <= sequence {
			return -1
		}
		return 0
	})
	return found < len(l.spans) && l.spans[found].first <= sequence
}

func (l ledger) count(first, end uint64) uint64 {
	if end <= first {
		return 0
	}
	var settled uint64
	if l.watermark > first {
		settled += min(l.watermark, end) - first
	}
	for _, held := range l.spans {
		if low, high := max(held.first, first), min(held.end, end); low < high {
			settled += high - low
		}
	}
	return settled
}

func (l ledger) highest() uint64 {
	if len(l.spans) > 0 {
		return l.spans[len(l.spans)-1].end
	}
	return l.watermark
}

func (l ledger) covered() uint64 {
	covered := l.watermark
	for _, held := range l.spans {
		covered += held.end - held.first
	}
	return covered
}

func (l ledger) settle(added []span) (ledger, uint64) {
	merged := make([]span, 0, len(l.spans)+len(added)+1)
	merged = append(append(merged, span{end: l.watermark}), l.spans...)
	for _, held := range added {
		if held.first < held.end {
			merged = append(merged, held)
		}
	}
	slices.SortFunc(merged, func(a, b span) int { return cmp.Compare(a.first, b.first) })
	joined := merged[:1]
	for _, held := range merged[1:] {
		if last := &joined[len(joined)-1]; held.first <= last.end {
			last.end = max(last.end, held.end)
			continue
		}
		joined = append(joined, held)
	}
	updated := ledger{watermark: joined[0].end, spans: slices.Clone(joined[1:]), delivered: l.delivered, lost: l.lost}
	return updated, updated.covered() - l.covered()
}

func consecutive(sequences []uint64) []span {
	sorted := slices.Clone(sequences)
	slices.Sort(sorted)
	var runs []span
	for _, sequence := range slices.Compact(sorted) {
		if n := len(runs); n > 0 && runs[n-1].end == sequence {
			runs[n-1].end++
			continue
		}
		runs = append(runs, span{first: sequence, end: sequence + 1})
	}
	return runs
}

func (l ledger) encode(stream Stream) []byte {
	content := make([]byte, 0, ledgerHeaderBytes+spanBytes*len(l.spans)+4)
	content = append(content, ledgerMagic...)
	content = binary.LittleEndian.AppendUint16(content, format)
	content = append(content, byte(stream), 0)
	content = binary.LittleEndian.AppendUint64(content, l.watermark)
	content = binary.LittleEndian.AppendUint64(content, l.delivered)
	content = binary.LittleEndian.AppendUint64(content, l.lost)
	content = binary.LittleEndian.AppendUint32(content, uint32(len(l.spans)))
	for _, held := range l.spans {
		content = binary.LittleEndian.AppendUint64(content, held.first)
		content = binary.LittleEndian.AppendUint64(content, held.end)
	}
	return binary.LittleEndian.AppendUint32(content, checksum(content))
}

func decodeLedger(stream Stream, content []byte) (ledger, error) {
	if len(content) < ledgerHeaderBytes+4 || !bytes.Equal(content[:len(ledgerMagic)], ledgerMagic) {
		return ledger{}, fmt.Errorf("%w: it is not a ledger", errUnreadable)
	}
	if written := binary.LittleEndian.Uint16(content[4:]); written != format {
		if written > format {
			return ledger{}, fmt.Errorf("%w: format %d, and this agent reads format %d", ErrNewer, written, format)
		}
		return ledger{}, fmt.Errorf("%w: format %d is not one this agent writes", errUnreadable, written)
	}
	body := content[:len(content)-4]
	if binary.LittleEndian.Uint32(content[len(content)-4:]) != checksum(body) {
		return ledger{}, fmt.Errorf("%w: its checksum does not match what it holds", errUnreadable)
	}
	count := binary.LittleEndian.Uint32(body[32:])
	switch {
	case Stream(body[6]) != stream || body[7] != 0:
		return ledger{}, fmt.Errorf("%w: it belongs to stream %d", errUnreadable, body[6])
	case uint64(len(body)) != ledgerHeaderBytes+spanBytes*uint64(count):
		return ledger{}, fmt.Errorf("%w: it declares %d spans in %d bytes", errUnreadable, count, len(body))
	}
	read := ledger{
		watermark: binary.LittleEndian.Uint64(body[8:]),
		delivered: binary.LittleEndian.Uint64(body[16:]),
		lost:      binary.LittleEndian.Uint64(body[24:]),
		spans:     make([]span, count),
	}
	if read.watermark == 0 || read.watermark > maxSequence+1 {
		return ledger{}, fmt.Errorf("%w: its watermark is %d, and sequences count from 1 to %d", errUnreadable, read.watermark, uint64(maxSequence))
	}
	bound := read.watermark
	for i := range read.spans {
		at := ledgerHeaderBytes + spanBytes*i
		held := span{first: binary.LittleEndian.Uint64(body[at:]), end: binary.LittleEndian.Uint64(body[at+8:])}
		if held.first <= bound || held.end <= held.first || held.end > maxSequence+1 {
			return ledger{}, fmt.Errorf("%w: span %d does not follow what it settled before it", errUnreadable, i)
		}
		read.spans[i], bound = held, held.end
	}
	return read, nil
}
