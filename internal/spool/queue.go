package spool

import (
	"bufio"
	"cmp"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/secrets"
)

const (
	ledgerName    = "ledger"
	segmentSuffix = ".seg"
)

var (
	segmentPattern     = regexp.MustCompile(`^[0-9]{20}\.seg$`)
	interruptedPattern = regexp.MustCompile(`^\.ledger\.[0-9a-f]{16}\.tmp$`)
)

type segment struct {
	first uint64
	size  int64
}

func (s segment) name() string { return fmt.Sprintf("%020d%s", s.first, segmentSuffix) }

type cursor struct {
	first  uint64
	offset int64
	prev   uint64
}

type loss struct {
	segment string
	span    span
	bytes   int64
}

type disk interface {
	write(file *os.File, content []byte) (int, error)
	sync(file *os.File) error
}

type system struct{}

func (system) write(file *os.File, content []byte) (int, error) { return file.Write(content) }

func (system) sync(file *os.File) error { return file.Sync() }

type appender struct {
	file *os.File
	disk disk
}

func (a appender) Write(content []byte) (int, error) { return a.disk.write(a.file, content) }

// A queue is the spool of one stream: its segments, which only ever grow at
// the end of the last one, and its ledger. io is held across whatever changes
// the files and mu across whatever reads or changes what the queue holds in
// memory, so a read of the files never waits on a sync.
type queue struct {
	stream Stream
	root   *os.Root
	budget *budget
	logger *slog.Logger
	disk   disk

	io sync.Mutex

	mu       sync.Mutex
	closed   bool
	broken   error
	segments []segment
	active   *os.File
	next     uint64
	ledger   ledger
	held     int64
	bytes    int64
	cursor   cursor
}

func (q *queue) recover() error {
	names, err := q.names()
	if err != nil {
		return err
	}
	var segments []segment
	written := false
	for _, name := range names {
		switch {
		case interruptedPattern.MatchString(name):
			if err := q.root.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return fmt.Errorf("discard the interrupted write %s: %w", q.path(name), err)
			}
		case name == ledgerName:
			written = true
		case segmentPattern.MatchString(name):
			first, err := strconv.ParseUint(strings.TrimSuffix(name, segmentSuffix), 10, 64)
			if err != nil || first == 0 || first > maxSequence {
				return fmt.Errorf("%w: %s does not name a segment", ErrDamaged, q.path(name))
			}
			segments = append(segments, segment{first: first})
		default:
			return fmt.Errorf("%w: %s holds %s, which the spool did not write", ErrDamaged, q.root.Name(), secrets.Shown(name))
		}
	}
	slices.SortFunc(segments, func(a, b segment) int { return cmp.Compare(a.first, b.first) })
	for i := range segments {
		if segments[i].size, err = q.inspect(segments[i]); err != nil {
			return err
		}
	}
	if err := q.settled(written, segments); err != nil {
		return err
	}

	var losses []loss
	var file *os.File
	prev := q.ledger.highest() - 1
	for len(segments) > 0 {
		recovered, err := q.recoverLast(&segments[len(segments)-1])
		if err != nil {
			return err
		}
		losses = append(losses, recovered.losses...)
		if recovered.file != nil {
			file, prev = recovered.file, recovered.prev
			break
		}
		segments = segments[:len(segments)-1]
	}
	next := q.ledger.highest()
	if len(segments) > 0 {
		next = max(next, prev+1)
	}
	for _, lost := range losses {
		next = max(next, lost.span.end)
	}
	switch {
	case len(segments) == 0 && q.ledger.watermark < next:
		losses = append(losses, loss{span: span{first: q.ledger.watermark, end: next}})
	case len(segments) > 0:
		losses = append(losses, loss{span: span{first: q.ledger.watermark, end: segments[0].first}},
			loss{segment: segments[len(segments)-1].name(), span: span{first: prev + 1, end: next}})
	}

	q.segments, q.next, q.bytes = segments, next, q.held
	for _, held := range segments {
		q.bytes += held.size
	}
	if file != nil && prev+1 == next {
		q.active = file
	} else if file != nil {
		if err := file.Close(); err != nil {
			return fmt.Errorf("close %s: %w", q.path(segments[len(segments)-1].name()), err)
		}
	}
	if err := q.settleLost(losses); err != nil {
		return err
	}
	q.next = max(q.next, q.ledger.highest())
	q.compact()
	return nil
}

// What the ledger said before the agent stopped, or, when it is missing or
// cannot be read back, a ledger that settles nothing the segments still hold:
// every record they hold is delivered again rather than taken as delivered.
func (q *queue) settled(written bool, segments []segment) error {
	fresh := ledger{watermark: 1}
	if len(segments) > 0 {
		fresh.watermark = segments[0].first
	}
	if !written {
		if len(segments) > 0 {
			q.logger.Warn("spool_acknowledgements_lost", q.attributes(slog.String("ledger", q.path(ledgerName)),
				slog.String("reason", "the ledger is missing"),
				slog.String("recovery", "none: every record the stream holds is delivered again"))...)
		}
		return q.store(fresh)
	}
	read, held, err := q.load()
	switch {
	case errors.Is(err, errUnreadable):
		q.logger.Warn("spool_acknowledgements_lost", q.attributes(slog.String("ledger", q.path(ledgerName)),
			slog.Any("reason", err),
			slog.String("recovery", "none: every record the stream holds is delivered again"))...)
		return q.store(fresh)
	case err != nil:
		return err
	}
	q.ledger, q.held = read, held
	return nil
}

func (q *queue) load() (ledger, int64, error) {
	file, _, err := q.open(ledgerName, os.O_RDONLY)
	if err != nil {
		return ledger{}, 0, err
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, maxLedgerBytes+1))
	if err != nil {
		return ledger{}, 0, fmt.Errorf("read %s: %w", q.path(ledgerName), err)
	}
	if len(content) > maxLedgerBytes {
		return ledger{}, 0, fmt.Errorf("%s: %w: it is larger than %d bytes", q.path(ledgerName), errUnreadable, maxLedgerBytes)
	}
	read, err := decodeLedger(q.stream, content)
	if err != nil {
		return ledger{}, 0, fmt.Errorf("%s: %w", q.path(ledgerName), err)
	}
	return read, int64(len(content)), nil
}

func (q *queue) inspect(held segment) (int64, error) {
	file, described, err := q.open(held.name(), os.O_RDONLY)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	header := make([]byte, segmentHeaderBytes)
	read, err := file.ReadAt(header, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return 0, fmt.Errorf("read %s: %w", q.path(held.name()), err)
	}
	return described.Size(), q.belongs(held, header[:read])
}

// A header that does not verify belongs to no one, and the frames after it are
// read by their own checksums. One that verifies and names another stream, or
// another first record, is a file somebody moved.
func (q *queue) belongs(held segment, header []byte) error {
	described, ok := decodeSegmentHeader(header)
	switch {
	case !ok:
		return nil
	case described.format > format:
		return fmt.Errorf("%w: %s is format %d, and this agent reads format %d", ErrNewer, q.path(held.name()), described.format, format)
	case described.stream != q.stream:
		return fmt.Errorf("%w: %s holds records of %s", ErrDamaged, q.path(held.name()), described.stream)
	case described.first != held.first:
		return fmt.Errorf("%w: %s starts at record %d", ErrDamaged, q.path(held.name()), described.first)
	}
	return nil
}

type recovered struct {
	file   *os.File
	prev   uint64
	losses []loss
}

func (q *queue) recoverLast(held *segment) (recovered, error) {
	name := held.name()
	file, _, err := q.open(name, os.O_RDWR|os.O_APPEND)
	if err != nil {
		return recovered{}, err
	}
	buffer := make([]byte, chunkBytes)
	header := buffer[:min(held.size, segmentHeaderBytes)]
	if _, err := file.ReadAt(header, 0); err != nil {
		file.Close()
		return recovered{}, fmt.Errorf("read %s: %w", q.path(name), err)
	}
	end := int64(0)
	if _, ok := decodeSegmentHeader(header); ok {
		end = segmentHeaderBytes
	}
	walked := newWalk(file, q.stream, end, held.size, buffer)
	found := recovered{file: file, prev: held.first - 1}
	for {
		frame, _, skipped, err := walked.next(nil)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			file.Close()
			return recovered{}, fmt.Errorf("read %s: %w", q.path(name), err)
		}
		if frame.sequence <= found.prev {
			continue
		}
		if frame.sequence > found.prev+1 {
			found.losses = append(found.losses, loss{segment: name, span: span{first: found.prev + 1, end: frame.sequence}, bytes: skipped})
		}
		found.prev, end = frame.sequence, frame.offset+frame.size()
	}
	if end == held.size && end > 0 {
		return found, nil
	}

	interrupted, err := torn(file, q.stream, end, held.size, buffer)
	if err != nil {
		file.Close()
		return recovered{}, fmt.Errorf("read %s: %w", q.path(name), err)
	}
	discarded := held.size - end
	if end == 0 {
		err = errors.Join(file.Close(), q.root.Remove(name), q.syncDirectory())
		found.file = nil
	} else {
		err = errors.Join(file.Truncate(end), q.disk.sync(file))
		held.size = end
	}
	if err != nil {
		if found.file != nil {
			file.Close()
		}
		return recovered{}, fmt.Errorf("discard the last %d bytes of %s: %w", discarded, q.path(name), err)
	}
	if interrupted {
		q.logger.Warn("spool_write_interrupted", q.attributes(slog.String("segment", q.path(name)), slog.Int64("bytes", discarded),
			slog.String("recovery", "none: the write was never confirmed, so its records are admitted again"))...)
		return found, nil
	}
	lost := span{first: found.prev + 1, end: max(walked.headed, found.prev+1) + 1}
	found.losses = append(found.losses, loss{segment: name, span: lost, bytes: discarded})
	return found, nil
}

func (q *queue) admit(records []Record) (Receipt, error) {
	var frames int64
	for i, record := range records {
		switch {
		case record.ID == "" || len(record.ID) > MaxIDBytes:
			return Receipt{}, fmt.Errorf("%w: record %d has an identifier of %d bytes, and the spool keeps identifiers of 1 to %d bytes",
				ErrRefused, i, len(record.ID), MaxIDBytes)
		case len(record.Payload) == 0 || len(record.Payload) > MaxPayloadBytes:
			return Receipt{}, fmt.Errorf("%w: record %d holds %d bytes, and the spool keeps records of 1 to %d bytes",
				ErrRefused, i, len(record.Payload), MaxPayloadBytes)
		}
		frames += frameHeaderBytes + int64(len(record.ID)) + int64(len(record.Payload))
	}
	q.io.Lock()
	defer q.io.Unlock()
	q.mu.Lock()
	closed, broken, first, rotate := q.closed, q.broken, q.next, q.active == nil
	if !rotate {
		rotate = q.segments[len(q.segments)-1].size >= q.budget.segment()
	}
	q.mu.Unlock()
	switch {
	case closed:
		return Receipt{}, ErrClosed
	case broken != nil:
		return Receipt{}, fmt.Errorf("%w: %w", ErrUnavailable, broken)
	}
	needed := frames
	if rotate {
		needed += segmentHeaderBytes
	}
	if err := q.budget.reserve(needed); err != nil {
		return Receipt{}, err
	}
	if rotate {
		if err := q.rotate(first); err != nil {
			q.budget.add(-needed)
			return Receipt{}, err
		}
	}

	q.mu.Lock()
	file, last := q.active, q.segments[len(q.segments)-1]
	q.mu.Unlock()
	admitted := time.Now().UnixNano()
	writer := bufio.NewWriterSize(appender{file: file, disk: q.disk}, chunkBytes)
	for i, record := range records {
		writer.Write(encodeFrameHeader(q.stream, first+uint64(i), admitted, record.ID, record.Payload))
		writer.WriteString(record.ID)
		writer.Write(record.Payload)
	}
	if err := writer.Flush(); err != nil {
		q.budget.add(-frames)
		if undone := errors.Join(file.Truncate(last.size), q.disk.sync(file)); undone != nil {
			q.fail(fmt.Errorf("discard an unfinished write to %s: %w", q.path(last.name()), undone))
		}
		return Receipt{}, fmt.Errorf("write to %s: %w", q.path(last.name()), err)
	}
	if err := q.disk.sync(file); err != nil {
		failed := fmt.Errorf("sync %s: %w", q.path(last.name()), err)
		q.fail(failed)
		return Receipt{}, fmt.Errorf("%w: %w", ErrUnavailable, failed)
	}
	q.mu.Lock()
	q.segments[len(q.segments)-1].size += frames
	q.next += uint64(len(records))
	q.bytes += frames
	q.mu.Unlock()
	return Receipt{Stream: q.stream, First: first, Last: first + uint64(len(records)) - 1}, nil
}

func (q *queue) rotate(first uint64) error {
	q.mu.Lock()
	sealed := q.active
	q.active = nil
	q.mu.Unlock()
	if sealed != nil {
		if err := sealed.Close(); err != nil {
			return fmt.Errorf("close %s: %w", q.path(q.segments[len(q.segments)-1].name()), err)
		}
	}
	created := segment{first: first, size: segmentHeaderBytes}
	name := created.name()
	file, err := q.root.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("create %s: %w", q.path(name), err)
	}
	_, err = q.disk.write(file, encodeSegmentHeader(q.stream, first))
	if err == nil {
		err = q.disk.sync(file)
	}
	if err == nil {
		err = q.syncDirectory()
	}
	if err != nil {
		if undone := errors.Join(file.Close(), q.root.Remove(name)); undone != nil {
			q.fail(fmt.Errorf("discard %s, which could not be created whole: %w", q.path(name), undone))
		}
		return fmt.Errorf("create %s: %w", q.path(name), err)
	}
	q.mu.Lock()
	q.segments = append(q.segments, created)
	q.active = file
	q.bytes += segmentHeaderBytes
	q.mu.Unlock()
	return nil
}

func (q *queue) fail(err error) {
	q.mu.Lock()
	q.broken = err
	q.mu.Unlock()
	q.logger.Error("spool_unavailable", q.attributes(slog.Any("error", err),
		slog.String("recovery", "restart the agent, which reads back what the spool holds before it admits anything more"))...)
}

func (q *queue) read(from uint64, most, bytes int) ([]Entry, error) {
	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		return nil, ErrClosed
	}
	segments, next, settled, at := slices.Clone(q.segments), q.next, q.ledger.clone(), q.cursor
	q.mu.Unlock()

	from = max(from, 1)
	buffer := make([]byte, chunkBytes)
	var (
		entries  []Entry
		losses   []loss
		payloads int
		reached  *cursor
		stopped  bool
	)
	for i, held := range segments {
		upper := next
		if i+1 < len(segments) {
			upper = segments[i+1].first
		}
		if upper <= from || settled.count(held.first, upper) == upper-held.first {
			continue
		}
		file, _, err := q.open(held.name(), os.O_RDONLY)
		if errors.Is(err, fs.ErrNotExist) {
			if !q.holds(held.first) {
				continue
			}
			losses = append(losses, loss{segment: held.name(), span: span{first: held.first, end: upper}, bytes: held.size})
			continue
		}
		if err != nil {
			return nil, err
		}
		start, prev := int64(segmentHeaderBytes), held.first-1
		if at.first == held.first && from > at.prev && at.offset >= segmentHeaderBytes && at.offset <= held.size {
			start, prev = at.offset, at.prev
		}
		walked := newWalk(file, q.stream, start, held.size, buffer)
		wanted := func(found frame) bool {
			return found.sequence >= from && found.sequence > prev && found.sequence < upper && !settled.settled(found.sequence)
		}
		for !stopped {
			found, body, skipped, err := walked.next(wanted)
			if errors.Is(err, io.EOF) {
				if prev+1 < upper {
					losses = append(losses, loss{segment: held.name(), span: span{first: prev + 1, end: upper}, bytes: skipped})
				}
				reached = &cursor{first: held.first, offset: walked.at, prev: prev}
				break
			}
			if err != nil {
				file.Close()
				return nil, fmt.Errorf("read %s: %w", q.path(held.name()), err)
			}
			if found.sequence <= prev || found.sequence >= upper {
				continue
			}
			if found.sequence > prev+1 {
				losses = append(losses, loss{segment: held.name(), span: span{first: prev + 1, end: found.sequence}, bytes: skipped})
			}
			if found.sequence >= from && !settled.settled(found.sequence) {
				if len(entries) > 0 && (len(entries) >= most || payloads+found.payload > bytes) {
					reached, stopped = &cursor{first: held.first, offset: found.offset, prev: prev}, true
					break
				}
				entries = append(entries, Entry{
					Sequence: found.sequence,
					Admitted: time.Unix(0, found.admitted).UTC(),
					ID:       string(body[:found.idBytes]),
					Payload:  body[found.idBytes:],
				})
				payloads += found.payload
			}
			prev = found.sequence
		}
		file.Close()
		if stopped {
			break
		}
	}
	if reached != nil {
		q.mu.Lock()
		q.cursor = *reached
		q.mu.Unlock()
	}
	if err := q.settleLost(losses); err != nil {
		return nil, err
	}
	return entries, nil
}

func (q *queue) holds(first uint64) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return slices.ContainsFunc(q.segments, func(held segment) bool { return held.first == first })
}

func (q *queue) acknowledge(sequences []uint64) error {
	q.io.Lock()
	defer q.io.Unlock()
	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		return ErrClosed
	}
	for _, sequence := range sequences {
		if sequence == 0 || sequence >= q.next {
			q.mu.Unlock()
			return fmt.Errorf("%w: %s record %d was never admitted", ErrRefused, q.stream, sequence)
		}
	}
	updated, newly := q.ledger.settle(consecutive(sequences))
	q.mu.Unlock()
	if newly == 0 {
		return nil
	}
	updated.delivered += newly
	if err := q.store(updated); err != nil {
		return err
	}
	q.compact()
	return nil
}

// A loss is settled before it is reported, so a record is reported lost once,
// counted as lost for as long as the stream lasts, and its sequence is never
// handed to another record.
func (q *queue) settleLost(losses []loss) error {
	if len(losses) == 0 {
		return nil
	}
	q.io.Lock()
	defer q.io.Unlock()
	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		return ErrClosed
	}
	updated := q.ledger.clone()
	q.mu.Unlock()
	type report struct {
		segment string
		first   uint64
		records uint64
		bytes   int64
	}
	var reports []report
	for _, lost := range losses {
		var newly uint64
		updated, newly = updated.settle([]span{lost.span})
		updated.lost += newly
		switch n := len(reports); {
		case newly == 0:
		case n > 0 && reports[n-1].segment == lost.segment:
			reports[n-1].records += newly
			reports[n-1].bytes += lost.bytes
		default:
			reports = append(reports, report{segment: lost.segment, first: lost.span.first, records: newly, bytes: lost.bytes})
		}
	}
	if len(reports) == 0 {
		return nil
	}
	if err := q.store(updated); err != nil {
		return err
	}
	for _, lost := range reports {
		attributes := []any{slog.Uint64("first", lost.first), slog.Uint64("records", lost.records), slog.Int64("bytes", lost.bytes)}
		if lost.segment != "" {
			attributes = append(attributes, slog.String("segment", q.path(lost.segment)))
		}
		q.logger.Error("spool_records_lost", q.attributes(append(attributes,
			slog.String("recovery", "none: the records could not be read back, and they are counted as lost rather than delivered"))...)...)
	}
	q.compact()
	return nil
}

func (q *queue) compact() {
	q.mu.Lock()
	var removable []segment
	for i, held := range q.segments {
		upper := q.next
		if i+1 < len(q.segments) {
			upper = q.segments[i+1].first
		}
		if q.ledger.count(held.first, upper) == upper-held.first {
			removable = append(removable, held)
		}
	}
	q.mu.Unlock()
	removed := false
	for _, held := range removable {
		q.mu.Lock()
		if last := q.segments[len(q.segments)-1]; last.first == held.first && q.active != nil {
			q.active.Close()
			q.active = nil
		}
		q.mu.Unlock()
		if err := q.root.Remove(held.name()); err != nil && !errors.Is(err, fs.ErrNotExist) {
			q.logger.Warn("spool_not_compacted", q.attributes(slog.String("segment", q.path(held.name())), slog.Any("error", err),
				slog.String("recovery", "none: the spool removes it once it can"))...)
			continue
		}
		q.mu.Lock()
		q.segments = slices.DeleteFunc(q.segments, func(kept segment) bool { return kept.first == held.first })
		q.bytes -= held.size
		if q.cursor.first == held.first {
			q.cursor = cursor{}
		}
		q.mu.Unlock()
		q.budget.add(-held.size)
		removed = true
	}
	if !removed {
		return
	}
	if err := q.syncDirectory(); err != nil {
		q.logger.Warn("spool_not_compacted", q.attributes(slog.Any("error", err),
			slog.String("recovery", "none: a segment that comes back is removed again"))...)
	}
}

func (q *queue) store(next ledger) error {
	content := next.encode(q.stream)
	path := q.path(ledgerName)
	if len(content) > maxLedgerBytes {
		return fmt.Errorf("write %s: %d spans settled out of order take more than %d bytes", path, len(next.spans), maxLedgerBytes)
	}
	drawn := make([]byte, 8)
	rand.Read(drawn)
	temporary := "." + ledgerName + "." + hex.EncodeToString(drawn) + ".tmp"
	file, err := q.root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	_, err = q.disk.write(file, content)
	if err == nil {
		err = q.disk.sync(file)
	}
	err = errors.Join(err, file.Close())
	if err == nil {
		err = q.root.Rename(temporary, ledgerName)
	}
	if err != nil {
		return errors.Join(fmt.Errorf("write %s: %w", path, err), ignoreMissing(q.root.Remove(temporary)))
	}
	if err := q.syncDirectory(); err != nil {
		return err
	}
	q.mu.Lock()
	grown := int64(len(content)) - q.held
	q.ledger, q.held, q.bytes = next, int64(len(content)), q.bytes+grown
	q.mu.Unlock()
	q.budget.add(grown)
	return nil
}

func (q *queue) stats() StreamStats {
	q.mu.Lock()
	defer q.mu.Unlock()
	held := StreamStats{Stream: q.stream, Bytes: q.bytes, Delivered: q.ledger.delivered, Lost: q.ledger.lost, Unavailable: q.broken}
	if len(q.segments) > 0 {
		first := q.segments[0].first
		held.Outstanding = q.next - first - q.ledger.count(first, q.next)
	}
	return held
}

func (q *queue) close() error {
	q.io.Lock()
	defer q.io.Unlock()
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return nil
	}
	q.closed = true
	var closed error
	if q.active != nil {
		closed, q.active = q.active.Close(), nil
	}
	return errors.Join(closed, q.root.Close())
}

func (q *queue) open(name string, flag int) (*os.File, fs.FileInfo, error) {
	path := q.path(name)
	described, err := q.root.Lstat(name)
	switch {
	case err != nil:
		return nil, nil, fmt.Errorf("inspect %s: %w", path, err)
	case !described.Mode().IsRegular():
		return nil, nil, fmt.Errorf("%w: %s is not a regular file", ErrDamaged, path)
	}
	if err := private(path, described); err != nil {
		return nil, nil, err
	}
	file, err := q.root.OpenFile(name, flag, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("open %s: %w", path, err)
	}
	if opened, err := file.Stat(); err != nil || !os.SameFile(opened, described) {
		file.Close()
		return nil, nil, fmt.Errorf("%w: %s changed while it was being opened", ErrInsecure, path)
	}
	return file, described, nil
}

func (q *queue) names() ([]string, error) {
	directory, err := q.root.Open(".")
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", q.root.Name(), err)
	}
	defer directory.Close()
	names, err := directory.Readdirnames(-1)
	if err != nil {
		return nil, fmt.Errorf("list %s: %w", q.root.Name(), err)
	}
	return names, nil
}

func (q *queue) syncDirectory() error { return syncDirectory(q.root, q.disk) }

func (q *queue) path(name string) string { return filepath.Join(q.root.Name(), name) }

func (q *queue) attributes(extra ...any) []any {
	return append([]any{slog.String("stream", q.stream.String())}, extra...)
}

func ignoreMissing(err error) error {
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}
