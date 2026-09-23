// Package spool keeps what the agent admits until the platform has it. A record
// is admitted once it is durable, it is read back in the order it was admitted,
// and it leaves the spool only once it settled: delivered, lost, expired or
// quarantined, each counted apart and none of them reported as another.
package spool

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/platform/files"
	"github.com/dynasmon/Seagull-agent-v2/internal/secrets"
)

type Stream uint8

const (
	Events Stream = iota + 1
	Inventory
)

var streams = []Stream{Events, Inventory}

func (s Stream) String() string {
	switch s {
	case Events:
		return "events"
	case Inventory:
		return "inventory"
	default:
		return fmt.Sprintf("stream(%d)", uint8(s))
	}
}

// The part of the budget a stream may hold. Events are what a host cannot
// produce again, so they may take seven eighths of it; inventory is collected
// again on the next scan, and takes at most half. Each is left room the other
// cannot take, so neither waits on the other for as long as the platform does.
func (s Stream) share() (int64, int64) {
	if s == Inventory {
		return 1, 2
	}
	return 7, 8
}

const (
	MaxIDBytes      = 255
	MaxPayloadBytes = 8 << 20
	reserved        = 64 << 10
	minFree         = 64 << 20
	minSegmentBytes = 1 << 20
	maxSegmentBytes = 64 << 20
	segmentsPerLoad = 16
	expiryInterval  = time.Minute
)

var (
	ErrFull        = errors.New("the spool holds all its budget allows")
	ErrUnavailable = errors.New("the spool can no longer make records durable")
	ErrRefused     = errors.New("the spool refuses the request")
	ErrDamaged     = errors.New("the spool holds what it did not write")
	ErrNewer       = errors.New("the spool was written by a newer agent")
	ErrInsecure    = errors.New("the spool is not private to the account the agent runs as")
	ErrLocked      = errors.New("another process holds the spool")
	ErrClosed      = errors.New("the spool is closed")
)

type Record struct {
	ID      string
	Payload []byte
}

type Receipt struct {
	Stream Stream
	First  uint64
	Last   uint64
}

type Entry struct {
	Sequence uint64
	Admitted time.Time
	ID       string
	Payload  []byte
}

type Limits struct {
	MaxBytes       int64
	MaxRecordBytes int64
	MaxAge         map[Stream]time.Duration
}

type Stats struct {
	MaxBytes int64
	Bytes    int64
	Streams  []StreamStats
}

type StreamStats struct {
	Stream      Stream
	MaxAge      time.Duration
	Outstanding uint64
	Bytes       int64
	Delivered   uint64
	Lost        uint64
	Expired     uint64
	Quarantined uint64
	Refused     uint64
	Paused      time.Time
	Unavailable error
}

type host interface {
	write(file *os.File, content []byte) (int, error)
	sync(file *os.File) error
	available(file *os.File) (int64, error)
	now() time.Time
}

type system struct{}

func (system) write(file *os.File, content []byte) (int, error) { return file.Write(content) }

func (system) sync(file *os.File) error { return file.Sync() }

func (system) available(file *os.File) (int64, error) { return files.Available(file) }

func (system) now() time.Time { return time.Now() }

type Spool struct {
	lock   *os.File
	budget *budget
	queues []*queue

	mu     sync.Mutex
	closed bool
}

func Open(root *os.Root, limits Limits, logger *slog.Logger) (*Spool, error) {
	return open(root, limits, logger, system{})
}

func open(root *os.Root, limits Limits, logger *slog.Logger, held host) (*Spool, error) {
	if logger == nil {
		return nil, errors.New("open the spool: no logger")
	}
	described, err := root.Stat(".")
	if err != nil {
		return nil, fmt.Errorf("inspect %s: %w", root.Name(), err)
	}
	if err := private(root.Name(), described); err != nil {
		return nil, err
	}
	lock, err := root.Open(".")
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", root.Name(), err)
	}
	if err := files.Lock(lock); err != nil {
		lock.Close()
		if errors.Is(err, files.ErrLocked) {
			return nil, fmt.Errorf("%w: %s", ErrLocked, root.Name())
		}
		return nil, err
	}
	room := func() (int64, error) { return held.available(lock) }
	spooled := &Spool{lock: lock, budget: &budget{room: room, held: map[Stream]int64{}}}
	spooled.budget.set(limits)
	if err := spooled.recover(root, logger, held, limits); err != nil {
		spooled.Close()
		return nil, err
	}
	return spooled, nil
}

func (s *Spool) recover(root *os.Root, logger *slog.Logger, held host, limits Limits) error {
	listed, err := root.Open(".")
	if err != nil {
		return fmt.Errorf("open %s: %w", root.Name(), err)
	}
	names, err := listed.Readdirnames(-1)
	listed.Close()
	if err != nil {
		return fmt.Errorf("list %s: %w", root.Name(), err)
	}
	for _, name := range names {
		if !slices.ContainsFunc(streams, func(stream Stream) bool { return stream.String() == name }) {
			return fmt.Errorf("%w: %s holds %s", ErrDamaged, root.Name(), secrets.Shown(name))
		}
	}
	created := false
	for _, stream := range streams {
		switch err := root.Mkdir(stream.String(), 0o700); {
		case err == nil:
			created = true
		case !errors.Is(err, fs.ErrExist):
			return fmt.Errorf("create %s: %w", filepath.Join(root.Name(), stream.String()), err)
		}
	}
	if created {
		if err := syncDirectory(root, held); err != nil {
			return err
		}
	}
	for _, stream := range streams {
		directory, err := openDirectory(root, stream.String())
		if err != nil {
			return err
		}
		kept := &queue{stream: stream, root: directory, budget: s.budget, logger: logger, host: held, maxAge: limits.MaxAge[stream]}
		s.queues = append(s.queues, kept)
		if err := kept.recover(); err != nil {
			return err
		}
		if _, err := kept.expire(); err != nil {
			return err
		}
	}
	s.budget.mu.Lock()
	defer s.budget.mu.Unlock()
	s.budget.used = 0
	for _, kept := range s.queues {
		held := kept.stats().Bytes
		s.budget.held[kept.stream] = held
		s.budget.used += held
	}
	return nil
}

// Admit returns a receipt only once every record is durable, in the order the
// records were given; a record it refuses, or a write it cannot finish, admits
// none of them. When there is no room for them, what outlived its age is
// expired first, and a refusal for room pauses the stream until one is admitted.
func (s *Spool) Admit(stream Stream, records ...Record) (Receipt, error) {
	kept, err := s.queue(stream)
	if err != nil {
		return Receipt{}, err
	}
	if len(records) == 0 {
		return Receipt{}, fmt.Errorf("%w: there is nothing to admit", ErrRefused)
	}
	receipt, err := kept.admit(records)
	if errors.Is(err, ErrFull) && s.expire() {
		receipt, err = kept.admit(records)
	}
	kept.pressure(len(records), err)
	return receipt, err
}

// Read returns the records of stream that are neither delivered nor lost, from
// sequence from onwards, in the order they were admitted: at most most records
// and bytes bytes of payload, and always the first one when there is one.
func (s *Spool) Read(stream Stream, from uint64, most, bytes int) ([]Entry, error) {
	kept, err := s.queue(stream)
	if err != nil {
		return nil, err
	}
	if most < 1 || bytes < 1 {
		return nil, fmt.Errorf("%w: a read takes at least one record and one byte", ErrRefused)
	}
	return kept.read(from, most, bytes)
}

func (s *Spool) Acknowledge(stream Stream, sequences ...uint64) error {
	kept, err := s.queue(stream)
	if err != nil || len(sequences) == 0 {
		return err
	}
	return kept.settle(sequences, delivered, "")
}

func (s *Spool) Quarantine(stream Stream, reason string, sequences ...uint64) error {
	kept, err := s.queue(stream)
	if err != nil || len(sequences) == 0 {
		return err
	}
	return kept.settle(sequences, quarantined, reason)
}

func (s *Spool) Room(stream Stream) int64 {
	kept, err := s.queue(stream)
	if err != nil {
		return 0
	}
	if _, err := kept.expireDue(); err != nil || !kept.admitting() {
		return 0
	}
	return s.budget.left(stream)
}

func (s *Spool) Limit(limits Limits) {
	s.budget.set(limits)
	for _, kept := range s.queues {
		kept.limit(limits.MaxAge[kept.stream])
	}
}

func (s *Spool) Stats() Stats {
	s.budget.mu.Lock()
	held := Stats{MaxBytes: s.budget.limit, Bytes: s.budget.used}
	s.budget.mu.Unlock()
	for _, kept := range s.queues {
		held.Streams = append(held.Streams, kept.stats())
	}
	return held
}

func (s *Spool) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	closed := make([]error, 0, len(s.queues)+1)
	for _, kept := range s.queues {
		closed = append(closed, kept.close())
	}
	return errors.Join(append(closed, s.lock.Close())...)
}

func (s *Spool) queue(stream Stream) (*queue, error) {
	for _, kept := range s.queues {
		if kept.stream == stream {
			return kept, nil
		}
	}
	return nil, fmt.Errorf("%w: the spool keeps no %s", ErrRefused, stream)
}

func (s *Spool) expire() bool {
	expired := false
	for _, kept := range s.queues {
		if settled, err := kept.expireDue(); err == nil && settled > 0 {
			expired = true
		}
	}
	return expired
}

type budget struct {
	room func() (int64, error)

	mu     sync.Mutex
	limit  int64
	record int64
	used   int64
	held   map[Stream]int64
}

func (b *budget) set(limits Limits) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.limit, b.record = limits.MaxBytes, limits.MaxRecordBytes
	if b.record <= 0 || b.record > MaxPayloadBytes {
		b.record = MaxPayloadBytes
	}
}

func (b *budget) reserve(stream Stream, bytes int64) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	numerator, denominator := stream.share()
	switch share := b.limit / denominator * numerator; {
	case b.used+bytes > b.limit-reserved:
		return fmt.Errorf("%w: it holds %d of the %d bytes it may keep, %d of them for its acknowledgements, and %d more do not fit",
			ErrFull, b.used, b.limit, reserved, bytes)
	case b.held[stream]+bytes > share:
		return fmt.Errorf("%w: %s holds %d bytes, of the %d its share of the spool allows, and %d more do not fit",
			ErrFull, stream, b.held[stream], share, bytes)
	}
	free, err := b.room()
	if err != nil {
		return err
	}
	if free-bytes < minFree {
		return fmt.Errorf("%w: the filesystem that holds it has %d bytes free, and it leaves %d free for what the agent must still write",
			ErrFull, free, minFree)
	}
	b.used += bytes
	b.held[stream] += bytes
	return nil
}

func (b *budget) left(stream Stream) int64 {
	b.mu.Lock()
	numerator, denominator := stream.share()
	left := min(b.limit-reserved-b.used, b.limit/denominator*numerator-b.held[stream])
	b.mu.Unlock()
	free, err := b.room()
	if err != nil {
		return 0
	}
	return max(min(left, free-minFree), 0)
}

func (b *budget) add(stream Stream, bytes int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.used += bytes
	b.held[stream] += bytes
}

func (b *budget) largest() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.record
}

func (b *budget) segment() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return min(max(b.limit/segmentsPerLoad, minSegmentBytes), maxSegmentBytes)
}

func openDirectory(root *os.Root, name string) (*os.Root, error) {
	path := filepath.Join(root.Name(), name)
	described, err := root.Lstat(name)
	switch {
	case err != nil:
		return nil, fmt.Errorf("inspect %s: %w", path, err)
	case !described.IsDir():
		return nil, fmt.Errorf("%w: %s is not a directory", ErrDamaged, path)
	}
	if err := private(path, described); err != nil {
		return nil, err
	}
	opened, err := root.OpenRoot(name)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	if held, err := opened.Stat("."); err != nil || !os.SameFile(held, described) {
		opened.Close()
		return nil, fmt.Errorf("%w: %s changed while it was being opened", ErrInsecure, path)
	}
	return opened, nil
}

func syncDirectory(root *os.Root, held host) error {
	directory, err := root.Open(".")
	if err != nil {
		return fmt.Errorf("open %s: %w", root.Name(), err)
	}
	if err := errors.Join(held.sync(directory), directory.Close()); err != nil {
		return fmt.Errorf("sync %s: %w", root.Name(), err)
	}
	return nil
}

func private(path string, described fs.FileInfo) error {
	if err := files.Private(described); err != nil {
		if errors.Is(err, errors.ErrUnsupported) {
			return fmt.Errorf("keep the spool in %s: %w", path, err)
		}
		return fmt.Errorf("%w: %s %v", ErrInsecure, path, err)
	}
	return nil
}
