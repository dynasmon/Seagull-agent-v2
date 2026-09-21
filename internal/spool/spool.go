// Package spool keeps what the agent admits until the platform has it. A record
// is admitted once it is durable, it is read back in the order it was admitted,
// and it leaves the spool only once its acknowledgement is durable, or once it
// is counted as lost because it could not be read back.
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

const (
	MaxIDBytes      = 255
	MaxPayloadBytes = 8 << 20
	reserved        = 64 << 10
	minSegmentBytes = 1 << 20
	maxSegmentBytes = 64 << 20
	segmentsPerLoad = 16
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
	MaxBytes int64
}

type Stats struct {
	MaxBytes int64
	Bytes    int64
	Streams  []StreamStats
}

type StreamStats struct {
	Stream      Stream
	Outstanding uint64
	Bytes       int64
	Delivered   uint64
	Lost        uint64
	Unavailable error
}

type Spool struct {
	lock   *os.File
	budget *budget
	queues []*queue

	mu     sync.Mutex
	closed bool
}

// Open holds the spool in root until Close, and reads back what it holds
// before it returns: an interrupted write is discarded, records that cannot be
// read back are counted as lost, and nothing it holds is otherwise dropped.
func Open(root *os.Root, limits Limits, logger *slog.Logger) (*Spool, error) {
	return open(root, limits, logger, system{})
}

func open(root *os.Root, limits Limits, logger *slog.Logger, held disk) (*Spool, error) {
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
	spooled := &Spool{lock: lock, budget: &budget{limit: limits.MaxBytes}}
	if err := spooled.recover(root, logger, held); err != nil {
		spooled.Close()
		return nil, err
	}
	return spooled, nil
}

func (s *Spool) recover(root *os.Root, logger *slog.Logger, held disk) error {
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
	var used int64
	for _, stream := range streams {
		directory, err := openDirectory(root, stream.String())
		if err != nil {
			return err
		}
		kept := &queue{stream: stream, root: directory, budget: s.budget, logger: logger, disk: held}
		s.queues = append(s.queues, kept)
		if err := kept.recover(); err != nil {
			return err
		}
		used += kept.stats().Bytes
	}
	s.budget.mu.Lock()
	s.budget.used = used
	s.budget.mu.Unlock()
	return nil
}

// Admit returns a receipt only once every record is durable, in the order the
// records were given; a record it refuses, or a write it cannot finish, admits
// none of them.
func (s *Spool) Admit(stream Stream, records ...Record) (Receipt, error) {
	kept, err := s.queue(stream)
	if err != nil {
		return Receipt{}, err
	}
	if len(records) == 0 {
		return Receipt{}, fmt.Errorf("%w: there is nothing to admit", ErrRefused)
	}
	return kept.admit(records)
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
	return kept.acknowledge(sequences)
}

func (s *Spool) Limit(limits Limits) {
	s.budget.mu.Lock()
	defer s.budget.mu.Unlock()
	s.budget.limit = limits.MaxBytes
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

type budget struct {
	mu    sync.Mutex
	limit int64
	used  int64
}

func (b *budget) reserve(bytes int64) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.used+bytes > b.limit-reserved {
		return fmt.Errorf("%w: it holds %d of %d bytes and keeps %d for its acknowledgements, and admitting %d more bytes would take them",
			ErrFull, b.used, b.limit, reserved, bytes)
	}
	b.used += bytes
	return nil
}

func (b *budget) add(bytes int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.used += bytes
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

func syncDirectory(root *os.Root, held disk) error {
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
