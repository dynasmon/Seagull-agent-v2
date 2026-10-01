// Package authentication collects what sshd decides as it authenticates the
// connections it takes, from the system journal, and admits each outcome to the
// spool as an authentication event before its place in the journal moves past
// the entry that said it.
package authentication

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/governor"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/journal"
	"github.com/dynasmon/Seagull-agent-v2/internal/protocol"
	"github.com/dynasmon/Seagull-agent-v2/internal/spool"
)

const (
	maxRecords = 256
	maxBytes   = 1 << 20
	frameBytes = 64
	source     = "journal"
)

type Spool interface {
	Admit(stream spool.Stream, records ...spool.Record) (spool.Receipt, error)
	Room(stream spool.Stream) int64
}

type Entries interface {
	Next() (journal.Entry, error)
	Pending() bool
	Close() error
}

type Options struct {
	Installation string
	Spool        Spool
	Governor     *governor.Governor
	Directory    *os.Root
	Logger       *slog.Logger
	Open         func(ctx context.Context, from journal.Position, follow bool) (Entries, error)
	Now          func() time.Time
}

type Stats struct {
	Admitted   uint64
	Unreadable uint64
	Aged       uint64
	Gaps       uint64
	Reached    time.Time
	Waiting    time.Time
}

type Collector struct {
	options Options
	logger  *slog.Logger

	mu    sync.Mutex
	stats Stats
}

type batch struct {
	records []spool.Record
	bytes   int64
	cursor  string
	read    time.Time
}

func (b *batch) full() bool { return len(b.records) >= maxRecords || b.bytes >= maxBytes }

func New(options Options) (*Collector, error) {
	var problems []error
	if options.Installation == "" || options.Spool == nil || options.Governor == nil || options.Directory == nil || options.Logger == nil {
		problems = append(problems, errors.New("an installation, a spool, a governor, a directory and a logger are all needed to collect"))
	}
	if options.Open == nil {
		reading, err := journal.New(query)
		if err != nil {
			problems = append(problems, err)
		}
		options.Open = func(ctx context.Context, from journal.Position, follow bool) (Entries, error) {
			reader, err := reading.Open(ctx, from, follow)
			if err != nil {
				return nil, err
			}
			return reader, nil
		}
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if len(problems) > 0 {
		return nil, fmt.Errorf("compose the %s collector: %w", Name, errors.Join(problems...))
	}
	return &Collector{options: options, logger: options.Logger.With(slog.String("module", Name))}, nil
}

// Collect reads what the journal holds from where the collector stopped, every
// boot the journal kept included, then follows the boot that is running until
// ctx ends. It returns early only when the journal or the spool cannot be read
// or written, and starting it again resumes from the last place it wrote down.
func (c *Collector) Collect(ctx context.Context) error {
	from, err := c.begin()
	if err == nil {
		from, err = c.read(ctx, from, false)
	}
	if err == nil {
		_, err = c.read(ctx, from, true)
		if err == nil {
			err = errors.New("journalctl stopped following the journal")
		}
	}
	if ctx.Err() != nil {
		return nil
	}
	return err
}

func (c *Collector) Stats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stats
}

func (c *Collector) begin() (position, error) {
	if err := discard(c.options.Directory); err != nil {
		return position{}, err
	}
	held, err := load(c.options.Directory)
	now := c.options.Now().UTC()
	switch {
	case err == nil:
		return held, nil
	case errors.Is(err, errUnwritten):
		started := position{Format: format, Since: now}
		if err := save(c.options.Directory, started); err != nil {
			return position{}, err
		}
		c.logger.Info("collection_started", slog.String("source", source), slog.Time("from", now))
		return started, nil
	case errors.Is(err, ErrDamaged):
		again := position{Format: format, Since: now.Add(-protocol.MaxEventAge)}
		if saved := save(c.options.Directory, again); saved != nil {
			return position{}, saved
		}
		c.logger.Warn("collection_place_lost", slog.String("source", source), slog.Any("error", err), slog.Time("from", again.Since),
			slog.String("reason", "the collector reads again every entry the platform still admits, and the events of those it read before are admitted again under the same names"),
			slog.String("recovery", "none"))
		return again, nil
	}
	return position{}, err
}

func (c *Collector) read(ctx context.Context, from position, follow bool) (position, error) {
	entries, err := c.options.Open(ctx, from.journal(), follow)
	if err != nil {
		return from, c.explain(err)
	}
	defer entries.Close()
	var held batch
	first := true
	for {
		if held.cursor != "" && (held.full() || !entries.Pending()) {
			next, err := c.flush(ctx, &held, from)
			if err != nil {
				return from, err
			}
			from = next
		}
		entry, err := entries.Next()
		switch {
		case errors.Is(err, journal.ErrUnreadable):
			c.unreadable(err)
			continue
		case errors.Is(err, io.EOF):
			if first && !follow && from.Cursor != "" {
				c.gap(from, time.Time{})
			}
			return c.flush(ctx, &held, from)
		case err != nil:
			if next, flushed := c.flush(ctx, &held, from); flushed == nil {
				from = next
			}
			return from, c.explain(err)
		}
		if first {
			first = false
			if from.Cursor != "" && entry.Cursor == from.Cursor {
				if !follow {
					c.logger.Info("collection_resumed", slog.String("source", source), slog.Time("after", from.Read))
				}
				continue
			}
			if from.Cursor != "" && !follow {
				c.gap(from, entry.Realtime)
			}
		}
		c.take(entry, &held)
	}
}

func (c *Collector) take(entry journal.Entry, held *batch) {
	held.cursor, held.read = entry.Cursor, entry.Realtime
	payload, id, seen := observe(c.options.Installation, entry, c.options.Now())
	switch seen {
	case aged:
		c.aged(entry)
	case observed:
		held.records = append(held.records, spool.Record{ID: id, Payload: payload})
		held.bytes += int64(frameBytes + len(id) + len(payload))
	}
}

func (c *Collector) flush(ctx context.Context, held *batch, from position) (position, error) {
	if held.cursor == "" {
		return from, nil
	}
	if len(held.records) > 0 {
		if err := c.admit(ctx, held.records, held.bytes+frameBytes); err != nil {
			return from, err
		}
		c.mu.Lock()
		c.stats.Admitted += uint64(len(held.records))
		c.mu.Unlock()
	}
	next := position{Format: format, Cursor: held.cursor, Read: held.read}
	if err := save(c.options.Directory, next); err != nil {
		return from, err
	}
	c.mu.Lock()
	c.stats.Reached = held.read
	c.mu.Unlock()
	*held = batch{}
	return next, nil
}

func (c *Collector) admit(ctx context.Context, records []spool.Record, need int64) error {
	for {
		_, err := c.options.Spool.Admit(spool.Events, records...)
		if !errors.Is(err, spool.ErrFull) {
			if err != nil {
				return fmt.Errorf("admit what sshd decided: %w", err)
			}
			return nil
		}
		c.waiting(time.Now())
		err = c.options.Governor.Room(ctx, func() int64 { return c.options.Spool.Room(spool.Events) }, need)
		c.waiting(time.Time{})
		if err != nil {
			return err
		}
	}
}

func (c *Collector) explain(err error) error {
	if errors.Is(err, journal.ErrDenied) {
		return fmt.Errorf("%w; it reads the system journal as a member of the systemd-journal group, which the service the package installs grants it", err)
	}
	return err
}

func (c *Collector) waiting(since time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stats.Waiting = since
}

func (c *Collector) gap(from position, next time.Time) {
	c.mu.Lock()
	c.stats.Gaps++
	c.mu.Unlock()
	reported := []any{slog.String("source", source), slog.Time("after", from.Read)}
	if !next.IsZero() {
		reported = append(reported, slog.Time("next", next))
	}
	c.logger.Warn("collection_gap", append(reported,
		slog.String("reason", "the journal no longer holds the last entry the collector read, so what journald dropped after it, before the collector read it, is lost"),
		slog.String("recovery", "keep the journal for longer than the agent may be stopped, with SystemMaxUse= and MaxRetentionSec= in journald.conf"))...)
}

func (c *Collector) unreadable(err error) {
	c.mu.Lock()
	c.stats.Unreadable++
	count := c.stats.Unreadable
	c.mu.Unlock()
	if doubled(count) {
		c.logger.Warn("collection_entry_unreadable", slog.String("source", source), slog.Any("error", err), slog.Uint64("unreadable", count),
			slog.String("recovery", "none: the collector reads on past it"))
	}
}

func (c *Collector) aged(entry journal.Entry) {
	c.mu.Lock()
	c.stats.Aged++
	count := c.stats.Aged
	c.mu.Unlock()
	if doubled(count) {
		c.logger.Warn("collection_entries_too_old", slog.String("source", source), slog.Time("written", entry.Realtime), slog.Uint64("too_old", count),
			slog.Duration("max_age", protocol.MaxEventAge),
			slog.String("reason", "the platform admits no event older than max_age, so the collector reads on past what sshd decided before it"),
			slog.String("recovery", "none: an agent stopped for less than max_age delivers everything sshd decided meanwhile"))
	}
}

func doubled(count uint64) bool { return count&(count-1) == 0 }
