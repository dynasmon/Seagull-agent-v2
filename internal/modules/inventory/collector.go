// Package inventory takes stock of what the host has: the distribution it
// runs, its kernel, its hardware, the packages dpkg installed, the services
// systemd manages, its network interfaces and its local accounts, and, as a
// module of its own, the processes it runs. Every interval each module takes
// its kinds whole, and admits a complete snapshot of a kind to the spool when
// what the host holds of it changed, or once the one the platform holds is a
// day old, give or take half an interval.
package inventory

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/governor"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/processes"
	"github.com/dynasmon/Seagull-agent-v2/internal/protocol"
	"github.com/dynasmon/Seagull-agent-v2/internal/spool"
)

const (
	everyHour  = time.Hour
	refresh    = 24 * time.Hour
	frameBytes = 64
)

var (
	ErrBeyondBatch = errors.New("one batch carries no inventory record this large")
	ErrClockBehind = errors.New("the clock is behind the last snapshot of this kind")
)

type Spool interface {
	Admit(stream spool.Stream, records ...spool.Record) (spool.Receipt, error)
	Room(stream spool.Stream) int64
}

type Options struct {
	Module       string
	Installation string
	Spool        Spool
	Governor     *governor.Governor
	Directory    *os.Root
	Logger       *slog.Logger
	Interval     func() time.Duration
	Largest      func() int64
	Host         Host
	Now          func() time.Time
}

type KindStats struct {
	Kind    string
	Items   int
	Taken   time.Time
	Sent    time.Time
	Failure error
	Merged  []string
	Skipped int
}

type Stats struct {
	Kinds   []KindStats
	Round   time.Time
	Waiting time.Time
}

type Collector struct {
	options Options
	logger  *slog.Logger
	takers  []taker

	mu      sync.Mutex
	kinds   []KindStats
	round   time.Time
	waiting time.Time
}

func New(options Options) (*Collector, error) {
	if options.Module == "" {
		options.Module = Name
	}
	if options.Module != Name && options.Module != Processes {
		return nil, fmt.Errorf("compose the %s collector: the modules that take stock are %s and %s", options.Module, Name, Processes)
	}
	if options.Installation == "" || options.Spool == nil || options.Governor == nil || options.Directory == nil || options.Logger == nil {
		return nil, fmt.Errorf("compose the %s collector: an installation, a spool, a governor, a directory and a logger are all needed to collect", options.Module)
	}
	if options.Interval == nil {
		options.Interval = func() time.Duration { return everyHour }
	}
	if options.Largest == nil {
		options.Largest = func() int64 { return spool.MaxPayloadBytes }
	}
	if options.Host == nil {
		options.Host = System()
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	collector := &Collector{options: options, logger: options.Logger.With(slog.String("module", options.Module))}
	for _, held := range kinds {
		if moduleOf(held.kind) == options.Module {
			collector.takers = append(collector.takers, held)
			collector.kinds = append(collector.kinds, KindStats{Kind: KindName(held.kind)})
		}
	}
	return collector, nil
}

// Collect takes stock as it starts and then every interval, phased by the
// installation so a fleet does not take it at once, until ctx ends. It
// returns early only when what it admitted cannot be written down, or the
// spool takes nothing, and starting it again starts from what it wrote down.
func (c *Collector) Collect(ctx context.Context) error {
	held, err := c.begin()
	if err != nil {
		return err
	}
	var schedule *governor.Schedule
	var every time.Duration
	for {
		if err := c.take(ctx, &held); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if wanted := c.interval(); schedule == nil || wanted != every {
			if schedule, err = c.options.Governor.Periodic(c.options.Module, wanted); err != nil {
				return err
			}
			every = wanted
		}
		if _, err := schedule.Wait(ctx); err != nil {
			return nil
		}
	}
}

func (c *Collector) Stats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	held := Stats{Round: c.round, Waiting: c.waiting, Kinds: slices.Clone(c.kinds)}
	for i := range held.Kinds {
		held.Kinds[i].Merged = slices.Clone(held.Kinds[i].Merged)
	}
	return held
}

func (c *Collector) begin() (baseline, error) {
	if err := discard(c.options.Directory, c.options.Module); err != nil {
		return baseline{}, err
	}
	held, err := load(c.options.Directory, c.options.Module)
	switch {
	case err == nil:
		c.mu.Lock()
		for i := range c.kinds {
			if sent, found := held.Kinds[c.kinds[i].Kind]; found {
				c.kinds[i].Sent, c.kinds[i].Items = sent.CollectedAt, sent.Items
			}
		}
		c.mu.Unlock()
		return held, nil
	case errors.Is(err, errUnwritten):
		return baseline{Format: format, Kinds: map[string]entry{}}, nil
	case errors.Is(err, ErrDamaged):
		c.logger.Warn("inventory_baseline_lost", slog.Any("error", err),
			slog.String("reason", "the collector cannot tell what it last admitted of the host, so it admits every kind again, which leaves what the platform holds as it was"),
			slog.String("recovery", "none"))
		return baseline{Format: format, Kinds: map[string]entry{}}, nil
	}
	return baseline{}, err
}

func (c *Collector) interval() time.Duration {
	if every := c.options.Interval(); every > 0 {
		return every
	}
	return everyHour
}

type chosen struct {
	Snapshot
	why string
	at  time.Time
}

func (c *Collector) take(ctx context.Context, held *baseline) error {
	began := time.Now()
	var admitting []chosen
	err := c.options.Governor.Scan(ctx, governor.Scan{Module: c.options.Module, Room: c.room, Needs: held.needs()}, func(ctx context.Context, meter *governor.Meter) error {
		for _, described := range c.takers {
			at := c.options.Now().UTC()
			taken, err := Take(ctx, c.options.Host, c.options.Installation, described.kind, at)
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err == nil {
				if err := meter.Charge(ctx, int64(len(taken.Encoded))); err != nil {
					return err
				}
				if largest := c.options.Largest(); int64(len(taken.Encoded)) > largest {
					err = fmt.Errorf("%w: it encodes to %d bytes, and a batch of transport.max_batch_bytes carries %d of one", ErrBeyondBatch, len(taken.Encoded), largest)
				}
			}
			name := KindName(described.kind)
			why, err := c.judge(name, taken, err, held.Kinds[name], at)
			c.noted(name, taken, err, at)
			if why != "" {
				admitting = append(admitting, chosen{Snapshot: taken, why: why, at: at})
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	if len(admitting) == 0 {
		c.ended(nil, began)
		return nil
	}
	if err := c.admit(ctx, admitting); err != nil {
		return err
	}
	for _, sent := range admitting {
		held.Kinds[sent.Kind] = entry{CollectedAt: sent.at, RecordID: sent.Record.GetRecordId(), Items: len(sent.Record.GetItems()), Bytes: len(sent.Encoded), Digest: sent.Digest}
	}
	if err := save(c.options.Directory, c.options.Module, *held); err != nil {
		return err
	}
	for _, sent := range admitting {
		c.logger.Info("inventory_admitted", slog.String("kind", sent.Kind), slog.Int("items", len(sent.Record.GetItems())), slog.Int("bytes", len(sent.Encoded)),
			slog.String("record_id", sent.Record.GetRecordId()), slog.Time("collected_at", sent.at), slog.String("because", sent.why))
	}
	c.ended(admitting, began)
	return nil
}

// judge says why a snapshot is admitted, or nothing when it is not. The
// platform orders the snapshots of a kind by when they were taken, to the
// millisecond, so one taken no later than the last the agent admitted would
// be held as older than it: the agent waits for its clock to pass that one,
// unless that one was further ahead than any platform admits a record.
func (c *Collector) judge(name string, taken Snapshot, failed error, last entry, at time.Time) (string, error) {
	if failed != nil {
		return "", failed
	}
	ahead := last.RecordID != "" && last.CollectedAt.Sub(at) > protocol.MaxClockSkew
	why := ""
	switch {
	case last.RecordID == "":
		return "first", nil
	case ahead:
		why = "the clock went back"
	case taken.Digest != last.Digest:
		why = "changed"
	case !at.Before(last.CollectedAt.Add(refresh - c.interval()/2)):
		why = "refreshed"
	default:
		return "", nil
	}
	switch {
	case ahead:
		c.logger.Warn("inventory_clock_regressed", slog.String("kind", name), slog.Time("collected_at", at), slog.Time("last", last.CollectedAt),
			slog.String("reason", "the last snapshot the agent admitted of this kind was taken further ahead than any platform admits, so the agent admits this one at the time its clock reads"),
			slog.String("recovery", "keep the clock of this host in time with the platform's"))
	case !at.Truncate(time.Millisecond).After(last.CollectedAt.Truncate(time.Millisecond)):
		return "", fmt.Errorf("%w: the clock reads %s, and the last snapshot of %s the agent admitted was taken at %s", ErrClockBehind,
			at.Format(time.RFC3339Nano), name, last.CollectedAt.Format(time.RFC3339Nano))
	}
	return why, nil
}

func (c *Collector) noted(name string, taken Snapshot, failed error, at time.Time) {
	c.mu.Lock()
	held := c.kind(name)
	before, merged, skipped := held.Failure, held.Merged, held.Skipped
	held.Failure = failed
	if failed == nil || errors.Is(failed, ErrClockBehind) {
		held.Items, held.Taken, held.Merged, held.Skipped = len(taken.Record.GetItems()), at, taken.Merged, taken.Skipped
	}
	c.mu.Unlock()
	switch {
	case failed != nil && (before == nil || before.Error() != failed.Error()):
		level, message := slog.LevelWarn, "inventory_not_collected"
		switch {
		case errors.Is(failed, ErrUnsupported):
			level = slog.LevelInfo
		case errors.Is(failed, ErrClockBehind):
			message = "inventory_deferred"
		}
		c.logger.Log(context.Background(), level, message, slog.String("kind", name), slog.Any("error", failed), slog.String("recovery", Recovery(failed)))
	case failed == nil && before != nil:
		c.logger.Info("inventory_collected_again", slog.String("kind", name))
	}
	if failed == nil && len(taken.Merged) > 0 && !slices.Equal(taken.Merged, merged) {
		c.logger.Warn("inventory_items_merged", slog.String("kind", name), slog.Any("merged", taken.Merged),
			slog.String("reason", "the platform identifies these items by what they share, and keeps one of them, whichever it is"),
			slog.String("recovery", "check why they share it: a second account with uid 0 beside root is a common way to keep a hold on a host"))
	}
	if failed == nil && taken.Skipped > 0 && taken.Skipped != skipped {
		c.logger.Warn("inventory_entries_skipped", slog.String("kind", name), slog.Int("skipped", taken.Skipped),
			slog.String("reason", "lines of the host's account files are no account or group as the C library reads them, so they are not in the snapshot"),
			slog.String("recovery", "correct or remove those lines of /etc/passwd and /etc/group"))
	}
}

func Recovery(failed error) string {
	switch {
	case errors.Is(failed, ErrUnsupported):
		return "none: this kind is not taken on this host"
	case errors.Is(failed, ErrTooLarge):
		return "none: the platform takes no larger inventory record, and the agent never sends part of a kind as if it were the whole; it sends the kind again once it fits"
	case errors.Is(failed, ErrBeyondBatch):
		return "raise transport.max_batch_bytes, up to the 8MiB the platform takes"
	case errors.Is(failed, ErrClockBehind):
		return "none: the agent admits the kind once its clock passes the last snapshot it admitted"
	case errors.Is(failed, processes.ErrHidden):
		return "have the service show the agent every process: a drop-in for seagull-agent.service that sets ProtectProc=default, then systemctl daemon-reload and systemctl restart seagull-agent"
	}
	var inadmissible *protocol.Inadmissible
	if errors.As(failed, &inadmissible) {
		return "none: the platform would refuse what the host holds of this kind, and the agent sends the kind again once it can take it"
	}
	return "none: the agent takes the kind again at its next round"
}

func (c *Collector) ended(admitted []chosen, began time.Time) {
	c.mu.Lock()
	for _, sent := range admitted {
		c.kind(sent.Kind).Sent = sent.at
	}
	c.round = c.options.Now().UTC()
	c.mu.Unlock()
	c.logger.Debug("inventory_taken", slog.Int("admitted", len(admitted)), slog.Duration("took", time.Since(began)))
}

func (c *Collector) kind(name string) *KindStats {
	for i := range c.kinds {
		if c.kinds[i].Kind == name {
			return &c.kinds[i]
		}
	}
	c.kinds = append(c.kinds, KindStats{Kind: name})
	return &c.kinds[len(c.kinds)-1]
}

func (c *Collector) room() int64 { return c.options.Spool.Room(spool.Inventory) }

func (c *Collector) admit(ctx context.Context, admitting []chosen) error {
	records := make([]spool.Record, len(admitting))
	var need int64
	for i, sent := range admitting {
		records[i] = spool.Record{ID: sent.Record.GetRecordId(), Payload: sent.Encoded}
		need += int64(frameBytes + len(records[i].ID) + len(records[i].Payload))
	}
	for {
		_, err := c.options.Spool.Admit(spool.Inventory, records...)
		if !errors.Is(err, spool.ErrFull) {
			if err != nil {
				return fmt.Errorf("admit what the host has: %w", err)
			}
			return nil
		}
		c.wait(time.Now())
		err = c.options.Governor.Room(ctx, c.room, need)
		c.wait(time.Time{})
		if err != nil {
			return err
		}
	}
}

func (c *Collector) wait(since time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.waiting = since
}
