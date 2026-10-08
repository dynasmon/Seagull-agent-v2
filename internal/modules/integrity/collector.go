// Package integrity watches the files of the host the agent is told to: it
// takes a baseline of what each path holds, has the kernel tell it what
// changes in the directories it walked, looks at those names again before it
// believes the kernel, and walks every path again every interval, after the
// kernel dropped what it had to say, and as it starts, to find what changed
// while nobody watched. It writes each change it finds down in the agent's log
// and nowhere else: the contracts the agent is built with have no record a
// file change travels in, so nothing it finds is admitted to the spool.
package integrity

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/governor"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/inotify"
)

const (
	Name      = "files"
	everyHour = time.Hour
)

var saveEvery = 10 * time.Second

type Options struct {
	Governor  *governor.Governor
	Directory *os.Root
	Logger    *slog.Logger
	Scope     func() Scope
	Interval  func() time.Duration
	Own       []string
	Watch     func() (Watcher, error)
}

type Collector struct {
	options  Options
	logger   *slog.Logger
	rescoped chan struct{}

	held    *baseline
	first   bool
	watcher Watcher
	covered string

	mu        sync.Mutex
	scope     scope
	byWatch   map[int]watched
	byPath    map[string]int
	dirty     map[string]*hint
	cookies   map[uint32][]string
	moved     map[string]bool
	holds     map[string]hold
	lost      uint64
	losses    uint64
	unwatched error
	hinted    chan struct{}
	ended     chan error
	stats     Stats
	changes   uint64
	unlogged  uint64
	changed   time.Time
	window    time.Time
	logged    int
	withheld  map[string]int
}

func New(options Options) (*Collector, error) {
	if options.Governor == nil || options.Directory == nil || options.Logger == nil || options.Scope == nil {
		return nil, fmt.Errorf("compose the %s collector: a governor, a directory, a logger and a scope are all needed to watch files", Name)
	}
	if options.Interval == nil {
		options.Interval = func() time.Duration { return everyHour }
	}
	if options.Watch == nil {
		options.Watch = func() (Watcher, error) {
			watcher, err := inotify.Open()
			if err != nil {
				return nil, err
			}
			return watcher, nil
		}
	}
	return &Collector{options: options, logger: options.Logger.With(slog.String("module", Name)), rescoped: make(chan struct{}, 1), withheld: map[string]int{}}, nil
}

// Rescope tells the module the scope it is given may have changed, which it
// applies as it next waits.
func (c *Collector) Rescope() {
	select {
	case c.rescoped <- struct{}{}:
	default:
	}
}

// Collect watches until ctx ends. It returns early only when what it saw
// cannot be written down or the kernel stops telling it what changes, and
// starting it again walks every path it watches from what it wrote down.
func (c *Collector) Collect(ctx context.Context) error {
	c.reset()
	if err := c.begin(); err != nil {
		return err
	}
	watcher, err := c.options.Watch()
	if err != nil {
		c.limited(err)
		c.logger.Warn("files_not_watched", slog.Any("error", err), slog.String("recovery", Recovery(fmt.Errorf("%w: %w", ErrUnwatched, err))))
	} else {
		c.watcher = watcher
	}
	var listening sync.WaitGroup
	if c.watcher != nil {
		listening.Go(func() { c.listen(watcher) })
	}
	defer func() {
		if c.watcher != nil {
			c.watcher.Close()
			listening.Wait()
			c.watcher = nil
		}
	}()
	err = c.serve(ctx)
	if saved := c.persist(); saved != nil && err == nil {
		err = saved
	}
	if ctx.Err() != nil {
		return nil
	}
	return err
}

func (c *Collector) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.byWatch, c.byPath, c.dirty, c.cookies, c.moved, c.holds = map[int]watched{}, map[string]int{}, map[string]*hint{}, map[uint32][]string{}, map[string]bool{}, map[string]hold{}
	c.lost, c.unwatched = 0, nil
	c.hinted, c.ended = make(chan struct{}, 1), make(chan error, 1)
	c.scope = scoped(c.options.Scope(), c.options.Own)
}

func (c *Collector) begin() error {
	if err := discard(c.options.Directory); err != nil {
		return err
	}
	held, err := load(c.options.Directory, c.scope.given, c.options.Own)
	c.first = err != nil
	switch {
	case err == nil:
		c.held = held
		return nil
	case errors.Is(err, errUnwritten):
	case errors.Is(err, ErrDamaged):
		c.logger.Warn("files_baseline_lost", slog.Any("error", err),
			slog.String("reason", "the module cannot tell what it last saw of the files it watches, so it takes what it sees now as the baseline, and reports nothing that changed before"),
			slog.String("recovery", "none"))
	default:
		return err
	}
	c.held = empty(c.scope.given)
	return nil
}

func (c *Collector) serve(ctx context.Context) error {
	if err := c.walk(ctx, "start", nil); err != nil {
		return err
	}
	var schedule *governor.Schedule
	var every time.Duration
	var last time.Time
	var settling *time.Timer
	defer func() {
		if settling != nil {
			settling.Stop()
		}
	}()
	for {
		if wanted := c.interval(); schedule == nil || wanted != every {
			var err error
			if schedule, err = c.options.Governor.Periodic(Name, wanted); err != nil {
				return err
			}
			every = wanted
		}
		due := schedule.Next(time.Now())
		if !last.IsZero() && !due.After(last) {
			due = schedule.Next(last)
		}
		walking := time.NewTimer(time.Until(due))
		var settled <-chan time.Time
		if settling != nil {
			settled = settling.C
		}
		select {
		case <-ctx.Done():
			walking.Stop()
			return nil
		case err := <-c.ended:
			walking.Stop()
			return fmt.Errorf("follow what changes in the directories the module watches: %w", err)
		case <-walking.C:
			last = due
			if err := c.walk(ctx, "interval", nil); err != nil {
				return err
			}
		case <-c.rescoped:
			walking.Stop()
			if err := c.rescope(ctx); err != nil {
				return err
			}
		case <-c.hinted:
			walking.Stop()
			if settling == nil {
				settling = time.NewTimer(settle)
			}
		case <-settled:
			walking.Stop()
			settling = nil
			next, err := c.realtime(ctx)
			if err != nil {
				return err
			}
			if !next.IsZero() {
				settling = time.NewTimer(max(time.Until(next), 10*time.Millisecond))
			}
		}
	}
}

func (c *Collector) interval() time.Duration {
	if every := c.options.Interval(); every > 0 {
		return every
	}
	return everyHour
}

func (c *Collector) rescope(ctx context.Context) error {
	given := c.options.Scope()
	if given.Equal(c.scope.given) {
		return nil
	}
	rescoped, err := c.held.rescope(given, c.options.Own)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.scope = scoped(given, c.options.Own)
	c.mu.Unlock()
	c.held = rescoped
	c.unwatch()
	return c.walk(ctx, "scope", nil)
}

// walk looks at the paths given, or all of them, whole. A walk over all of
// them that ends makes the scope it walked the baseline's.
func (c *Collector) walk(ctx context.Context, reason string, paths []string) error {
	began := time.Now()
	whole := paths == nil
	if whole {
		paths = c.scope.given.Paths
		if c.watcher != nil {
			c.mu.Lock()
			c.unwatched = nil
			c.mu.Unlock()
		}
	}
	err := c.options.Governor.Scan(ctx, governor.Scan{Module: Name}, func(ctx context.Context, meter *governor.Meter) error {
		done := &pass{c: c, ctx: ctx, meter: meter, origin: fromReconciliation, fresh: c.held.fresh, saved: time.Now()}
		for _, path := range paths {
			if err := done.root(path); err != nil {
				return err
			}
		}
		done.finish()
		return nil
	})
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return err
	}
	c.withholding()
	if whole {
		c.held.fresh = fresh{}
	}
	c.survey(time.Now())
	if err := c.persist(); err != nil {
		return err
	}
	stats := c.Stats()
	level := slog.LevelInfo
	if reason == "interval" {
		level = slog.LevelDebug
	}
	if c.first && whole {
		c.first = false
		c.logger.Info("files_watched", slog.Int("entries", stats.Entries), slog.Int("directories", stats.Directories), slog.Int("watched", stats.Watched),
			slog.Duration("took", time.Since(began)), slog.String("reason", "the module took what it sees now as the baseline of the paths it watches, and reports what changes from now on"))
		return nil
	}
	c.logger.Log(ctx, level, "files_walked", slog.String("because", reason), slog.Int("entries", stats.Entries), slog.Int("watched", stats.Watched),
		slog.Uint64("changes", stats.Changes), slog.Duration("took", time.Since(began)))
	return nil
}

func (c *Collector) realtime(ctx context.Context) (time.Time, error) {
	ready, moved, lost, next := c.due(time.Now())
	if lost > 0 {
		c.hintsLost()
		c.mu.Lock()
		clear(c.dirty)
		clear(c.cookies)
		c.mu.Unlock()
		return time.Time{}, c.walk(ctx, "overflow", nil)
	}
	if len(ready) == 0 && len(moved) == 0 {
		return next, nil
	}
	err := c.options.Governor.Scan(ctx, governor.Scan{Module: Name}, func(ctx context.Context, meter *governor.Meter) error {
		done := &pass{c: c, ctx: ctx, meter: meter, origin: fromRealtime, fresh: c.held.fresh, saved: time.Now()}
		if err := done.hinted(ready, moved); err != nil {
			return err
		}
		done.finish()
		return nil
	})
	if err != nil {
		if ctx.Err() != nil {
			return time.Time{}, nil
		}
		return time.Time{}, err
	}
	c.withholding()
	c.survey(time.Time{})
	if err := c.persist(); err != nil {
		return time.Time{}, err
	}
	c.mu.Lock()
	pending := len(c.dirty) > 0
	c.mu.Unlock()
	if pending && next.IsZero() {
		next = time.Now().Add(settle)
	}
	return next, nil
}

func (c *Collector) persist() error {
	if c.held == nil {
		return nil
	}
	return save(c.options.Directory, c.held)
}
