// Package network watches what the host listens on and what it talks to, as
// the kernel's socket tables say every interval: each listener, and each
// flow, the connections of one account with one remote address on one service
// port, in each network namespace procfs shows the agent. It writes down what
// opens and closes in the agent's log and nowhere else: the contracts the
// agent is built with have no record a connection travels in, so nothing it
// finds is admitted to the spool.
package network

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/governor"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/accounts"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/sockets"
)

const (
	Name         = "network"
	everyMinute  = time.Minute
	fromStart    = "start"
	fromInterval = "interval"
)

var limits = sockets.Limits{Processes: 1 << 16, Namespaces: maxNamespaces, Sockets: 1 << 16, Descriptors: 1 << 18}

type Options struct {
	Governor  *governor.Governor
	Directory *os.Root
	Logger    *slog.Logger
	Interval  func() time.Duration
	Read      func(context.Context, sockets.Limits) (sockets.Reading, error)
	Accounts  func() (accounts.Database, error)
	Now       func() time.Time
}

type Collector struct {
	options Options
	logger  *slog.Logger

	held     *state
	whole    bool
	written  []byte
	covered  string
	failures int

	mu       sync.Mutex
	stats    Stats
	window   time.Time
	logged   int
	withheld map[string]int
	changes  uint64
	unlogged uint64
	changed  time.Time
}

func New(options Options) (*Collector, error) {
	if options.Governor == nil || options.Directory == nil || options.Logger == nil {
		return nil, fmt.Errorf("compose the %s collector: a governor, a directory and a logger are all needed to watch the network", Name)
	}
	if options.Interval == nil {
		options.Interval = func() time.Duration { return everyMinute }
	}
	if options.Read == nil {
		options.Read = sockets.Read
	}
	if options.Accounts == nil {
		options.Accounts = accounts.Read
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	return &Collector{options: options, logger: options.Logger.With(slog.String("module", Name)), withheld: map[string]int{}}, nil
}

// Collect watches until ctx ends, a round as it starts and one every
// interval. It returns early only when what it saw cannot be written down or
// the host has no socket tables, and starting it again compares what it sees
// with what it wrote down.
func (c *Collector) Collect(ctx context.Context) error {
	if err := c.begin(); err != nil {
		return err
	}
	if err := c.round(ctx, fromStart); err != nil {
		return err
	}
	var schedule *governor.Schedule
	var every time.Duration
	var last time.Time
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
		waiting := time.NewTimer(time.Until(due))
		select {
		case <-ctx.Done():
			waiting.Stop()
			return nil
		case <-waiting.C:
			last = due
			if err := c.round(ctx, fromInterval); err != nil {
				return err
			}
		}
	}
}

func (c *Collector) interval() time.Duration {
	if every := c.options.Interval(); every > 0 {
		return every
	}
	return everyMinute
}

func (c *Collector) begin() error {
	c.held, c.whole, c.written, c.covered, c.failures = nil, true, nil, "", 0
	if err := discard(c.options.Directory); err != nil {
		return err
	}
	held, err := load(c.options.Directory)
	switch {
	case err == nil:
		c.held = held
	case errors.Is(err, errUnwritten):
	case errors.Is(err, ErrDamaged):
		c.logger.Warn("network_state_lost", slog.Any("error", err),
			slog.String("reason", "the module cannot tell what it last saw of the network, so it takes what it sees now as the baseline, and reports nothing that changed before"),
			slog.String("recovery", "none"))
	default:
		return err
	}
	return nil
}

func (c *Collector) round(ctx context.Context, origin string) error {
	began := time.Now()
	var reading sockets.Reading
	err := c.options.Governor.Scan(ctx, governor.Scan{Module: Name}, func(ctx context.Context, meter *governor.Meter) error {
		var err error
		if reading, err = c.options.Read(ctx, limits); err != nil {
			return err
		}
		return meter.Charge(ctx, reading.Bytes)
	})
	switch {
	case ctx.Err() != nil:
		return nil
	case errors.Is(err, errors.ErrUnsupported):
		return err
	case err != nil:
		c.failed(err)
		return nil
	}
	if c.failures > 0 {
		c.logger.Info("network_observed_again", slog.Int("failures", c.failures))
		c.failures = 0
	}
	previous, first := c.held, c.held == nil
	compared := &comparison{now: c.options.Now(), adopting: first || origin == fromStart || !c.whole, ending: origin == fromStart,
		complete: reading.Unvisited == nil && !reading.Hidden && reading.Refused == 0 && reading.Unread == 0}
	if !first && origin == fromStart && previous.boot != reading.Boot {
		previous, compared.quiet = rebooted(previous), true
	}
	c.held = compared.compare(previous, reading)
	c.whole = reading.Unvisited == nil && !reading.Hidden && reading.Refused == 0 && reading.Skipped == 0
	names := c.names()
	for _, found := range compared.changes {
		c.report(found, origin, names)
	}
	c.withholding()
	content, err := encode(c.held)
	if err != nil {
		return fmt.Errorf("write down what the module saw of the network: %w", err)
	}
	if !bytes.Equal(content, c.written) {
		if err := save(c.options.Directory, content); err != nil {
			return err
		}
		c.written = content
	}
	c.survey(reading, compared.untracked, compared.now)
	stats := c.Stats()
	if first {
		c.logger.Info("network_watched", slog.Int("namespaces", stats.Namespaces), slog.Int("listeners", stats.Listeners), slog.Int("flows", stats.Flows),
			slog.Int("connections", stats.Connections), slog.Duration("took", time.Since(began)),
			slog.String("reason", "the module took what it sees now as the baseline of the network, and reports what opens and closes from now on"))
		return nil
	}
	level := slog.LevelDebug
	if origin == fromStart {
		level = slog.LevelInfo
	}
	c.logger.Log(ctx, level, "network_observed", slog.String("because", origin), slog.Int("namespaces", stats.Namespaces), slog.Int("listeners", stats.Listeners),
		slog.Int("flows", stats.Flows), slog.Int("connections", stats.Connections), slog.Int("changes", len(compared.changes)), slog.Duration("took", time.Since(began)))
	return nil
}

// failed says why a round read nothing, at the first failure and each time
// their count doubles, and keeps what the module saw before as it was.
func (c *Collector) failed(err error) {
	c.failures++
	c.mu.Lock()
	c.stats.Failure = err
	c.mu.Unlock()
	if c.failures&(c.failures-1) == 0 {
		c.logger.Warn("network_not_observed", slog.Any("error", err), slog.Int("failures", c.failures), slog.String("recovery", Recovery(err)))
	}
}

func rebooted(held *state) *state {
	own := *held.spaces[0]
	own.flows, own.connected = map[conversation]*flow{}, map[connected]conversation{}
	return &state{boot: held.boot, spaces: []*space{&own}}
}

func (c *Collector) names() map[uint32]string {
	named := map[uint32]string{}
	held, err := c.options.Accounts()
	if err != nil {
		return named
	}
	for _, account := range held.Accounts {
		if _, found := named[account.UID]; !found {
			named[account.UID] = account.Name
		}
	}
	return named
}
