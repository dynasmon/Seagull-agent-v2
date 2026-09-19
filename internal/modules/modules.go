package modules

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"slices"
	"strings"
	"sync"
	"time"
)

// Collect owns every goroutine, timer, descriptor and checkpoint the module
// starts, and returns once all of them have stopped: after ctx is cancelled,
// or earlier when the module fails. Goroutines share the agent's process and
// its privileges, so one is a unit of lifecycle and never of isolation.
type Module struct {
	Name    string
	Enabled bool
	Collect func(ctx context.Context) error
}

type State int

const (
	Disabled State = iota + 1
	Running
	Degraded
	Failed
)

func (s State) String() string {
	switch s {
	case Disabled:
		return "disabled"
	case Running:
		return "running"
	case Degraded:
		return "degraded"
	case Failed:
		return "failed"
	default:
		return fmt.Sprintf("state(%d)", int(s))
	}
}

type Health struct {
	Name     string
	State    State
	Since    time.Time
	Restarts int
	Reason   string
}

// How the collection treats a module that fails: it waits Backoff before
// starting it again and twice as long after each failure, up to MaxBackoff,
// and leaves the module alone once Budget failures happen in a row. A module
// that collected for Recovered has its failures forgiven. Stop bounds how long
// the collection waits for a module to return. A field left at zero takes the
// value this package documents; a negative one is refused.
type Policy struct {
	Backoff    time.Duration
	MaxBackoff time.Duration
	Budget     int
	Recovered  time.Duration
	Stop       time.Duration
}

const (
	backoff    = time.Second
	maxBackoff = 5 * time.Minute
	budget     = 5
	recovered  = 5 * time.Minute
	stop       = 5 * time.Second
	jitter     = 0.2
	maxReason  = 256
)

var (
	errStoppedEarly = errors.New("stopped before the agent was asked to stop")
	errStopping     = errors.New("the collection is stopping")
)

type module struct {
	Module
	desired  bool
	running  bool
	spent    bool
	since    time.Time
	restarts int
	failures int
	reason   string
	cancel   context.CancelFunc
	done     chan struct{}
}

func (m *module) state() State {
	switch {
	case !m.desired:
		return Disabled
	case m.running:
		return Running
	case m.spent:
		return Failed
	default:
		return Degraded
	}
}

func (m *module) attributes() []any {
	return []any{slog.String("module", m.Name), slog.String("state", m.state().String())}
}

// Collection runs the modules this build has, each in its own goroutine, and
// keeps the rest collecting whatever one of them does. It is not the agent's
// runtime: the runtime owns components, and this owns the collectors inside one.
type Collection struct {
	logger *slog.Logger
	policy Policy

	mu       sync.Mutex
	modules  map[string]*module
	order    []string
	work     context.Context
	stopping bool
	ran      bool
}

func New(logger *slog.Logger, policy Policy, held ...Module) (*Collection, error) {
	var problems []error
	if logger == nil {
		problems = append(problems, errors.New("no logger"))
	}
	settled, refused := policy.settled()
	problems = append(problems, refused...)
	collection := &Collection{logger: logger, policy: settled, modules: map[string]*module{}}
	for i, held := range held {
		label := held.Name
		switch {
		case label == "":
			label = fmt.Sprintf("module %d", i)
			problems = append(problems, fmt.Errorf("%s has no name", label))
		case collection.modules[label] != nil:
			problems = append(problems, fmt.Errorf("%s is composed twice", label))
		}
		if held.Collect == nil {
			problems = append(problems, fmt.Errorf("%s has nothing to collect", label))
		}
		if collection.modules[label] == nil {
			collection.order = append(collection.order, label)
		}
		collection.modules[label] = &module{Module: held, desired: held.Enabled, since: time.Now()}
	}
	if len(problems) > 0 {
		return nil, fmt.Errorf("compose the collection: %w", errors.Join(problems...))
	}
	return collection, nil
}

func (p Policy) settled() (Policy, []error) {
	var problems []error
	settle := func(name string, held, fallback time.Duration) time.Duration {
		switch {
		case held < 0:
			problems = append(problems, fmt.Errorf("%s %s is not a time to wait", name, held))
		case held == 0:
			return fallback
		}
		return held
	}
	settled := Policy{
		Backoff:    settle("backoff", p.Backoff, backoff),
		MaxBackoff: settle("maximum backoff", p.MaxBackoff, maxBackoff),
		Budget:     p.Budget,
		Recovered:  settle("recovery", p.Recovered, recovered),
		Stop:       settle("stop", p.Stop, stop),
	}
	switch {
	case p.Budget < 0:
		problems = append(problems, fmt.Errorf("a budget of %d restarts is not one", p.Budget))
	case p.Budget == 0:
		settled.Budget = budget
	}
	if settled.MaxBackoff < settled.Backoff {
		problems = append(problems, fmt.Errorf("a backoff of %s is longer than the maximum %s", settled.Backoff, settled.MaxBackoff))
	}
	return settled, problems
}

func (c *Collection) Run(ctx context.Context) error {
	c.mu.Lock()
	if c.ran {
		c.mu.Unlock()
		return errors.New("the collection runs once")
	}
	c.ran, c.work = true, ctx
	var starting [][]any
	for _, name := range c.order {
		if held := c.modules[name]; held.desired {
			starting = append(starting, c.start(held))
		}
	}
	c.mu.Unlock()
	for _, attributes := range starting {
		c.logger.Info("module_started", attributes...)
	}

	<-ctx.Done()

	c.mu.Lock()
	c.stopping, c.work = true, nil
	running := c.waiting(c.order)
	c.mu.Unlock()
	if stuck := await(running, c.policy.Stop); len(stuck) > 0 {
		return fmt.Errorf("%s still running %s after the stop", strings.Join(stuck, ", "), c.policy.Stop)
	}
	return nil
}

// Apply is the set of modules that should be collecting. A name this build
// does not have refuses the whole set, so no module is left half applied, and
// a module that spent its budget is tried again when it is named: the budget
// bounds what the agent retries on its own, not what an operator asks for.
func (c *Collection) Apply(enabled []string) error {
	c.mu.Lock()
	var unknown []string
	for _, name := range enabled {
		if c.modules[name] == nil && !slices.Contains(unknown, name) {
			unknown = append(unknown, name)
		}
	}
	if len(unknown) > 0 {
		c.mu.Unlock()
		return fmt.Errorf("this build collects with %s, and it was asked to collect with %s",
			strings.Join(c.order, ", "), strings.Join(unknown, ", "))
	}
	if c.stopping {
		c.mu.Unlock()
		return errStopping
	}
	var starting, disabled [][]any
	var releasing []string
	for _, name := range c.order {
		held := c.modules[name]
		switch collecting := slices.Contains(enabled, name); {
		case collecting && (!held.desired || held.spent):
			if held.spent {
				held.restarts++
			}
			held.desired, held.spent, held.failures = true, false, 0
			if c.work != nil && held.done == nil {
				starting = append(starting, c.start(held))
			}
		case !collecting && held.desired:
			held.desired = false
			if held.done == nil {
				disabled = append(disabled, held.attributes())
				continue
			}
			held.cancel()
			releasing = append(releasing, name)
		}
	}
	released := c.waiting(releasing)
	c.mu.Unlock()
	for _, attributes := range starting {
		c.logger.Info("module_started", attributes...)
	}
	for _, attributes := range disabled {
		c.logger.Info("module_disabled", attributes...)
	}

	if stuck := await(released, c.policy.Stop); len(stuck) > 0 {
		return fmt.Errorf("%s still running %s after being disabled", strings.Join(stuck, ", "), c.policy.Stop)
	}
	return nil
}

func (c *Collection) Health() []Health {
	c.mu.Lock()
	defer c.mu.Unlock()
	held := make([]Health, 0, len(c.order))
	for _, name := range c.order {
		module := c.modules[name]
		held = append(held, Health{
			Name:     name,
			State:    module.state(),
			Since:    module.since,
			Restarts: module.restarts,
			Reason:   module.reason,
		})
	}
	return held
}

func (c *Collection) start(held *module) []any {
	work, cancel := context.WithCancel(c.work)
	held.cancel, held.done = cancel, make(chan struct{})
	held.running, held.reason, held.since = true, "", time.Now()
	go c.collect(work, held)
	return append(held.attributes(), slog.Int("restarts", held.restarts))
}

func (c *Collection) waiting(names []string) []waiting {
	held := make([]waiting, 0, len(names))
	for _, name := range names {
		if module := c.modules[name]; module.done != nil {
			held = append(held, waiting{name: name, done: module.done})
		}
	}
	return held
}

func (c *Collection) collect(ctx context.Context, held *module) {
	defer c.released(held)
	for {
		started := time.Now()
		err := held.Collect(ctx)
		if ctx.Err() != nil {
			c.stopped(held)
			return
		}
		wait, spent := c.failed(held, err, time.Since(started))
		if spent {
			return
		}
		timer := time.NewTimer(wait)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			c.stopped(held)
			return
		}
		c.mu.Lock()
		held.restarts++
		held.running, held.reason, held.since = true, "", time.Now()
		attributes := append(held.attributes(), slog.Int("restarts", held.restarts))
		c.mu.Unlock()
		c.logger.Info("module_started", attributes...)
	}
}

func (c *Collection) failed(held *module, err error, ran time.Duration) (time.Duration, bool) {
	c.mu.Lock()
	if err == nil {
		err = errStoppedEarly
	}
	if ran >= c.policy.Recovered {
		held.failures = 0
	}
	held.running, held.failures, held.since = false, held.failures+1, time.Now()
	held.reason = bounded(err.Error())
	held.spent = held.failures >= c.policy.Budget
	wait := c.backoff(held.failures)
	attributes := append(held.attributes(), slog.Any("error", err), slog.Int("failures", held.failures))
	spent := held.spent
	c.mu.Unlock()

	if spent {
		c.logger.Error("module_failed", append(attributes,
			slog.String("recovery", "correct what the module reports and ask the agent to collect with it again"))...)
		return 0, true
	}
	c.logger.Warn("module_restarting", append(attributes, slog.Duration("in", wait))...)
	return wait, false
}

func (c *Collection) stopped(held *module) {
	c.mu.Lock()
	held.running, held.since = false, time.Now()
	c.mu.Unlock()
	c.logger.Info("module_stopped", slog.String("module", held.Name))
}

func (c *Collection) released(held *module) {
	c.mu.Lock()
	done := held.done
	held.cancel, held.done, held.running = nil, nil, false
	c.mu.Unlock()
	close(done)
}

func (c *Collection) backoff(failures int) time.Duration {
	wait := c.policy.Backoff
	for range failures - 1 {
		if wait >= c.policy.MaxBackoff/2 {
			wait = c.policy.MaxBackoff
			break
		}
		wait *= 2
	}
	spread := float64(wait) * jitter
	return time.Duration(float64(wait) - spread + rand.Float64()*2*spread)
}

type waiting struct {
	name string
	done chan struct{}
}

func await(running []waiting, within time.Duration) []string {
	deadline := time.NewTimer(within)
	defer deadline.Stop()
	var stuck []string
	late := false
	for _, held := range running {
		if late {
			select {
			case <-held.done:
			default:
				stuck = append(stuck, held.name)
			}
			continue
		}
		select {
		case <-held.done:
		case <-deadline.C:
			late = true
			select {
			case <-held.done:
			default:
				stuck = append(stuck, held.name)
			}
		}
	}
	return stuck
}

func bounded(reason string) string {
	if len(reason) <= maxReason {
		return reason
	}
	return reason[:maxReason] + "..."
}
