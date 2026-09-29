// Package link keeps the agent's connection to one listener of the platform:
// whether the listener answers, since when it has not and why, and when it is
// tried again. Every request to the listener takes a turn on its link first.
// While the listener answers, every request has its turn at once; once it
// fails, one request at a time tries it again, as the policy allows, and the
// first answer lets every request through again.
package link

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/secrets"
)

type Options struct {
	Listener string
	Policy   Policy
	Logger   *slog.Logger
	Recovery func(error) string
}

type Link struct {
	options Options

	mu       sync.Mutex
	epoch    uint64
	failing  bool
	probing  bool
	failures int
	class    Class
	reason   string
	since    time.Time
	until    time.Time
	answered time.Time
	changed  chan struct{}
}

type State struct {
	Listener string
	Answered time.Time
	Failing  time.Time
	Failure  Class
	Reason   string
	Attempts int
	Next     time.Time
}

type Turn struct {
	link  *Link
	epoch uint64
	probe bool
	done  bool
}

func New(options Options) (*Link, error) {
	var problems []error
	if options.Listener == "" || options.Logger == nil {
		problems = append(problems, errors.New("a link names the listener it reaches and has a logger"))
	}
	policy, err := options.Policy.Settled()
	if err != nil {
		problems = append(problems, err)
	}
	if len(problems) > 0 {
		return nil, fmt.Errorf("compose the link: %w", errors.Join(problems...))
	}
	options.Policy = policy
	if options.Recovery == nil {
		options.Recovery = func(error) string { return "" }
	}
	return &Link{options: options}, nil
}

// Take waits for the turn of a request to the listener: at once while the
// listener answers, and while it does not, until the next attempt is due and
// no other request holds the turn to make it. Whoever takes a turn settles it
// once, with what the request learnt of the listener.
func (l *Link) Take(ctx context.Context) (*Turn, error) {
	for {
		l.mu.Lock()
		if !l.failing || (!l.probing && !time.Now().Before(l.until)) {
			turn := &Turn{link: l, epoch: l.epoch, probe: l.failing}
			l.probing = l.failing
			l.mu.Unlock()
			return turn, nil
		}
		changed, wait := l.signal(), time.Until(l.until)
		if l.probing {
			wait = 0
		}
		l.mu.Unlock()
		if err := pause(ctx, changed, wait); err != nil {
			return nil, err
		}
	}
}

func (l *Link) State() State {
	l.mu.Lock()
	defer l.mu.Unlock()
	state := State{Listener: l.options.Listener, Answered: l.answered}
	if l.failing {
		state.Failing, state.Failure, state.Reason, state.Attempts, state.Next = l.since, l.class, l.reason, l.failures, l.until
	}
	return state
}

// Answered settles a turn whose request the listener answered, whatever it
// answered about what the request carried: the listener is reached, so every
// request waiting on it has its turn again.
func (t *Turn) Answered() {
	l := t.link
	l.mu.Lock()
	if t.done {
		l.mu.Unlock()
		return
	}
	t.done = true
	now := time.Now()
	l.answered = now
	if !l.failing {
		l.mu.Unlock()
		return
	}
	restored := []any{slog.String("listener", l.options.Listener), slog.String("failure", l.class.String()),
		slog.Int("attempts", l.failures), slog.Duration("failing", now.Sub(l.since))}
	l.failing, l.probing, l.failures, l.class, l.reason, l.since, l.until = false, false, 0, 0, "", time.Time{}, time.Time{}
	l.epoch++
	l.announce()
	l.mu.Unlock()
	l.options.Logger.Info("connection_restored", restored...)
}

// Failed settles a turn whose request found the listener failing, and returns
// when the next attempt is due. A request that took its turn before the link
// last changed tells it nothing new: an outage several requests ran into is
// counted once, and an answer given since stands.
func (t *Turn) Failed(class Class, asked time.Duration, reason error) time.Time {
	l := t.link
	l.mu.Lock()
	now := time.Now()
	if t.done || t.epoch != l.epoch {
		t.done = true
		next := now
		if l.failing {
			next = l.until
		}
		l.mu.Unlock()
		return next
	}
	t.done = true
	said := ""
	if reason != nil {
		said = secrets.Bounded(reason.Error())
	}
	changed := !l.failing || l.class != class
	if !l.failing {
		l.since = now
	}
	l.failures++
	l.failing, l.probing, l.class, l.reason = true, false, class, said
	l.until = now.Add(l.options.Policy.Wait(l.failures, class.Lasting(), asked))
	l.epoch++
	l.announce()
	failing := []any{slog.String("listener", l.options.Listener), slog.String("failure", class.String()), slog.String("error", said),
		slog.Time("failing_since", l.since), slog.Int("attempt", l.failures), slog.Time("next_attempt", l.until)}
	next := l.until
	l.mu.Unlock()
	if !changed {
		return next
	}
	if class.Lasting() {
		l.options.Logger.Error("connection_failing", append(failing, slog.String("recovery", l.options.Recovery(reason)))...)
		return next
	}
	l.options.Logger.Warn("connection_failing", append(failing, slog.String("recovery", "none: the agent tries the listener again, one request at a time, until it answers"))...)
	return next
}

func (t *Turn) Abandoned() {
	l := t.link
	l.mu.Lock()
	defer l.mu.Unlock()
	if t.done {
		return
	}
	t.done = true
	if t.probe && t.epoch == l.epoch {
		l.probing = false
		l.announce()
	}
}

func (l *Link) signal() <-chan struct{} {
	if l.changed == nil {
		l.changed = make(chan struct{})
	}
	return l.changed
}

func (l *Link) announce() {
	if l.changed != nil {
		close(l.changed)
		l.changed = nil
	}
}

func pause(ctx context.Context, changed <-chan struct{}, wait time.Duration) error {
	var due <-chan time.Time
	if wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		due = timer.C
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-changed:
	case <-due:
	}
	return nil
}
