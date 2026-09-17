package runtime

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"
)

type Policy int

const (
	Essential Policy = iota + 1
	Optional
)

func (p Policy) String() string {
	switch p {
	case Essential:
		return "essential"
	case Optional:
		return "optional"
	default:
		return fmt.Sprintf("policy(%d)", int(p))
	}
}

// Run owns every goroutine, timer and descriptor the component starts, and
// returns only once all of them have stopped: after ctx is cancelled, or
// earlier when the component fails.
type Component struct {
	Name   string
	Policy Policy
	Run    func(ctx context.Context) error
}

func (c Component) attributes() []any {
	return []any{slog.String("component", c.Name), slog.String("policy", c.Policy.String())}
}

type Runtime struct {
	logger          *slog.Logger
	shutdownTimeout time.Duration
	components      []Component
}

var errStoppedEarly = errors.New("stopped before the agent was asked to stop")

func New(logger *slog.Logger, shutdownTimeout time.Duration, components ...Component) (*Runtime, error) {
	var problems []error
	if logger == nil {
		problems = append(problems, errors.New("no logger"))
	}
	if shutdownTimeout <= 0 {
		problems = append(problems, fmt.Errorf("shutdown timeout %s is not positive", shutdownTimeout))
	}
	composed := make(map[string]bool, len(components))
	for i, component := range components {
		label := component.Name
		switch {
		case label == "":
			label = fmt.Sprintf("component %d", i)
			problems = append(problems, fmt.Errorf("%s has no name", label))
		case composed[label]:
			problems = append(problems, fmt.Errorf("%s is composed twice", label))
		}
		composed[label] = true
		if component.Policy != Essential && component.Policy != Optional {
			problems = append(problems, fmt.Errorf("%s declares no failure policy", label))
		}
		if component.Run == nil {
			problems = append(problems, fmt.Errorf("%s has nothing to run", label))
		}
	}
	if len(problems) > 0 {
		return nil, fmt.Errorf("compose the runtime: %w", errors.Join(problems...))
	}
	return &Runtime{logger: logger, shutdownTimeout: shutdownTimeout, components: slices.Clone(components)}, nil
}

type exit struct {
	component int
	err       error
}

func (r *Runtime) Run(ctx context.Context) error {
	work, cancel := context.WithCancel(ctx)
	defer cancel()

	exits := make(chan exit, len(r.components))
	running := make([]bool, len(r.components))
	pending := 0
	// A stop that arrives before the agent runs starts no component, and is
	// still reported: every stop names the reason it happened.
	if ctx.Err() == nil {
		for i, component := range r.components {
			r.logger.Info("component_started", component.attributes()...)
			running[i] = true
			pending++
			go func() { exits <- exit{component: i, err: component.Run(work)} }()
		}
	}

	var failures []error
	record := func(stopped exit, stopping bool) error {
		pending--
		running[stopped.component] = false
		failure := r.settle(r.components[stopped.component], stopped.err, stopping)
		if failure != nil {
			failures = append(failures, failure)
		}
		return failure
	}

	var reason string
	for reason == "" {
		select {
		case <-ctx.Done():
			reason = context.Cause(ctx).Error()
		case stopped := <-exits:
			stopping := ctx.Err() != nil
			if failure := record(stopped, stopping); failure != nil && !stopping {
				reason = failure.Error()
			}
		}
	}

	cancel()
	began := time.Now()
	r.logger.Info("shutdown_started", slog.String("reason", reason), slog.Duration("timeout", r.shutdownTimeout))
	deadline := time.NewTimer(r.shutdownTimeout)
	defer deadline.Stop()
	for pending > 0 {
		select {
		case stopped := <-exits:
			record(stopped, true)
		case <-deadline.C:
			var stuck []string
			for i, component := range r.components {
				if running[i] {
					stuck = append(stuck, component.Name)
				}
			}
			r.logger.Error("shutdown_deadline_exceeded", slog.Duration("timeout", r.shutdownTimeout), slog.Any("running", stuck))
			failures = append(failures, fmt.Errorf("%s still running %s after the stop", strings.Join(stuck, ", "), r.shutdownTimeout))
			return errors.Join(failures...)
		}
	}
	r.logger.Info("shutdown_completed", slog.Duration("duration", time.Since(began)))
	return errors.Join(failures...)
}

// An essential component stops the agent whenever it returns before the stop,
// even without an error: the agent cannot do its work without it. An optional
// one that fails is reported and the agent carries on without it.
func (r *Runtime) settle(component Component, err error, stopping bool) error {
	attributes := component.attributes()
	switch {
	case stopping && (err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)):
		r.logger.Info("component_stopped", attributes...)
		return nil
	case err == nil && component.Policy == Optional:
		r.logger.Warn("component_stopped", attributes...)
		return nil
	case err == nil:
		err = errStoppedEarly
	}
	r.logger.Error("component_failed", append(attributes, slog.Any("error", err))...)
	if component.Policy == Optional {
		return nil
	}
	return fmt.Errorf("%s: %w", component.Name, err)
}
