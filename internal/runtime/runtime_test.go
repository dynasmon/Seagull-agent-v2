package runtime_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/runtime"
)

const shutdownTimeout = 10 * time.Second

type journal struct {
	mu    sync.Mutex
	lines bytes.Buffer
}

func (j *journal) Write(line []byte) (int, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.lines.Write(line)
}

func (j *journal) entries(t *testing.T, message string) []map[string]any {
	t.Helper()
	j.mu.Lock()
	defer j.mu.Unlock()
	var found []map[string]any
	for line := range strings.Lines(j.lines.String()) {
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("decode the log line %q: %v", line, err)
		}
		if entry["msg"] == message {
			found = append(found, entry)
		}
	}
	return found
}

type probe struct {
	started, stopped atomic.Bool
}

func (p *probe) run(ctx context.Context) error {
	p.started.Store(true)
	<-ctx.Done()
	p.stopped.Store(true)
	return ctx.Err()
}

func compose(t *testing.T, logs *journal, components ...runtime.Component) *runtime.Runtime {
	t.Helper()
	agent, err := runtime.New(slog.New(slog.NewJSONHandler(logs, nil)), shutdownTimeout, components...)
	if err != nil {
		t.Fatalf("compose the runtime: %v", err)
	}
	return agent
}

func start(ctx context.Context, agent *runtime.Runtime) <-chan error {
	result := make(chan error, 1)
	go func() { result <- agent.Run(ctx) }()
	return result
}

func stillRunning(t *testing.T, result <-chan error) {
	t.Helper()
	synctest.Wait()
	select {
	case err := <-result:
		t.Fatalf("the agent stopped on its own: %v", err)
	default:
	}
}

func TestAnIncompleteCompositionIsRefused(t *testing.T) {
	run := func(context.Context) error { return nil }
	logger := slog.New(slog.DiscardHandler)
	cases := []struct {
		name       string
		logger     *slog.Logger
		timeout    time.Duration
		components []runtime.Component
		problem    string
	}{
		{
			name:    "no logger",
			timeout: time.Second,
			problem: "no logger",
		},
		{
			name:    "no shutdown deadline",
			logger:  logger,
			problem: "shutdown timeout 0s is not positive",
		},
		{
			name:       "a component without a name",
			logger:     logger,
			timeout:    time.Second,
			components: []runtime.Component{{Policy: runtime.Essential, Run: run}},
			problem:    "component 0 has no name",
		},
		{
			name:    "a component composed twice",
			logger:  logger,
			timeout: time.Second,
			components: []runtime.Component{
				{Name: "delivery", Policy: runtime.Essential, Run: run},
				{Name: "delivery", Policy: runtime.Optional, Run: run},
			},
			problem: "delivery is composed twice",
		},
		{
			name:       "a component without a failure policy",
			logger:     logger,
			timeout:    time.Second,
			components: []runtime.Component{{Name: "delivery", Run: run}},
			problem:    "delivery declares no failure policy",
		},
		{
			name:       "a component with nothing to run",
			logger:     logger,
			timeout:    time.Second,
			components: []runtime.Component{{Name: "delivery", Policy: runtime.Essential}},
			problem:    "delivery has nothing to run",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := runtime.New(c.logger, c.timeout, c.components...)
			if err == nil {
				t.Fatalf("the runtime accepted the composition, want a refusal naming %q", c.problem)
			}
			if !strings.Contains(err.Error(), c.problem) {
				t.Fatalf("the refusal %q does not name %q", err, c.problem)
			}
		})
	}
}

func TestComponentsWorkOnlyWhileTheAgentRuns(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		inventory := &probe{}
		agent := compose(t, &journal{}, runtime.Component{Name: "inventory", Policy: runtime.Optional, Run: inventory.run})
		synctest.Wait()
		if inventory.started.Load() {
			t.Fatal("composing the agent started a component")
		}

		ctx, cancel := context.WithCancel(t.Context())
		result := start(ctx, agent)
		stillRunning(t, result)
		if !inventory.started.Load() {
			t.Fatal("running the agent did not start its component")
		}

		cancel()
		if err := <-result; err != nil {
			t.Fatalf("a requested stop failed: %v", err)
		}
		if !inventory.stopped.Load() {
			t.Fatal("the agent returned before its component stopped")
		}
	})
}

func TestTheAgentRunsUntilItIsAskedToStop(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var logs journal
		delivery, inventory := &probe{}, &probe{}
		agent := compose(t, &logs,
			runtime.Component{Name: "delivery", Policy: runtime.Essential, Run: delivery.run},
			runtime.Component{Name: "inventory", Policy: runtime.Optional, Run: inventory.run},
		)
		ctx, stop := context.WithCancelCause(t.Context())
		result := start(ctx, agent)
		time.Sleep(24 * time.Hour)
		stillRunning(t, result)

		stop(errors.New("terminated signal received"))
		if err := <-result; err != nil {
			t.Fatalf("a requested stop failed: %v", err)
		}
		if !delivery.stopped.Load() || !inventory.stopped.Load() {
			t.Fatal("the agent returned before its components stopped")
		}
		shutdown := logs.entries(t, "shutdown_started")
		if len(shutdown) != 1 || shutdown[0]["reason"] != "terminated signal received" {
			t.Fatalf("the stop was logged as %v, want the reason it was requested", shutdown)
		}
	})
}

func TestWithoutComponentsTheAgentWaitsToBeStopped(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		result := start(ctx, compose(t, &journal{}))
		time.Sleep(24 * time.Hour)
		stillRunning(t, result)

		cancel()
		if err := <-result; err != nil {
			t.Fatalf("a requested stop failed: %v", err)
		}
	})
}

func TestAnOptionalFailureLeavesDeliveryRunning(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var logs journal
		delivery := &probe{}
		agent := compose(t, &logs,
			runtime.Component{Name: "delivery", Policy: runtime.Essential, Run: delivery.run},
			runtime.Component{Name: "inventory", Policy: runtime.Optional, Run: func(context.Context) error {
				time.Sleep(time.Minute)
				return errors.New("package database unreadable")
			}},
		)
		ctx, cancel := context.WithCancel(t.Context())
		result := start(ctx, agent)
		time.Sleep(24 * time.Hour)
		stillRunning(t, result)
		if delivery.stopped.Load() {
			t.Fatal("an optional failure stopped delivery")
		}
		failed := logs.entries(t, "component_failed")
		if len(failed) != 1 || failed[0]["component"] != "inventory" || failed[0]["policy"] != "optional" ||
			failed[0]["error"] != "package database unreadable" {
			t.Fatalf("the failure was reported as %v", failed)
		}

		cancel()
		if err := <-result; err != nil {
			t.Fatalf("an optional failure made the requested stop fail: %v", err)
		}
	})
}

func TestAnEssentialComponentThatStopsStopsTheAgent(t *testing.T) {
	errSpool := errors.New("spool unavailable")
	cases := []struct {
		name   string
		err    error
		reason string
	}{
		{name: "with an error", err: errSpool, reason: "delivery: spool unavailable"},
		{name: "without an error", reason: "delivery: stopped before the agent was asked to stop"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var logs journal
				inventory := &probe{}
				agent := compose(t, &logs,
					runtime.Component{Name: "delivery", Policy: runtime.Essential, Run: func(context.Context) error {
						time.Sleep(time.Minute)
						return c.err
					}},
					runtime.Component{Name: "inventory", Policy: runtime.Optional, Run: inventory.run},
				)
				began := time.Now()
				err := agent.Run(t.Context())
				if err == nil || err.Error() != c.reason {
					t.Fatalf("the agent stopped with %v, want %q", err, c.reason)
				}
				if c.err != nil && !errors.Is(err, c.err) {
					t.Fatalf("%v does not wrap %v", err, c.err)
				}
				if elapsed := time.Since(began); elapsed != time.Minute {
					t.Fatalf("the agent stopped %s after it started, want it to stop as soon as delivery did", elapsed)
				}
				if !inventory.stopped.Load() {
					t.Fatal("the agent returned before stopping its other components")
				}
				shutdown := logs.entries(t, "shutdown_started")
				if len(shutdown) != 1 || shutdown[0]["reason"] != c.reason {
					t.Fatalf("the stop was logged as %v, want %q as its reason", shutdown, c.reason)
				}
			})
		})
	}
}

func TestStoppingWaitsForWorkInFlight(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var flushed atomic.Bool
		agent := compose(t, &journal{}, runtime.Component{Name: "delivery", Policy: runtime.Essential, Run: func(ctx context.Context) error {
			<-ctx.Done()
			time.Sleep(3 * time.Second)
			flushed.Store(true)
			return ctx.Err()
		}})
		ctx, cancel := context.WithCancel(t.Context())
		result := start(ctx, agent)
		synctest.Wait()

		cancel()
		stopped := time.Now()
		if err := <-result; err != nil {
			t.Fatalf("a stop within the deadline failed: %v", err)
		}
		if !flushed.Load() {
			t.Fatal("the agent returned while delivery was still flushing")
		}
		if elapsed := time.Since(stopped); elapsed != 3*time.Second {
			t.Fatalf("the stop took %s, want the 3s delivery needed", elapsed)
		}
	})
}

func TestStoppingGivesUpAtTheDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var logs journal
		release := make(chan struct{})
		agent := compose(t, &logs,
			runtime.Component{Name: "delivery", Policy: runtime.Essential, Run: (&probe{}).run},
			runtime.Component{Name: "fim", Policy: runtime.Optional, Run: func(context.Context) error {
				<-release
				return nil
			}},
		)
		ctx, cancel := context.WithCancel(t.Context())
		result := start(ctx, agent)
		synctest.Wait()

		cancel()
		stopped := time.Now()
		err := <-result
		if elapsed := time.Since(stopped); elapsed != shutdownTimeout {
			t.Fatalf("the stop gave up after %s, want the %s deadline", elapsed, shutdownTimeout)
		}
		if err == nil || err.Error() != "fim still running 10s after the stop" {
			t.Fatalf("the stop reported %v, want the component that overran the deadline", err)
		}
		overrun := logs.entries(t, "shutdown_deadline_exceeded")
		if len(overrun) != 1 || fmt.Sprint(overrun[0]["running"]) != "[fim]" {
			t.Fatalf("the overrun was logged as %v, want fim alone", overrun)
		}
		close(release)
	})
}

func TestAFailureWhileStoppingIsReported(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var logs journal
		errAcknowledgements := errors.New("acknowledgements not persisted")
		agent := compose(t, &logs,
			runtime.Component{Name: "delivery", Policy: runtime.Essential, Run: func(ctx context.Context) error {
				<-ctx.Done()
				return errAcknowledgements
			}},
			runtime.Component{Name: "inventory", Policy: runtime.Optional, Run: func(ctx context.Context) error {
				<-ctx.Done()
				return errors.New("checkpoint not written")
			}},
		)
		ctx, cancel := context.WithCancel(t.Context())
		result := start(ctx, agent)
		synctest.Wait()

		cancel()
		err := <-result
		if !errors.Is(err, errAcknowledgements) || err.Error() != "delivery: acknowledgements not persisted" {
			t.Fatalf("the stop reported %v, want the essential failure alone", err)
		}
		var failed []string
		for _, entry := range logs.entries(t, "component_failed") {
			failed = append(failed, fmt.Sprint(entry["component"]))
		}
		if slices.Sort(failed); !slices.Equal(failed, []string{"delivery", "inventory"}) {
			t.Fatalf("failures logged for %v, want both components", failed)
		}
	})
}

func TestAStopRequestedBeforeTheAgentRunsStartsNothing(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		delivery := &probe{}
		agent := compose(t, &journal{}, runtime.Component{Name: "delivery", Policy: runtime.Essential, Run: delivery.run})
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if err := agent.Run(ctx); err != nil {
			t.Fatalf("a stop requested before the agent ran failed: %v", err)
		}
		synctest.Wait()
		if delivery.started.Load() {
			t.Fatal("a component started although the agent had already been stopped")
		}
	})
}

const panicking = "SEAGULL_RUNTIME_TEST_PANIC"

func TestAPanicTerminatesTheProcess(t *testing.T) {
	if os.Getenv(panicking) != "" {
		runAPanickingComponent(t)
		return
	}
	child := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^"+t.Name()+"$")
	child.Env = append(os.Environ(), panicking+"=1")
	output, err := child.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 2 {
		t.Fatalf("the process ended with %v, want the exit status 2 of an unrecovered panic:\n%s", err, output)
	}
	if !bytes.Contains(output, []byte("panic: collector state is inconsistent")) {
		t.Fatalf("the process did not report the panic:\n%s", output)
	}
	for _, handling := range []string{"component_failed", "shutdown_started"} {
		if bytes.Contains(output, []byte(handling)) {
			t.Errorf("the runtime handled the panic as an ordinary failure (%s):\n%s", handling, output)
		}
	}
}

func runAPanickingComponent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	agent, err := runtime.New(slog.New(slog.NewJSONHandler(os.Stderr, nil)), time.Second,
		runtime.Component{Name: "delivery", Policy: runtime.Essential, Run: (&probe{}).run},
		runtime.Component{Name: "collector", Policy: runtime.Optional, Run: func(context.Context) error {
			panic("collector state is inconsistent")
		}},
	)
	if err != nil {
		t.Fatalf("compose the runtime: %v", err)
	}
	t.Errorf("the runtime outlived a panic and stopped with %v", agent.Run(ctx))
}
