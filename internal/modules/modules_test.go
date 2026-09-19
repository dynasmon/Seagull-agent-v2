package modules_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/modules"
)

const settle = 2 * time.Second

func TestEveryEnabledModuleCollectsAndADisabledOneNeverDoes(t *testing.T) {
	auth, inventory, fim := collector(t), collector(t), collector(t)
	collection, logs := composed(t, modules.Policy{},
		modules.Module{Name: "auth", Enabled: true, Collect: auth.collect},
		modules.Module{Name: "inventory", Enabled: true, Collect: inventory.collect},
		modules.Module{Name: "fim", Collect: fim.collect})
	stop, stopped := running(t, collection)

	auth.started(t)
	inventory.started(t)
	if fim.calls() != 0 {
		t.Fatalf("a module nobody enabled collected %d times", fim.calls())
	}
	health(t, collection, map[string]modules.State{"auth": modules.Running, "inventory": modules.Running, "fim": modules.Disabled})

	stop()
	if err := stopped(); err != nil {
		t.Fatalf("the collection stopped with %v", err)
	}
	if auth.collecting() || inventory.collecting() {
		t.Fatal("a module was still collecting after the collection stopped")
	}
	if entry, found := logged(t, logs, "module_stopped", "module", "auth"); !found {
		t.Fatalf("the agent did not say that auth stopped: %v", entry)
	}
}

func TestAModuleThatFailsIsStartedAgainWithAGrowingWait(t *testing.T) {
	failing := collector(t)
	collection, logs := composed(t, modules.Policy{Backoff: time.Millisecond, MaxBackoff: 8 * time.Millisecond, Budget: 5},
		modules.Module{Name: "auth", Enabled: true, Collect: failing.collect})
	stop, stopped := running(t, collection)
	defer func() { stop(); _ = stopped() }()

	for range 3 {
		failing.started(t)
		failing.fail(t, errors.New("the journal moved"))
	}
	failing.started(t)

	if held := health(t, collection, map[string]modules.State{"auth": modules.Running}); held["auth"].Restarts != 3 {
		t.Fatalf("the agent started auth again %d times, it failed 3 times", held["auth"].Restarts)
	}
	var waits []time.Duration
	for _, entry := range entries(t, logs, "module_restarting") {
		waited, _ := entry["in"].(float64)
		waits = append(waits, time.Duration(waited))
	}
	if len(waits) != 3 {
		t.Fatalf("the agent waited before %d restarts, it restarted 3 times", len(waits))
	}
	for attempt, waited := range waits {
		want := time.Duration(1<<attempt) * time.Millisecond
		if waited < want*4/5 || waited > want*6/5 {
			t.Errorf("the agent waited %s before restart %d, around %s was due", waited, attempt+1, want)
		}
	}
}

func TestOneModuleFailingForGoodLeavesTheOthersCollecting(t *testing.T) {
	auth, inventory := collector(t), collector(t)
	collection, logs := composed(t, modules.Policy{Backoff: time.Millisecond, Budget: 3},
		modules.Module{Name: "auth", Enabled: true, Collect: auth.collect},
		modules.Module{Name: "inventory", Enabled: true, Collect: inventory.collect})
	stop, stopped := running(t, collection)
	defer func() { stop(); _ = stopped() }()

	auth.started(t)
	for range 3 {
		inventory.started(t)
		inventory.fail(t, errors.New("proc is unreadable"))
	}
	spent, found := logged(t, logs, "module_failed", "module", "inventory")
	if !found || spent["failures"] != float64(3) {
		t.Fatalf("the agent gave up on inventory with %v", spent)
	}
	if calls := inventory.calls(); calls != 3 {
		t.Fatalf("the agent ran inventory %d times, its budget was 3", calls)
	}

	held := health(t, collection, map[string]modules.State{"auth": modules.Running, "inventory": modules.Failed})
	if !strings.Contains(held["inventory"].Reason, "proc is unreadable") {
		t.Errorf("inventory is failed and says %q", held["inventory"].Reason)
	}
	if auth.calls() != 1 || !auth.collecting() {
		t.Fatalf("auth collected %d times and is collecting: %t", auth.calls(), auth.collecting())
	}
}

func TestDisablingAModuleWhileTheAgentRunsReleasesIt(t *testing.T) {
	auth, inventory := collector(t), collector(t)
	collection, logs := composed(t, modules.Policy{},
		modules.Module{Name: "auth", Enabled: true, Collect: auth.collect},
		modules.Module{Name: "inventory", Enabled: true, Collect: inventory.collect})
	stop, stopped := running(t, collection)
	defer func() { stop(); _ = stopped() }()

	auth.started(t)
	inventory.started(t)
	if err := collection.Apply([]string{"auth"}); err != nil {
		t.Fatalf("collect with auth alone: %v", err)
	}
	if inventory.collecting() {
		t.Fatal("a module the agent stopped collecting with was still collecting when it said so")
	}
	health(t, collection, map[string]modules.State{"auth": modules.Running, "inventory": modules.Disabled})
	if _, found := logged(t, logs, "module_stopped", "module", "inventory"); !found {
		t.Fatalf("the agent did not say that inventory stopped:\n%s", logs)
	}
	if auth.calls() != 1 {
		t.Fatalf("auth was started %d times while another module was disabled", auth.calls())
	}

	if err := collection.Apply([]string{"auth", "inventory"}); err != nil {
		t.Fatalf("collect with both again: %v", err)
	}
	inventory.started(t)
	health(t, collection, map[string]modules.State{"auth": modules.Running, "inventory": modules.Running})
}

func TestAModuleTheBuildDoesNotHaveIsRefusedWholeRatherThanHalfApplied(t *testing.T) {
	auth, inventory := collector(t), collector(t)
	collection, _ := composed(t, modules.Policy{},
		modules.Module{Name: "auth", Enabled: true, Collect: auth.collect},
		modules.Module{Name: "inventory", Enabled: true, Collect: inventory.collect})
	stop, stopped := running(t, collection)
	defer func() { stop(); _ = stopped() }()

	auth.started(t)
	inventory.started(t)
	err := collection.Apply([]string{"auth", "netflow"})
	if err == nil || !strings.Contains(err.Error(), "netflow") {
		t.Fatalf("the agent was asked to collect with netflow and answered %v", err)
	}
	health(t, collection, map[string]modules.State{"auth": modules.Running, "inventory": modules.Running})
	if inventory.collecting() != true || auth.calls() != 1 || inventory.calls() != 1 {
		t.Fatal("a refused set of modules changed what the agent collects with")
	}
}

func TestAskingAgainStartsAModuleThatSpentItsBudget(t *testing.T) {
	failing := collector(t)
	collection, _ := composed(t, modules.Policy{Backoff: time.Millisecond, Budget: 2},
		modules.Module{Name: "auth", Enabled: true, Collect: failing.collect})
	stop, stopped := running(t, collection)
	defer func() { stop(); _ = stopped() }()

	for range 2 {
		failing.started(t)
		failing.fail(t, errors.New("the journal moved"))
	}
	held := health(t, collection, map[string]modules.State{"auth": modules.Failed})
	if err := collection.Apply([]string{"auth"}); err != nil {
		t.Fatalf("ask for auth again: %v", err)
	}
	failing.started(t)
	if again := health(t, collection, map[string]modules.State{"auth": modules.Running}); again["auth"].Restarts <= held["auth"].Restarts {
		t.Fatalf("the agent started auth again without counting it: %v", again["auth"])
	}
}

func TestAModuleThatStopsWithoutFailingIsStartedAgain(t *testing.T) {
	quiet := collector(t)
	collection, logs := composed(t, modules.Policy{Backoff: time.Millisecond, Budget: 3},
		modules.Module{Name: "auth", Enabled: true, Collect: quiet.collect})
	stop, stopped := running(t, collection)
	defer func() { stop(); _ = stopped() }()

	quiet.started(t)
	quiet.fail(t, nil)
	quiet.started(t)

	restarting, found := logged(t, logs, "module_restarting", "module", "auth")
	if reason, _ := restarting["error"].(string); !found || !strings.Contains(reason, "stopped before the agent was asked to stop") {
		t.Fatalf("a module that returned before the stop was reported as %v", restarting)
	}
}

func TestTheCollectionNamesAModuleThatDoesNotStop(t *testing.T) {
	stubborn, quick := collector(t), collector(t)
	collection, _ := composed(t, modules.Policy{Stop: 50 * time.Millisecond},
		modules.Module{Name: "fim", Enabled: true, Collect: stubborn.ignoreTheStop},
		modules.Module{Name: "auth", Enabled: true, Collect: quick.collect})
	stop, stopped := running(t, collection)

	stubborn.started(t)
	quick.started(t)
	stop()
	err := stopped()
	if err == nil || !strings.Contains(err.Error(), "fim still running") {
		t.Fatalf("the collection stopped with %v", err)
	}
	if strings.Contains(err.Error(), "auth") {
		t.Errorf("the collection named a module that did stop: %v", err)
	}
	stubborn.fail(t, nil)
}

func TestComposingTheCollectionRefusesAModuleItCannotRun(t *testing.T) {
	working := collector(t)
	cases := map[string]struct {
		logger *slog.Logger
		policy modules.Policy
		held   []modules.Module
		says   string
	}{
		"a module with no name": {
			held: []modules.Module{{Collect: working.collect}},
			says: "module 0 has no name",
		},
		"a module composed twice": {
			held: []modules.Module{{Name: "auth", Collect: working.collect}, {Name: "auth", Collect: working.collect}},
			says: "auth is composed twice",
		},
		"a module with nothing to collect": {
			held: []modules.Module{{Name: "auth"}},
			says: "auth has nothing to collect",
		},
		"a backoff that is not a wait": {
			policy: modules.Policy{Backoff: -time.Second},
			says:   "backoff -1s is not a time to wait",
		},
		"a budget that is not one": {
			policy: modules.Policy{Budget: -1},
			says:   "a budget of -1 restarts is not one",
		},
		"a backoff beyond its maximum": {
			policy: modules.Policy{Backoff: time.Minute, MaxBackoff: time.Second},
			says:   "a backoff of 1m0s is longer than the maximum 1s",
		},
		"no logger": {says: "no logger"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			logger := c.logger
			if name != "no logger" {
				logger = slog.New(slog.NewJSONHandler(&journal{}, nil))
			}
			collection, err := modules.New(logger, c.policy, c.held...)
			if collection != nil || err == nil || !strings.Contains(err.Error(), c.says) {
				t.Fatalf("composing %s returned %v, %v", name, collection, err)
			}
		})
	}
}

func TestTheCollectionRunsOnce(t *testing.T) {
	collection, _ := composed(t, modules.Policy{})
	stopped, stop := context.WithCancel(t.Context())
	stop()
	if err := collection.Run(stopped); err != nil {
		t.Fatalf("the collection stopped with %v", err)
	}
	if err := collection.Run(t.Context()); err == nil || !strings.Contains(err.Error(), "runs once") {
		t.Fatalf("the collection ran twice: %v", err)
	}
}

func TestWhatAModuleReportsIsBoundedBeforeItIsKept(t *testing.T) {
	noisy := collector(t)
	collection, _ := composed(t, modules.Policy{Backoff: time.Millisecond, Budget: 1},
		modules.Module{Name: "auth", Enabled: true, Collect: noisy.collect})
	stop, stopped := running(t, collection)
	defer func() { stop(); _ = stopped() }()

	noisy.started(t)
	noisy.fail(t, errors.New(strings.Repeat("unreadable ", 1000)))
	held := health(t, collection, map[string]modules.State{"auth": modules.Failed})
	if len(held["auth"].Reason) > 300 {
		t.Fatalf("the agent kept %d bytes of what a module reported", len(held["auth"].Reason))
	}
}

func composed(t *testing.T, policy modules.Policy, held ...modules.Module) (*modules.Collection, *journal) {
	t.Helper()
	logs := &journal{}
	collection, err := modules.New(slog.New(slog.NewJSONHandler(logs, nil)), policy, held...)
	if err != nil {
		t.Fatalf("compose the collection: %v", err)
	}
	return collection, logs
}

func running(t *testing.T, collection *modules.Collection) (func(), func() error) {
	t.Helper()
	ctx, stop := context.WithCancel(t.Context())
	stopped := make(chan error, 1)
	go func() { stopped <- collection.Run(ctx) }()
	t.Cleanup(stop)
	return stop, func() error {
		select {
		case err := <-stopped:
			return err
		case <-time.After(settle):
			t.Fatal("the collection did not stop")
			return nil
		}
	}
}

func health(t *testing.T, collection *modules.Collection, want map[string]modules.State) map[string]modules.Health {
	t.Helper()
	deadline := time.Now().Add(settle)
	for {
		held := map[string]modules.Health{}
		agreed := true
		for _, module := range collection.Health() {
			held[module.Name] = module
			if want[module.Name] != module.State {
				agreed = false
			}
		}
		if agreed && len(held) == len(want) {
			return held
		}
		if time.Now().After(deadline) {
			t.Fatalf("the collection reports %v, want %v", held, want)
		}
		time.Sleep(time.Millisecond)
	}
}

// A module the test drives: it says when it is collecting and returns what the
// test hands it.
type driven struct {
	mu      sync.Mutex
	held    int
	inside  bool
	entered chan struct{}
	returns chan error
}

func collector(t *testing.T) *driven {
	t.Helper()
	return &driven{entered: make(chan struct{}, 64), returns: make(chan error)}
}

func (d *driven) collect(ctx context.Context) error {
	d.enter()
	defer d.leave()
	select {
	case err := <-d.returns:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (d *driven) ignoreTheStop(context.Context) error {
	d.enter()
	defer d.leave()
	return <-d.returns
}

func (d *driven) enter() {
	d.mu.Lock()
	d.held, d.inside = d.held+1, true
	d.mu.Unlock()
	d.entered <- struct{}{}
}

func (d *driven) leave() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.inside = false
}

func (d *driven) calls() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.held
}

func (d *driven) collecting() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.inside
}

func (d *driven) started(t *testing.T) {
	t.Helper()
	select {
	case <-d.entered:
	case <-time.After(settle):
		t.Fatal("the module was not started")
	}
}

func (d *driven) fail(t *testing.T, err error) {
	t.Helper()
	select {
	case d.returns <- err:
	case <-time.After(settle):
		t.Fatalf("the module was not collecting to return %v", err)
	}
}

type journal struct {
	mu   sync.Mutex
	held bytes.Buffer
}

func (j *journal) Write(line []byte) (int, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.held.Write(line)
}

func (j *journal) String() string {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.held.String()
}

func entries(t *testing.T, logs *journal, message string) []map[string]any {
	t.Helper()
	var found []map[string]any
	for line := range strings.Lines(logs.String()) {
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

func logged(t *testing.T, logs *journal, message, name, value string) (map[string]any, bool) {
	t.Helper()
	deadline := time.Now().Add(settle)
	for {
		for _, entry := range entries(t, logs, message) {
			if entry[name] == value {
				return entry, true
			}
		}
		if time.Now().After(deadline) {
			return nil, false
		}
		time.Sleep(time.Millisecond)
	}
}
