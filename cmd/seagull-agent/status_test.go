package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-agent-v2/internal/config"
	"github.com/dynasmon/Seagull-agent-v2/internal/governor"
	"github.com/dynasmon/Seagull-agent-v2/internal/modules"
	"github.com/dynasmon/Seagull-agent-v2/internal/modules/authentication"
	"github.com/dynasmon/Seagull-agent-v2/internal/modules/inventory"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/accounts"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/dpkg"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/interfaces"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/journal"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/machine"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/processes"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/services"
	"github.com/dynasmon/Seagull-agent-v2/internal/spool"
	"github.com/dynasmon/Seagull-agent-v2/internal/status"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	ingestv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/ingest/v1"
)

func TestTheAgentSaysHowItIsDoingBeforeItRunsWhileItRunsAndOnceItStops(t *testing.T) {
	state := stateDirectory(t)
	path := configured(t, state, nil)
	code, said, told := asked(t, path)
	if code != 1 || said != "" || !strings.Contains(told, status.ErrUnwritten.Error()) || !strings.Contains(told, "start the agent: it writes its status as it starts") {
		t.Fatalf("before the agent ran, the status command exited %d:\n%s%s", code, said, told)
	}

	entries, stop := running(t, path)
	await(t, buffered(entries), "agent_starting")
	held := written(t, state)
	code, said, _ = asked(t, path)
	if code != 1 {
		t.Fatalf("an agent that is not enrolled is reported with exit code %d:\n%s", code, said)
	}
	for _, line := range []string{
		"the agent is degraded: its status was written ",
		fmt.Sprintf("an installation that is not enrolled, installation %s, process %d started ", held.Agent.InstallationID, os.Getpid()),
		"configuration: running since ",
		"collection: disabled: no module is enabled",
		"module authentication: disabled since ",
		"spool: running",
		"delivery: degraded: the installation is not enrolled, so nothing it admits is delivered",
		"  what to do: enroll the installation first",
		"credential: disabled: the installation is not enrolled",
		"resources: running",
		"events: nothing waiting; nothing delivered since the agent started",
		"inventory: nothing waiting; nothing delivered since the agent started",
		"resources: ",
	} {
		if !strings.Contains(said, "\n"+line) && !strings.HasPrefix(said, line) {
			t.Errorf("the status does not say %q:\n%s", line, said)
		}
	}

	if code, _ := stop(); code != 0 {
		t.Fatalf("the agent exited with %d", code)
	}
	code, said, _ = asked(t, path)
	if code != 1 || !strings.HasPrefix(said, "the agent stopped: its status was written ") || !strings.Contains(said, ": the agent was asked to stop\n") {
		t.Fatalf("once the agent stopped, the status command exited %d:\n%s", code, said)
	}
}

func TestAnEnrolledAgentSaysWhatHoldsItsDeliveryBackAndWhatToDo(t *testing.T) {
	state := stateDirectory(t)
	path := configured(t, state, nil)
	signing := listening(t, trustBundle(path))
	var refusing atomic.Bool
	var acknowledged atomic.Int32
	refusing.Store(true)
	ingest := signing.serving(t, &served{}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var batch ingestv1.EventBatch
		if proto.Unmarshal(body, &batch) != nil {
			http.Error(w, "not a batch", http.StatusBadRequest)
			return
		}
		answer := proto.Message(&ingestv1.BatchAck{Accepted: true, Durable: true, Received: uint32(len(batch.GetEvents()))})
		status := http.StatusOK
		if refusing.Load() {
			answer, status = &ingestv1.Rejection{Code: "agent_not_admitted", Detail: "the platform no longer admits telemetry from this agent", EventIndex: -1}, http.StatusForbidden
		} else {
			acknowledged.Add(int32(len(batch.GetEvents())))
		}
		encoded, _ := proto.Marshal(answer)
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(status)
		w.Write(encoded)
	}))
	rewrite(t, path, state, map[string]string{"server": servers(ingest.URL, signing.listen(t).URL, trustBundle(path))})
	enrollWith(t, path, signing)
	held, release := spoolIn(t, state)
	admitted := time.Now()
	for i := range 3 {
		id := fmt.Sprintf("event-%d", i)
		payload, err := proto.Marshal(&eventv1.Event{EventId: id, SchemaVersion: 1})
		if err == nil {
			_, err = held.Admit(spool.Events, spool.Record{ID: id, Payload: payload})
		}
		if err != nil {
			t.Fatalf("admit %s: %v", id, err)
		}
	}
	release()

	entries, stop := running(t, path)
	await(t, buffered(entries), "delivery_failed")
	stop()
	kept := written(t, state)
	code, said, _ := asked(t, path)
	if code != 1 {
		t.Fatalf("a stopped agent is reported with exit code %d", code)
	}
	for _, line := range []string{
		"agent web-01, installation ",
		"delivery: degraded since ",
		": the platform refuses this agent, unadmitted: the platform no longer admits telemetry from this agent",
		"  what to do: the platform no longer admits this agent: an operator admits it again",
		"events: 3 records waiting in ",
		"; nothing delivered since the agent started",
		"ingest listener: failing since ",
		", authorization, 1 attempt; next attempt ",
		"credential: agent web-01, generation 1, serial ",
	} {
		if !strings.Contains(said, line) {
			t.Errorf("the status does not say %q:\n%s", line, said)
		}
	}
	if oldest := kept.Streams[0].Oldest; oldest.Before(admitted.Add(-time.Second)) || oldest.After(time.Now()) {
		t.Errorf("the oldest record waiting was admitted at %s, and the test admitted it at %s", oldest, admitted)
	}

	refusing.Store(false)
	entries, stop = running(t, path)
	await(t, buffered(entries), "agent_starting")
	for written(t, state).State == status.Stopped {
		time.Sleep(10 * time.Millisecond)
	}
	code, said, _ = asked(t, path)
	if code != 0 || !strings.HasPrefix(said, "the agent is running: ") {
		t.Fatalf("an agent whose platform takes what it delivers is reported with exit code %d:\n%s", code, said)
	}
	deadline := time.Now().Add(10 * time.Second)
	for acknowledged.Load() < 3 {
		if time.Now().After(deadline) {
			t.Fatalf("the platform acknowledged %d of 3 events within 10s", acknowledged.Load())
		}
		time.Sleep(10 * time.Millisecond)
	}
	stop()
	if code, said, _ = asked(t, path); !strings.Contains(said, "delivery: running\n") || !strings.Contains(said, "events: nothing waiting; last delivered ") {
		t.Fatalf("once it delivered, the status command exited %d:\n%s", code, said)
	}
}

func TestTheStatusHoldsNothingThatAuthenticatesTheAgent(t *testing.T) {
	state := stateDirectory(t)
	path := configured(t, state, nil)
	held := enroll(t, path)
	serveStopped(t, path)
	content, err := os.ReadFile(filepath.Join(state, statusDirectory, "status.json"))
	if err != nil {
		t.Fatalf("read the status: %v", err)
	}
	_, said, told := asked(t, path)
	written := string(content) + said + told
	if exposesKeys(t, written, state) || strings.Contains(written, "PRIVATE KEY") || strings.Contains(written, "BEGIN CERTIFICATE") {
		t.Fatalf("the status holds key or certificate material:\n%s", written)
	}
	certificate, err := os.ReadFile(held.certificate)
	if err != nil {
		t.Fatalf("read the certificate: %v", err)
	}
	for line := range strings.Lines(string(certificate)) {
		if line = strings.TrimSpace(line); len(line) > 16 && !strings.HasPrefix(line, "-----") && strings.Contains(written, line) {
			t.Fatalf("the status holds the certificate the agent presents:\n%s", written)
		}
	}
	if strings.Contains(written, base64.StdEncoding.EncodeToString(content[:0])+"MII") {
		t.Fatalf("the status holds encoded certificate material:\n%s", written)
	}
	described, err := os.Stat(filepath.Join(state, statusDirectory, "status.json"))
	if err != nil || described.Mode().Perm() != 0o600 {
		t.Fatalf("the status is kept as %v: %v", described, err)
	}
}

func TestARefusedReloadSaysTheAgentRunsOnTheConfigurationItApplied(t *testing.T) {
	state := stateDirectory(t)
	path := configured(t, state, nil)
	started := loaded(t, path)
	applied := time.Now().Add(-time.Minute)
	held := configuration{
		logger:  slog.New(slog.DiscardHandler),
		path:    path,
		active:  config.Activate(started),
		level:   new(slog.LevelVar),
		applied: applied,
	}
	if observed := held.observed(); observed.State != status.Running || !observed.Since.Equal(applied.UTC()) {
		t.Fatalf("before any reload the configuration stands at %+v", observed)
	}
	rewrite(t, path, state, map[string]string{"logging": `{"level": "silent"}`})
	reload(t, &held)
	refused := held.observed()
	if refused.State != status.Degraded || !strings.Contains(string(refused.Reason), "refused what "+path+" holds now") ||
		!strings.Contains(string(refused.Reason), "logging.level") || !strings.Contains(string(refused.Recovery), "config check") {
		t.Fatalf("after a refused reload the configuration stands at %+v", refused)
	}
	rewrite(t, path, state, nil)
	reload(t, &held)
	if observed := held.observed(); observed.State != status.Running || !observed.Since.After(applied) {
		t.Fatalf("after a reload it applied, the configuration stands at %+v", observed)
	}
}

func TestASpoolThatHoldsAllItsBudgetAllowsSaysItLeavesAGap(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "spool")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatalf("create %s: %v", directory, err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatalf("open %s: %v", directory, err)
	}
	t.Cleanup(func() { root.Close() })
	held, err := spool.Open(root, spool.Limits{MaxBytes: 256 << 10}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("open the spool: %v", err)
	}
	t.Cleanup(func() { held.Close() })
	if _, err := held.Admit(spool.Events, spool.Record{ID: "burst", Payload: make([]byte, 300<<10)}); err == nil {
		t.Fatal("a spool of 256KiB admitted 300KiB")
	}
	observed := &observing{path: "/etc/seagull-agent/agent.json", state: "/var/lib/seagull-agent", spool: held}
	var snapshot status.Snapshot
	component := observed.streams(&snapshot)
	if component.State != status.Degraded || !strings.Contains(string(component.Reason), "refused 1 records since") ||
		!strings.Contains(string(component.Reason), "a gap") || !strings.Contains(string(component.Recovery), "spool.max_bytes") {
		t.Fatalf("a spool that refused a record stands at %+v", component)
	}
	if events := snapshot.Streams[0]; events.Refused != 1 || events.PausedSince.IsZero() {
		t.Fatalf("the events stream stands at %+v", events)
	}
}

func TestTheCollectionStandsAtItsWorstEnabledModule(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "collection")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatalf("create %s: %v", directory, err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatalf("open %s: %v", directory, err)
	}
	t.Cleanup(func() { root.Close() })
	logger := slog.New(slog.DiscardHandler)
	governed, err := governor.New(logger, "5d0f6c9e-6a4b-4f43-9a3f-2f5a8f8f7c11", governor.Budget{Scans: 1, ScanBytesPerSecond: 1 << 20, Uploads: 1, UploadBytesPerSecond: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	collector, err := authentication.New(authentication.Options{
		Installation: "5d0f6c9e-6a4b-4f43-9a3f-2f5a8f8f7c11",
		Spool:        unusedSpool{},
		Governor:     governed,
		Directory:    root,
		Logger:       logger,
		Open: func(context.Context, journal.Position, bool) (authentication.Entries, error) {
			return nil, errors.New("the test reads no journal")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	stopped := errors.New("journalctl stopped, exit status 1: No journal files were opened due to insufficient permissions.")
	for _, held := range []struct {
		name     string
		enabled  bool
		policy   modules.Policy
		collect  func(context.Context) error
		state    status.State
		reason   string
		recovery string
	}{
		{name: "nothing enabled", collect: func(ctx context.Context) error { <-ctx.Done(); return nil }, state: status.Disabled, reason: "no module is enabled"},
		{name: "collecting", enabled: true, collect: func(ctx context.Context) error { <-ctx.Done(); return nil }, state: status.Running},
		{name: "started again", enabled: true, policy: modules.Policy{Backoff: time.Hour, MaxBackoff: time.Hour}, collect: func(context.Context) error { return stopped },
			state: status.Degraded, reason: "authentication: " + stopped.Error(), recovery: "none: the agent starts the module again"},
		{name: "spent", enabled: true, policy: modules.Policy{Budget: 1}, collect: func(context.Context) error { return stopped },
			state: status.Failed, reason: "authentication: " + stopped.Error(), recovery: "/etc/seagull-agent/agent.json"},
	} {
		t.Run(held.name, func(t *testing.T) {
			collection, err := modules.New(logger, held.policy, modules.Module{Name: authentication.Name, Enabled: held.enabled, Collect: held.collect})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			done := make(chan error, 1)
			go func() { done <- collection.Run(ctx) }()
			defer func() { cancel(); <-done }()
			observed := &observing{path: "/etc/seagull-agent/agent.json", collection: collection, authentication: collector}
			deadline := time.Now().Add(5 * time.Second)
			for {
				var snapshot status.Snapshot
				component := observed.collected(&snapshot)
				if component.State == held.state && (held.state == status.Disabled || snapshot.Modules[0].State == held.state) {
					if string(component.Reason) != held.reason || !strings.Contains(string(component.Recovery), held.recovery) ||
						len(snapshot.Modules) != 1 || snapshot.Modules[0].Name != authentication.Name {
						t.Errorf("the collection stands at %+v with %+v", component, snapshot.Modules)
					}
					if held.state != status.Disabled && snapshot.Modules[0].State != held.state {
						t.Errorf("the module stands at %+v and the collection at %s", snapshot.Modules[0], component.State)
					}
					return
				}
				if time.Now().After(deadline) {
					t.Fatalf("the collection stands at %+v, want %s", component, held.state)
				}
				time.Sleep(10 * time.Millisecond)
			}
		})
	}
}

func TestAModuleTheAgentHasNotStartedYetFailsNothing(t *testing.T) {
	collection, err := modules.New(slog.New(slog.DiscardHandler), modules.Policy{}, modules.Module{
		Name: authentication.Name, Enabled: true, Collect: func(ctx context.Context) error { <-ctx.Done(); return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	observed := &observing{path: "/etc/seagull-agent/agent.json", collection: collection}
	var snapshot status.Snapshot
	component := observed.collected(&snapshot)
	if component.State != status.Running || len(snapshot.Modules) != 1 || snapshot.Modules[0].State != status.Degraded ||
		snapshot.Modules[0].Reason != "the agent has not started it yet" {
		t.Errorf("before the agent started its module the collection stands at %+v with %+v", component, snapshot.Modules)
	}
}

type describedHost struct {
	accounts accounts.Database
	failures map[string]error
}

func (h describedHost) Processes(context.Context) ([]processes.Process, error) {
	return []processes.Process{{PID: 1, Name: "systemd", StartedAt: time.Date(2026, 10, 6, 9, 0, 2, 0, time.UTC)}}, h.failures["process"]
}

func (describedHost) Hostname() (string, error) { return "web-01", nil }
func (describedHost) Distribution() (machine.Release, error) {
	return machine.Release{ID: "ubuntu", Name: "Ubuntu", Version: "24.04"}, nil
}
func (describedHost) Kernel() (machine.Kernel, error) {
	return machine.Kernel{Name: "Linux", Release: "6.8.0-45-generic"}, nil
}
func (describedHost) Hardware() (machine.Hardware, error) {
	return machine.Hardware{Memory: 1 << 30}, nil
}
func (h describedHost) Packages(context.Context) ([]dpkg.Package, error) {
	return nil, h.failures["package"]
}
func (describedHost) Services(context.Context) ([]services.Service, error) { return nil, nil }
func (describedHost) Interfaces() ([]interfaces.Interface, error)          { return nil, nil }
func (h describedHost) Accounts() (accounts.Database, error)               { return h.accounts, h.failures["user"] }

func TestTheStatusSaysWhatTheInventoryCannotAdmitAndWhatToDo(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("the inventory keeps its baseline where it can tell who owns it")
	}
	root := func(name string) *os.Root {
		directory := filepath.Join(t.TempDir(), name)
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		opened, err := os.OpenRoot(directory)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { opened.Close() })
		return opened
	}
	logger := slog.New(slog.DiscardHandler)
	kept, err := spool.Open(root("spool"), spool.Limits{MaxBytes: 64 << 20}, logger)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { kept.Close() })
	governed, err := governor.New(logger, "5d0f6c9e-6a4b-4f43-9a3f-2f5a8f8f7c11", governor.Budget{Scans: 1, ScanBytesPerSecond: 1 << 20, Uploads: 1, UploadBytesPerSecond: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	shared := accounts.Database{Accounts: []accounts.Account{{Name: "root"}, {Name: "toor"}}}
	for name, held := range map[string]struct {
		host     describedHost
		state    status.State
		reason   string
		recovery string
	}{
		"a host without dpkg": {host: describedHost{failures: map[string]error{"package": dpkg.ErrAbsent}}, state: status.Running,
			reason: "package is not taken on this host"},
		"account files it cannot read": {host: describedHost{failures: map[string]error{"user": accounts.ErrUnreadable}}, state: status.Degraded,
			reason: "inventory: user is not admitted: " + accounts.ErrUnreadable.Error(), recovery: "none: the agent takes the kind again at its next round"},
		"accounts sharing a uid": {host: describedHost{accounts: shared}, state: status.Running,
			reason: `the platform holds as one user "0": "root", "toor"`},
	} {
		t.Run(name, func(t *testing.T) {
			collector, err := inventory.New(inventory.Options{
				Installation: "5d0f6c9e-6a4b-4f43-9a3f-2f5a8f8f7c11", Spool: kept, Governor: governed, Directory: root("collection"), Logger: logger, Host: held.host,
			})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			done := make(chan error, 2)
			go func() { done <- collector.Collect(ctx) }()
			collection, err := modules.New(logger, modules.Policy{}, modules.Module{Name: inventory.Name, Enabled: true, Collect: func(ctx context.Context) error { <-ctx.Done(); return nil }})
			if err != nil {
				t.Fatal(err)
			}
			go func() { done <- collection.Run(ctx) }()
			defer func() { cancel(); <-done; <-done }()
			observed := &observing{path: "/etc/seagull-agent/agent.json", collection: collection, inventory: collector}
			deadline := time.Now().Add(5 * time.Second)
			for collector.Stats().Round.IsZero() || collection.Health()[0].State != modules.Running {
				if time.Now().After(deadline) {
					t.Fatalf("the inventory took no stock: %+v", collector.Stats())
				}
				time.Sleep(10 * time.Millisecond)
			}
			var snapshot status.Snapshot
			component := observed.collected(&snapshot)
			if component.State != held.state || len(snapshot.Modules) != 1 || snapshot.Modules[0].State != held.state ||
				!strings.Contains(string(snapshot.Modules[0].Reason), held.reason) && !strings.Contains(string(component.Reason), held.reason) || string(component.Recovery) != held.recovery {
				t.Errorf("the collection stands at %+v with %+v", component, snapshot.Modules)
			}
		})
	}
}

type unusedSpool struct{}

func (unusedSpool) Admit(spool.Stream, ...spool.Record) (spool.Receipt, error) {
	return spool.Receipt{}, errors.New("the test admits nothing")
}

func (unusedSpool) Room(spool.Stream) int64 { return 0 }

// The log of a running agent read into a buffer as it is written, so an agent
// the test is not listening to meanwhile is never held up writing its log.
func buffered(entries <-chan map[string]any) <-chan map[string]any {
	held := make(chan map[string]any, 1<<12)
	go func() {
		defer close(held)
		for entry := range entries {
			held <- entry
		}
	}()
	return held
}

func asked(t *testing.T, path string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run([]string{"-config", path, "status"}, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func written(t *testing.T, state string) status.Snapshot {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		held, err := status.Read(filepath.Join(state, statusDirectory))
		if err == nil {
			return held
		}
		if time.Now().After(deadline) {
			t.Fatalf("the agent wrote no status within 10s: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
