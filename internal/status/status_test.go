package status_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/status"
)

func TestAKeeperWritesWhatTheAgentSaysAsItStartsAsItRunsAndAsItStops(t *testing.T) {
	directory := private(t)
	synctest.Test(t, func(t *testing.T) {
		var observed atomic.Int32
		keeper, err := status.NewKeeper(opened(t, directory), 30*time.Second, func() status.Snapshot {
			observed.Add(1)
			return snapshot(status.Component{Name: "delivery", State: status.Degraded, Reason: "the platform could not be reached"})
		}, slog.New(slog.DiscardHandler))
		if err != nil {
			t.Fatalf("compose the keeper: %v", err)
		}
		began := time.Now()
		stopped := make(chan error, 1)
		ctx, stop := context.WithCancel(t.Context())
		go func() { stopped <- keeper.Run(ctx) }()
		synctest.Wait()
		first := read(t, directory)
		if !first.WrittenAt.Equal(began.UTC()) || first.State != status.Degraded || first.EverySeconds != 30 || first.Format != status.Format || observed.Load() != 1 {
			t.Fatalf("as it started, the keeper wrote %+v after observing %d times", first, observed.Load())
		}
		time.Sleep(30 * time.Second)
		synctest.Wait()
		if again := read(t, directory); !again.WrittenAt.Equal(began.Add(30*time.Second).UTC()) || observed.Load() != 2 {
			t.Fatalf("an interval later, the keeper wrote %+v after observing %d times", again, observed.Load())
		}
		stop()
		if err := <-stopped; err != nil {
			t.Fatalf("the keeper stopped with %v", err)
		}
		keeper.Stopped("the agent was asked to stop")
		last := read(t, directory)
		if last.State != status.Stopped || last.Reason != "the agent was asked to stop" || last.Fresh(time.Now()) {
			t.Fatalf("as the agent stopped, the keeper wrote %+v", last)
		}
	})
}

func TestASnapshotIsPrivateAndReplacedWhole(t *testing.T) {
	directory := private(t)
	interrupted := filepath.Join(directory, ".status.json.tmp")
	if err := os.WriteFile(interrupted, []byte("half a snap"), 0o600); err != nil {
		t.Fatalf("leave an interrupted write: %v", err)
	}
	keeper, err := status.NewKeeper(opened(t, directory), time.Second, func() status.Snapshot {
		return snapshot(status.Component{Name: "spool", State: status.Running})
	}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("compose the keeper: %v", err)
	}
	if _, err := os.Stat(interrupted); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the interrupted write was kept: %v", err)
	}
	keeper.Stopped("the agent was asked to stop")
	keeper.Stopped("the agent stopped again")
	held, err := os.ReadDir(directory)
	if err != nil || len(held) != 1 || held[0].Name() != "status.json" {
		t.Fatalf("the status directory holds %v: %v", held, err)
	}
	described, err := os.Stat(filepath.Join(directory, "status.json"))
	if err != nil || described.Mode().Perm() != 0o600 {
		t.Fatalf("the status is kept as %v: %v", described, err)
	}
	if last := read(t, directory); last.Reason != "the agent stopped again" {
		t.Fatalf("the status says %q", last.Reason)
	}
}

func TestAStatusThatIsMissingDamagedNewerOrNotPrivateIsNotRead(t *testing.T) {
	written := func(t *testing.T, content string, mode os.FileMode) string {
		t.Helper()
		directory := private(t)
		if err := os.WriteFile(filepath.Join(directory, "status.json"), []byte(content), mode); err != nil {
			t.Fatalf("write the status: %v", err)
		}
		return directory
	}
	valid := encoded(t, snapshot(status.Component{Name: "spool", State: status.Running}))
	for name, c := range map[string]struct {
		directory func(t *testing.T) string
		want      error
	}{
		"a directory never made": {directory: func(t *testing.T) string { return filepath.Join(t.TempDir(), "status") }, want: status.ErrUnwritten},
		"a status never written": {directory: private, want: status.ErrUnwritten},
		"a status others read":   {directory: func(t *testing.T) string { return written(t, valid, 0o644) }, want: status.ErrInsecure},
		"a directory others read": {directory: func(t *testing.T) string {
			directory := written(t, valid, 0o600)
			if err := os.Chmod(directory, 0o755); err != nil {
				t.Fatalf("open %s: %v", directory, err)
			}
			return directory
		}, want: status.ErrInsecure},
		"bytes that are no status": {directory: func(t *testing.T) string { return written(t, "{half", 0o600) }, want: status.ErrDamaged},
		"a status of a newer agent": {directory: func(t *testing.T) string {
			return written(t, strings.Replace(valid, `"format": 1`, `"format": 2`, 1), 0o600)
		}, want: status.ErrNewer},
		"a status with more than this agent writes": {directory: func(t *testing.T) string {
			return written(t, strings.Replace(valid, `"format": 1`, `"format": 1, "mood": "fine"`, 1), 0o600)
		}, want: status.ErrDamaged},
		"a status that says nothing of the agent": {directory: func(t *testing.T) string { return written(t, `{"format": 1}`, 0o600) }, want: status.ErrDamaged},
		"a status larger than a reader takes": {directory: func(t *testing.T) string {
			return written(t, `{"format": 1, "reason": "`+strings.Repeat("a", 300<<10)+`"}`, 0o600)
		}, want: status.ErrDamaged},
		"a directory in its place": {directory: func(t *testing.T) string {
			directory := private(t)
			if err := os.Mkdir(filepath.Join(directory, "status.json"), 0o700); err != nil {
				t.Fatalf("create a directory: %v", err)
			}
			return directory
		}, want: status.ErrDamaged},
	} {
		t.Run(name, func(t *testing.T) {
			if held, err := status.Read(c.directory(t)); !errors.Is(err, c.want) {
				t.Fatalf("read %+v: %v, want %v", held, err, c.want)
			}
		})
	}
}

func TestWhatASnapshotSaysIsAKilobyteAtMostPerText(t *testing.T) {
	long := strings.Repeat("the platform said something long ", 200) + "ü"
	held := snapshot(status.Component{Name: "delivery", State: status.Degraded, Reason: status.Text(long)})
	content, err := json.Marshal(held)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	var decoded status.Snapshot
	if err := json.Unmarshal(content, &decoded); err != nil {
		t.Fatalf("decode: %v", err)
	}
	reason := string(decoded.Components[0].Reason)
	if len(reason) > 1<<10+3 || !strings.HasSuffix(reason, "...") || !strings.HasPrefix(long, strings.TrimSuffix(reason, "...")) {
		t.Fatalf("a reason of %d bytes was written as %d bytes: %q", len(long), len(reason), reason)
	}
}

func TestAStatusThatCannotBeWrittenIsReportedEachTimeItsFailuresDouble(t *testing.T) {
	directory := private(t)
	blocking := filepath.Join(directory, ".status.json.tmp")
	if err := os.MkdirAll(filepath.Join(blocking, "held"), 0o700); err != nil {
		t.Fatalf("block the status: %v", err)
	}
	written := &logs{}
	keeper, err := status.NewKeeper(opened(t, directory), time.Second, func() status.Snapshot {
		return snapshot(status.Component{Name: "spool", State: status.Running})
	}, slog.New(slog.NewJSONHandler(written, nil)))
	if keeper != nil || err == nil {
		t.Fatalf("a keeper that cannot discard an interrupted write was composed: %v", err)
	}
	if err := os.RemoveAll(blocking); err != nil {
		t.Fatalf("unblock: %v", err)
	}
	keeper, err = status.NewKeeper(opened(t, directory), time.Second, func() status.Snapshot {
		return snapshot(status.Component{Name: "spool", State: status.Running})
	}, slog.New(slog.NewJSONHandler(written, nil)))
	if err != nil {
		t.Fatalf("compose the keeper: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(blocking, "held"), 0o700); err != nil {
		t.Fatalf("block the status: %v", err)
	}
	for range 20 {
		keeper.Stopped("the agent was asked to stop")
	}
	var attempts []float64
	for _, entry := range written.entries(t, "status_not_written") {
		attempts = append(attempts, entry["attempt"].(float64))
		if entry["level"] != "WARN" || !strings.Contains(entry["recovery"].(string), directory) {
			t.Fatalf("logged %v", entry)
		}
	}
	if want := []float64{1, 2, 4, 8, 16}; !slices.Equal(attempts, want) {
		t.Fatalf("twenty failures were logged at attempts %v, want %v", attempts, want)
	}
	if err := os.RemoveAll(blocking); err != nil {
		t.Fatalf("unblock: %v", err)
	}
	keeper.Stopped("the agent was asked to stop")
	if held := read(t, directory); held.State != status.Stopped {
		t.Fatalf("once it could, the keeper wrote %+v", held)
	}
}

func TestTheStateOfTheAgentIsThatOfItsWorstPart(t *testing.T) {
	for _, c := range []struct {
		states []status.State
		want   status.State
	}{
		{want: status.Running},
		{states: []status.State{status.Running, status.Disabled}, want: status.Running},
		{states: []status.State{status.Running, status.Degraded, status.Disabled}, want: status.Degraded},
		{states: []status.State{status.Degraded, status.Failed, status.Running}, want: status.Failed},
	} {
		var components []status.Component
		for _, state := range c.states {
			components = append(components, status.Component{Name: "part", State: state})
		}
		if worst := status.Worst(components); worst != c.want {
			t.Errorf("parts %v make an agent %s, want %s", c.states, worst, c.want)
		}
	}
}

func TestTheStatusSaysWhatStateTheAgentIsInAndWhatToDo(t *testing.T) {
	written := time.Date(2026, time.September, 29, 17, 10, 30, 0, time.UTC)
	held := snapshot(
		status.Component{Name: "configuration", State: status.Running, Since: written.Add(-time.Hour)},
		status.Component{Name: "collection", State: status.Disabled, Reason: "this build has no collector"},
		status.Component{Name: "delivery", State: status.Degraded, Since: written.Add(-5 * time.Minute),
			Reason: "the platform could not be reached: dial tcp: connection refused", Recovery: "check that the host resolves"},
		status.Component{Name: "credential", State: status.Running, Reason: "\x1b[31mred\x1b[0m"},
	)
	held.Format, held.WrittenAt, held.EverySeconds, held.State = status.Format, written, 30, status.Degraded
	held.Streams = []status.Stream{
		{Stream: "events", Outstanding: 1200, Bytes: 3 << 20, Oldest: written.Add(-5*time.Minute - 32*time.Second), LastDelivered: written.Add(-5*time.Minute - 31*time.Second),
			Delivered: 100000, Quarantined: 2, FailingSince: written.Add(-5 * time.Minute), Attempts: 5, Outcome: "unconfirmed", Failure: "transport", NextAttempt: written.Add(41 * time.Second)},
		{Stream: "inventory", Refused: 7, PausedSince: written.Add(-time.Minute)},
	}
	held.Listeners = []status.Listener{{Name: "ingest", FailingSince: written.Add(-5 * time.Minute), Failure: "transport", Attempts: 5, NextAttempt: written.Add(41 * time.Second)}}
	held.Credential = &status.Credential{AgentID: "web-01", Generation: 2, Serial: "1a2b", NotBefore: written.Add(-24 * time.Hour), NotAfter: written.Add(29 * 24 * time.Hour), RenewsAt: written.Add(20 * 24 * time.Hour)}
	held.Resources = status.Resources{MemoryHeld: 23 << 20, MemoryLimit: 256 << 20, MemoryCeiling: 512 << 20, Goroutines: 42, Uploads: status.Use{Held: 1, Limit: 1}, Scans: status.Use{Limit: 2}}

	for _, c := range []struct {
		name  string
		at    time.Time
		state status.State
		says  []string
	}{
		{name: "as the agent runs", at: written.Add(12 * time.Second), state: status.Degraded, says: []string{
			"the agent is degraded: its status was written 2026-09-29T17:10:30Z, 12s ago",
			"agent web-01, installation 8a4a6c52-3a3b-4f0e-9c38-1f2d7f0c9b11, process 4242 started 2026-09-29T16:00:00Z",
			"collection: disabled: this build has no collector",
			"delivery: degraded since 2026-09-29T17:05:30Z: the platform could not be reached: dial tcp: connection refused",
			"  what to do: check that the host resolves",
			`credential: running: "\x1b[31mred\x1b[0m"`,
			"events: 1200 records waiting in 3.0MiB, the oldest admitted 5m44s ago; last delivered 5m43s ago",
			"  kept: 100000 delivered, 0 expired, 0 lost, 2 quarantined",
			"  failing since 2026-09-29T17:05:30Z: 5 attempts, unconfirmed, transport; next attempt in 29s",
			"inventory: nothing waiting; nothing delivered since the agent started",
			"  not kept: 7 records refused admission, admitting nothing since 2026-09-29T17:09:30Z",
			"ingest listener: failing since 2026-09-29T17:05:30Z, transport, 5 attempts; next attempt in 29s",
			"credential: agent web-01, generation 2, serial 1a2b, valid from 2026-09-28T17:10:30Z until 2026-10-28T17:10:30Z",
			"  renews in 19 days",
			"resources: 23.0MiB of memory held, for a target of 256.0MiB within a ceiling of 512.0MiB; 42 goroutines",
			"  uploads: 1 of 1 held, 0 waiting; scans: 0 of 2 held, 0 waiting, 0 deferred",
		}},
		{name: "once the agent stopped writing it", at: written.Add(10 * time.Minute), state: status.Degraded, says: []string{
			"the agent last wrote its status 2026-09-29T17:10:30Z, 10m0s ago, and writes it every 30s: it stopped without saying so, or cannot write its status; it was degraded then",
		}},
		{name: "once the agent stopped", at: written.Add(10 * time.Minute), state: status.Stopped, says: []string{
			"the agent stopped: its status was written 2026-09-29T17:10:30Z, 10m0s ago: the agent was asked to stop",
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			shown := held
			shown.State = c.state
			if c.state == status.Stopped {
				shown.Reason = "the agent was asked to stop"
			}
			var printed bytes.Buffer
			if err := shown.Print(&printed, c.at); err != nil {
				t.Fatalf("print: %v", err)
			}
			for _, said := range c.says {
				if !strings.Contains(printed.String(), said+"\n") {
					t.Errorf("the status does not say %q:\n%s", said, printed.String())
				}
			}
			if strings.Contains(printed.String(), "\x1b") {
				t.Errorf("the status carries a terminal escape:\n%q", printed.String())
			}
		})
	}
}

func snapshot(components ...status.Component) status.Snapshot {
	return status.Snapshot{
		Agent: status.Agent{Build: "seagull-agent (devel) go1.26.8 linux/amd64", Process: 4242, StartedAt: time.Date(2026, time.September, 29, 16, 0, 0, 0, time.UTC),
			InstallationID: "8a4a6c52-3a3b-4f0e-9c38-1f2d7f0c9b11", AgentID: "web-01"},
		Components: components,
	}
}

func encoded(t *testing.T, held status.Snapshot) string {
	t.Helper()
	held.Format, held.WrittenAt, held.EverySeconds, held.State = status.Format, time.Now().UTC(), 30, status.Running
	content, err := json.MarshalIndent(held, "", "  ")
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return string(content)
}

func private(t *testing.T) string {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "status")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatalf("create %s: %v", directory, err)
	}
	return directory
}

func opened(t *testing.T, directory string) *os.Root {
	t.Helper()
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatalf("open %s: %v", directory, err)
	}
	t.Cleanup(func() { root.Close() })
	return root
}

func read(t *testing.T, directory string) status.Snapshot {
	t.Helper()
	held, err := status.Read(directory)
	if err != nil {
		t.Fatalf("read the status: %v", err)
	}
	return held
}

type logs struct {
	mu      sync.Mutex
	written bytes.Buffer
}

func (l *logs) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.written.Write(p)
}

func (l *logs) entries(t *testing.T, message string) []map[string]any {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	var found []map[string]any
	for line := range strings.Lines(l.written.String()) {
		entry := map[string]any{}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("decode the log line %q: %v", line, err)
		}
		if entry["msg"] == message {
			found = append(found, entry)
		}
	}
	return found
}
