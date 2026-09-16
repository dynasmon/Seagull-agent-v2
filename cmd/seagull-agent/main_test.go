package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/identity"
	"github.com/dynasmon/Seagull-agent-v2/internal/protocol"
	agentruntime "github.com/dynasmon/Seagull-agent-v2/internal/runtime"
)

const childArguments = "SEAGULL_AGENT_TEST_ARGUMENTS"

func TestMain(m *testing.M) {
	if arguments, ok := os.LookupEnv(childArguments); ok {
		os.Exit(run(strings.Fields(arguments), os.Stdout, os.Stderr))
	}
	os.Exit(m.Run())
}

func TestTheVersionFlagPrintsTheBuildIdentityApartFromTheWireVersions(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-version"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit code %d: %s", code, stderr.String())
	}
	identity, spoken, _ := strings.Cut(stdout.String(), "\n")
	fields := strings.Fields(identity)
	if len(fields) != 4 || fields[0] != "seagull-agent" || fields[2] != runtime.Version() {
		t.Fatalf("build identity %q", identity)
	}
	if platform := runtime.GOOS + "/" + runtime.GOARCH; fields[3] != platform {
		t.Fatalf("build identity names %s, the binary runs on %s", fields[3], platform)
	}
	want := fmt.Sprintf("protocol_version %d\nevent_schema_version %d\ninventory_schema_version %d\n",
		protocol.Version, protocol.EventSchemaVersion, protocol.InventorySchemaVersion)
	if spoken != want {
		t.Fatalf("printed the wire versions as %q, want %q", spoken, want)
	}
}

func TestTheAgentLogsWhatItIsAsItStarts(t *testing.T) {
	logs := serveStopped(t, stateDirectory(t))
	created, _ := logged(t, logs, "installation_created")
	started, found := logged(t, logs, "agent_starting")
	if !found || created["installation_id"] == nil {
		t.Fatalf("logged no installation_created and agent_starting:\n%s", logs)
	}
	want := map[string]any{
		"build":                    buildIdentity(),
		"protocol_version":         float64(protocol.Version),
		"event_schema_version":     float64(protocol.EventSchemaVersion),
		"inventory_schema_version": float64(protocol.InventorySchemaVersion),
		"installation_id":          created["installation_id"],
	}
	for name, value := range want {
		if started[name] != value {
			t.Errorf("agent_starting carries %s=%v, want %v: %v", name, started[name], value, started)
		}
	}
	if agentID, enrolled := started["agent_id"]; enrolled {
		t.Errorf("a new installation started as agent %v", agentID)
	}
}

func TestTheAgentKeepsItsInstallationAcrossRestarts(t *testing.T) {
	state := stateDirectory(t)
	first, second := serveStopped(t, state), serveStopped(t, state)
	created, _ := logged(t, first, "installation_created")
	if _, recreated := logged(t, second, "installation_created"); recreated || created["installation_id"] == nil {
		t.Fatalf("the first start created %v and the second created one too: %t", created["installation_id"], recreated)
	}
	for _, logs := range []string{first, second} {
		if started, _ := logged(t, logs, "agent_starting"); started["installation_id"] != created["installation_id"] {
			t.Fatalf("started as installation %v, created %v", started["installation_id"], created["installation_id"])
		}
	}
}

func TestAnythingButACommandIsAUsageError(t *testing.T) {
	state := stateDirectory(t)
	for _, args := range [][]string{
		nil,
		{"start"},
		{"-verbose"},
		{"-version", "extra"},
		{"-version", "run"},
		{"run"},
		{"run", "extra"},
		{"-state", state},
		{"-state", state, "-version"},
		{"-state", state, "run", "extra"},
		{"-state", state, "installation"},
		{"-state", state, "installation", "show"},
	} {
		var stdout, stderr bytes.Buffer
		if code := run(args, &stdout, &stderr); code != 2 {
			t.Errorf("%q: exit code %d, want 2", args, code)
		}
		if stdout.Len() != 0 {
			t.Errorf("%q: wrote %q to stdout", args, stdout.String())
		}
		if !strings.Contains(stderr.String(), "seagull-agent -state DIR run") {
			t.Errorf("%q: explained no command on stderr: %q", args, stderr.String())
		}
	}
	if _, err := os.Lstat(state); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a usage error touched the installation state: %v", err)
	}
}

func TestReplacingTheInstallationNamesTheOneItReplaces(t *testing.T) {
	state := stateDirectory(t)
	created, _ := logged(t, serveStopped(t, state), "installation_created")
	previous, _ := created["installation_id"].(string)

	var stdout, stderr bytes.Buffer
	if code := run([]string{"-state", state, "installation", "replace"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit code %d: %s", code, stderr.String())
	}
	replacement, replaces, _ := strings.Cut(strings.TrimPrefix(stdout.String(), "installation_id "), "\n")
	if previous == "" || replacement == previous || replaces != "replaces "+previous+"\n" {
		t.Fatalf("printed %q after replacing %q", stdout.String(), previous)
	}
	if !strings.Contains(stderr.String(), "enroll the new installation") {
		t.Errorf("said nothing about enrolling the new installation: %q", stderr.String())
	}
	if started, _ := logged(t, serveStopped(t, state), "agent_starting"); started["installation_id"] != replacement {
		t.Fatalf("started as installation %v after replacing it with %s", started["installation_id"], replacement)
	}
}

func TestThereIsNoInstallationToReplaceBeforeTheAgentRuns(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-state", stateDirectory(t), "installation", "replace"}, &stdout, &stderr); code != 1 {
		t.Fatalf("exit code %d, want 1", code)
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "no installation to replace") ||
		!strings.Contains(stderr.String(), "run the agent to create an installation") {
		t.Fatalf("printed %q and %q", stdout.String(), stderr.String())
	}
}

func TestASignalStopsTheAgentCleanly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("windows cannot deliver SIGINT or SIGTERM to another process")
	}
	for _, signal := range []syscall.Signal{syscall.SIGTERM, syscall.SIGINT} {
		t.Run(signal.String(), func(t *testing.T) {
			agent := exec.CommandContext(t.Context(), os.Args[0])
			agent.Env = append(os.Environ(), childArguments+"=-state "+stateDirectory(t)+" run")
			logs, err := agent.StderrPipe()
			if err != nil {
				t.Fatalf("attach to the agent's log: %v", err)
			}
			if err := agent.Start(); err != nil {
				t.Fatalf("start the agent: %v", err)
			}
			entries := follow(t, logs)
			await(t, entries, "agent_starting")

			if err := agent.Process.Signal(signal); err != nil {
				t.Fatalf("send %s: %v", signal, err)
			}
			if reason := await(t, entries, "shutdown_started")["reason"]; reason != signal.String()+" signal received" {
				t.Errorf("the agent logged %q as the reason it stopped", reason)
			}
			await(t, entries, "agent_stopped")
			for range entries {
			}
			if err := agent.Wait(); err != nil {
				t.Fatalf("the agent exited with %v after %s, want a clean exit", err, signal)
			}
		})
	}
}

func TestTheAgentExitsWithAnErrorWhenItCannotRun(t *testing.T) {
	cases := []struct {
		name       string
		components []agentruntime.Component
		prepare    func(t *testing.T, state string)
		message    string
		cause      string
		recovery   string
	}{
		{
			name: "an essential component failed",
			components: []agentruntime.Component{{Name: "delivery", Policy: agentruntime.Essential, Run: func(context.Context) error {
				return errors.New("spool unavailable")
			}}},
			message: "agent_stopped",
			cause:   "delivery: spool unavailable",
		},
		{
			name: "the composition is incomplete",
			components: []agentruntime.Component{{Name: "delivery", Run: func(context.Context) error {
				return nil
			}}},
			message: "agent_not_started",
			cause:   "delivery declares no failure policy",
		},
		{
			name: "the installation state is damaged",
			prepare: func(t *testing.T, state string) {
				if err := os.Mkdir(state, 0o700); err != nil {
					t.Fatalf("create %s: %v", state, err)
				}
				if err := os.WriteFile(filepath.Join(state, "installation.json"), []byte("{"), 0o600); err != nil {
					t.Fatalf("damage the installation state: %v", err)
				}
			},
			message:  "agent_not_started",
			cause:    "the installation state is damaged",
			recovery: "-state %s installation replace",
		},
		{
			name: "another agent holds the installation",
			prepare: func(t *testing.T, state string) {
				held, err := identity.Open(state)
				if err != nil {
					t.Fatalf("hold the installation: %v", err)
				}
				t.Cleanup(func() { _ = held.Close() })
			},
			message:  "agent_not_started",
			cause:    "another agent process holds the installation state",
			recovery: "stop the agent that holds %s",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			state := stateDirectory(t)
			if c.prepare != nil {
				c.prepare(t, state)
			}
			var logs bytes.Buffer
			if code := serve(t.Context(), slog.New(slog.NewJSONHandler(&logs, nil)), state, c.components...); code != 1 {
				t.Fatalf("exit code %d, want 1", code)
			}
			entry, found := logged(t, logs.String(), c.message)
			if !found {
				t.Fatalf("logged no %s:\n%s", c.message, logs.String())
			}
			cause, _ := entry["error"].(string)
			recovery, _ := entry["recovery"].(string)
			if want := strings.ReplaceAll(c.recovery, "%s", state); entry["level"] != "ERROR" ||
				!strings.Contains(cause, c.cause) || !strings.Contains(recovery, want) {
				t.Fatalf("logged %v, want an error naming %q and a recovery naming %q", entry, c.cause, want)
			}
		})
	}
}

func follow(t *testing.T, logs io.Reader) <-chan map[string]any {
	entries := make(chan map[string]any)
	go func() {
		defer close(entries)
		lines := bufio.NewScanner(logs)
		for lines.Scan() {
			entry := map[string]any{}
			if err := json.Unmarshal(lines.Bytes(), &entry); err != nil {
				entry = map[string]any{"msg": lines.Text()}
			}
			select {
			case entries <- entry:
			case <-t.Context().Done():
				return
			}
		}
	}()
	return entries
}

func await(t *testing.T, entries <-chan map[string]any, message string) map[string]any {
	t.Helper()
	timeout := time.After(10 * time.Second)
	for {
		select {
		case entry, open := <-entries:
			if !open {
				t.Fatalf("the agent closed its log before %s", message)
			}
			if entry["msg"] == message {
				return entry
			}
		case <-timeout:
			t.Fatalf("the agent logged no %s within 10s", message)
		}
	}
}

func stateDirectory(t *testing.T) string {
	return filepath.Join(t.TempDir(), "state")
}

func serveStopped(t *testing.T, state string) string {
	t.Helper()
	ctx, stop := context.WithCancel(t.Context())
	stop()
	var logs bytes.Buffer
	if code := serve(ctx, slog.New(slog.NewJSONHandler(&logs, nil)), state); code != 0 {
		t.Fatalf("exit code %d:\n%s", code, logs.String())
	}
	return logs.String()
}

func logged(t *testing.T, logs, message string) (map[string]any, bool) {
	t.Helper()
	for line := range strings.Lines(logs) {
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("decode the log line %q: %v", line, err)
		}
		if entry["msg"] == message {
			return entry, true
		}
	}
	return nil, false
}
