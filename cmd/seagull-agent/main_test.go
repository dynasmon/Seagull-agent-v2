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
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

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

func TestTheAgentLogsTheVersionsItSpeaksAsItStarts(t *testing.T) {
	ctx, stop := context.WithCancel(t.Context())
	stop()
	var logs bytes.Buffer
	if code := serve(ctx, slog.New(slog.NewJSONHandler(&logs, nil))); code != 0 {
		t.Fatalf("exit code %d:\n%s", code, logs.String())
	}
	first, _, _ := strings.Cut(logs.String(), "\n")
	var started map[string]any
	if err := json.Unmarshal([]byte(first), &started); err != nil {
		t.Fatalf("decode the first log line: %v\n%s", err, logs.String())
	}
	want := map[string]any{
		"msg":                      "agent_starting",
		"build":                    buildIdentity(),
		"protocol_version":         float64(protocol.Version),
		"event_schema_version":     float64(protocol.EventSchemaVersion),
		"inventory_schema_version": float64(protocol.InventorySchemaVersion),
	}
	for name, value := range want {
		if started[name] != value {
			t.Errorf("the first log line carries %s=%v, want %v: %v", name, started[name], value, started)
		}
	}
}

func TestAnythingButACommandIsAUsageError(t *testing.T) {
	for _, args := range [][]string{nil, {"start"}, {"-verbose"}, {"-version", "extra"}, {"-version", "run"}, {"run", "extra"}} {
		var stdout, stderr bytes.Buffer
		if code := run(args, &stdout, &stderr); code != 2 {
			t.Errorf("%q: exit code %d, want 2", args, code)
		}
		if stdout.Len() != 0 {
			t.Errorf("%q: wrote %q to stdout", args, stdout.String())
		}
		if !strings.Contains(stderr.String(), "seagull-agent run") {
			t.Errorf("%q: explained no command on stderr: %q", args, stderr.String())
		}
	}
}

func TestASignalStopsTheAgentCleanly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("windows cannot deliver SIGINT or SIGTERM to another process")
	}
	for _, signal := range []syscall.Signal{syscall.SIGTERM, syscall.SIGINT} {
		t.Run(signal.String(), func(t *testing.T) {
			agent := exec.CommandContext(t.Context(), os.Args[0])
			agent.Env = append(os.Environ(), childArguments+"=run")
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
		name      string
		component agentruntime.Component
		message   string
		cause     string
	}{
		{
			name: "an essential component failed",
			component: agentruntime.Component{Name: "delivery", Policy: agentruntime.Essential, Run: func(context.Context) error {
				return errors.New("spool unavailable")
			}},
			message: "agent_stopped",
			cause:   "delivery: spool unavailable",
		},
		{
			name: "the composition is incomplete",
			component: agentruntime.Component{Name: "delivery", Run: func(context.Context) error {
				return nil
			}},
			message: "agent_not_started",
			cause:   "delivery declares no failure policy",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var logs bytes.Buffer
			if code := serve(t.Context(), slog.New(slog.NewJSONHandler(&logs, nil)), c.component); code != 1 {
				t.Fatalf("exit code %d, want 1", code)
			}
			for line := range strings.Lines(logs.String()) {
				var entry map[string]any
				if err := json.Unmarshal([]byte(line), &entry); err != nil {
					t.Fatalf("decode the log line %q: %v", line, err)
				}
				if entry["msg"] == c.message {
					if cause, _ := entry["error"].(string); entry["level"] != "ERROR" || !strings.Contains(cause, c.cause) {
						t.Fatalf("logged %v, want an error naming %q", entry, c.cause)
					}
					return
				}
			}
			t.Fatalf("logged no %s:\n%s", c.message, logs.String())
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
