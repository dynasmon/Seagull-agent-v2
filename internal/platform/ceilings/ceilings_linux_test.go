//go:build linux

package ceilings

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const child = "SEAGULL_CEILINGS_TEST_CHILD"

func TestMain(m *testing.M) {
	if _, ok := os.LookupEnv(child); ok {
		report(os.Stdout)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

type reported struct {
	Ceilings  Ceilings `json:"ceilings"`
	Error     string   `json:"error"`
	Delegated bool     `json:"delegated"`
}

func report(out io.Writer) {
	found, err := Enforced()
	held := reported{Ceilings: found, Delegated: delegated()}
	if err != nil {
		held.Error = err.Error()
	}
	json.NewEncoder(out).Encode(held)
}

// Whether the service manager handed the scope the controllers the test sets
// limits with: one that does not writes no limit file, and bounds nothing.
func delegated() bool {
	content, err := os.ReadFile(membership)
	if err != nil {
		return false
	}
	leaf, err := member(string(content))
	if err != nil {
		return false
	}
	for _, name := range []string{"memory.max", "pids.max", "cpu.max"} {
		if _, err := os.Stat(filepath.Join(hierarchy, leaf, name)); err != nil {
			return false
		}
	}
	return true
}

type level struct {
	path  string
	files map[string]string
}

const service = "0::/system.slice/seagull-agent.service\n"

func TestTheTightestCeilingOnTheWayToTheRootIsTheOneEnforced(t *testing.T) {
	cases := []struct {
		name       string
		membership string
		levels     []level
		want       Ceilings
	}{
		{
			name:       "nothing bounds the agent",
			membership: service,
			levels: []level{
				{path: "system.slice/seagull-agent.service", files: map[string]string{"memory.max": "max\n", "pids.max": "max\n", "cpu.max": "max 100000\n"}},
				{path: "system.slice", files: map[string]string{"memory.max": "max\n"}},
			},
		},
		{
			name:       "its service bounds it",
			membership: service,
			levels: []level{
				{path: "system.slice/seagull-agent.service", files: map[string]string{"memory.max": "100663296\n", "pids.max": "64\n", "cpu.max": "50000 100000\n"}},
				{path: "system.slice", files: map[string]string{"memory.max": "max\n", "pids.max": "max\n", "cpu.max": "max 100000\n"}},
			},
			want: Ceilings{Memory: 96 << 20, CPUs: 0.5, Tasks: 64},
		},
		{
			name:       "a slice above it is tighter",
			membership: service,
			levels: []level{
				{path: "system.slice/seagull-agent.service", files: map[string]string{"memory.max": "1073741824\n", "pids.max": "4096\n"}},
				{path: "system.slice", files: map[string]string{"memory.max": "536870912\n", "pids.max": "8192\n", "cpu.max": "200000 100000\n"}},
			},
			want: Ceilings{Memory: 512 << 20, CPUs: 2, Tasks: 4096},
		},
		{
			name:       "a container sees its own cgroup as the root",
			membership: "0::/\n",
			levels:     []level{{path: ".", files: map[string]string{"memory.max": "67108864\n", "pids.max": "max\n", "cpu.max": "150000 100000\n"}}},
			want:       Ceilings{Memory: 64 << 20, CPUs: 1.5},
		},
		{
			name:       "a host that keeps v1 controllers beside the unified hierarchy",
			membership: "12:memory:/system.slice/seagull-agent.service\n1:name=systemd:/system.slice/seagull-agent.service\n" + service,
			levels:     []level{{path: "system.slice/seagull-agent.service", files: map[string]string{"memory.max": "268435456\n"}}},
			want:       Ceilings{Memory: 256 << 20},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			found, err := enforced(c.membership, hierarchyOf(t, true, c.levels...))
			if err != nil {
				t.Fatalf("read the ceilings: %v", err)
			}
			if found != c.want {
				t.Fatalf("read %+v, want %+v", found, c.want)
			}
		})
	}
}

func TestCeilingsThatCannotBeReadAreNeverReportedAsNone(t *testing.T) {
	bounded := func(files map[string]string) []level {
		return []level{{path: "system.slice/seagull-agent.service", files: files}}
	}
	cases := []struct {
		name       string
		membership string
		mounted    bool
		levels     []level
		says       string
	}{
		{name: "no cgroup of a v2 hierarchy", membership: "4:memory:/system.slice/seagull-agent.service\n", mounted: true, says: "no cgroup of a v2 hierarchy"},
		{name: "no v2 hierarchy where the agent looks", membership: service, levels: bounded(nil), says: "holds no cgroup v2 hierarchy"},
		{name: "a cgroup that is not there", membership: service, mounted: true, says: "inspect the cgroup"},
		{name: "a path that climbs out of the hierarchy", membership: "0::/../../etc\n", mounted: true, says: "not a path to one"},
		{name: "a relative path", membership: "0::system.slice\n", mounted: true, says: "not a path to one"},
		{name: "a memory limit that is not a number", membership: service, mounted: true, levels: bounded(map[string]string{"memory.max": "lots\n"}), says: `memory.max is "lots"`},
		{name: "a task limit of nothing", membership: service, mounted: true, levels: bounded(map[string]string{"pids.max": "0\n"}), says: `pids.max is "0"`},
		{name: "a quota of no time", membership: service, mounted: true, levels: bounded(map[string]string{"cpu.max": "0 100000\n"}), says: "cpu.max is"},
		{name: "a quota without a period", membership: service, mounted: true, levels: bounded(map[string]string{"cpu.max": "50000\n"}), says: "cpu.max is"},
		{name: "a limit file larger than one", membership: service, mounted: true, levels: bounded(map[string]string{"memory.max": strings.Repeat("9", 5000)}), says: "more than 4096 bytes"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			found, err := enforced(c.membership, hierarchyOf(t, c.mounted, c.levels...))
			if err == nil || !strings.Contains(err.Error(), c.says) {
				t.Fatalf("read %+v with %v, want a refusal saying %q", found, err, c.says)
			}
		})
	}
}

func TestTheCeilingsOfTheRunningProcessAreRead(t *testing.T) {
	if _, err := os.Stat(filepath.Join(hierarchy, "cgroup.controllers")); err != nil {
		t.Skipf("this host holds no cgroup v2 hierarchy at %s", hierarchy)
	}
	found, err := Enforced()
	if err != nil {
		t.Fatalf("read what this host enforces on the test: %v", err)
	}
	if found.Descriptors < 1 {
		t.Fatalf("the test may open %d descriptors", found.Descriptors)
	}
}

func TestTheCeilingsAServiceManagerSetsAreTheOnesReported(t *testing.T) {
	manager, err := exec.LookPath("systemd-run")
	if err != nil {
		t.Skip("there is no systemd-run to start the test under ceilings")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	scope := exec.CommandContext(ctx, manager, "--user", "--scope", "--quiet",
		"-p", "MemoryMax=96M", "-p", "TasksMax=64", "-p", "CPUQuota=50%", os.Args[0])
	scope.Env = append(os.Environ(), child+"=1")
	var stderr bytes.Buffer
	scope.Stderr = &stderr
	out, err := scope.Output()
	var held reported
	if decoded := json.Unmarshal(out, &held); decoded != nil {
		t.Skipf("the user's service manager started no scope (%v): %s", err, strings.TrimSpace(stderr.String()))
	}
	if !held.Delegated {
		t.Skip("the user's service manager does not hand a scope the memory, pids and cpu controllers")
	}
	if held.Error != "" {
		t.Fatalf("the process in the scope could not read its ceilings: %s", held.Error)
	}
	want := Ceilings{Memory: 96 << 20, CPUs: 0.5, Tasks: 64, Descriptors: held.Ceilings.Descriptors}
	if held.Ceilings != want || want.Descriptors < 1 {
		t.Fatalf("the process in the scope read %+v, and its scope sets %+v", held.Ceilings, want)
	}
}

func hierarchyOf(t *testing.T, mounted bool, levels ...level) *os.Root {
	t.Helper()
	directory := t.TempDir()
	if mounted {
		if err := os.WriteFile(filepath.Join(directory, "cgroup.controllers"), []byte("cpuset cpu io memory pids\n"), 0o444); err != nil {
			t.Fatalf("write the controllers: %v", err)
		}
	}
	for _, held := range levels {
		cgroup := filepath.Join(directory, held.path)
		if err := os.MkdirAll(cgroup, 0o755); err != nil {
			t.Fatalf("create %s: %v", cgroup, err)
		}
		for name, content := range held.files {
			if err := os.WriteFile(filepath.Join(cgroup, name), []byte(content), 0o444); err != nil {
				t.Fatalf("write %s: %v", name, err)
			}
		}
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatalf("open %s: %v", directory, err)
	}
	t.Cleanup(func() { root.Close() })
	return root
}
