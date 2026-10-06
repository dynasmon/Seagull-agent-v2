//go:build linux

package native_test

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-agent-v2/internal/platform/accounts"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/processes"
	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
)

const (
	namedVariable = "SEAGULL_NATIVE_NAMED"
	namedUnit     = "seagull-native-gate-named.service"
	shownDropIn   = "processes.conf"
	chosenName    = "\xff) S 1 ("
)

// named runs as a process that takes the name the gate gives it, as any
// process may through procfs, and waits to be stopped.
func named(written string) int {
	name, err := hex.DecodeString(written)
	if err == nil {
		err = os.WriteFile("/proc/self/comm", name, 0)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	for {
		time.Sleep(time.Hour)
	}
}

type identified struct {
	pid     uint32
	started int64
}

func identifying(pid uint32, started time.Time) identified {
	return identified{pid: pid, started: started.UnixNano()}
}

// What the agent delivered of the processes in one round, and what the
// superuser read of them just before and just after it.
type photographed struct {
	Name    string              `json:"name"`
	Changed string              `json:"changed"`
	Records []map[string]string `json:"records"`
	Stable  int                 `json:"stable"`
	Items   int                 `json:"items"`
}

func (g *gate) processes(t *testing.T) {
	g.running, g.debugging = true, true
	g.collecting(t, g.collects)
	hidden := g.logged(t, "inventory_not_collected")
	if hidden["level"] != "WARN" || hidden["module"] != "processes" || hidden["kind"] != "process" ||
		!strings.Contains(fmt.Sprint(hidden["error"]), "hidepid=") || !strings.Contains(fmt.Sprint(hidden["recovery"]), "ProtectProc=default") {
		t.Errorf("with the service hiding the processes, the agent reported %v", hidden)
	}
	g.statusSays(t, false, "\ncollection: degraded", "processes: process is not admitted", "ProtectProc=default")
	if delivered := g.photographs(); len(delivered) != 0 {
		t.Fatalf("with the processes hidden, the agent delivered %d snapshots of them", len(delivered))
	}

	installed := filepath.Join(probeHome, "native.test")
	if err := os.MkdirAll(probeHome, 0o755); err != nil {
		t.Fatalf("create %s: %v", probeHome, err)
	}
	copySelf(t, installed)
	t.Cleanup(func() {
		exec.Command("systemctl", "stop", namedUnit).Run()
		os.RemoveAll(probeHome)
		os.Remove(filepath.Join(overrides, shownDropIn))
		exec.Command("systemctl", "daemon-reload").Run()
	})
	run(t, "systemd-run", "--unit="+namedUnit, "--property=Type=exec", "--property=User=nobody", "--setenv="+namedVariable+"="+hex.EncodeToString([]byte(chosenName)), installed)
	probe := g.namedProbe(t)

	place(t, filepath.Join(overrides, shownDropIn), []byte("[Service]\nProtectProc=default\n"))
	run(t, "systemctl", "daemon-reload")
	var rounds []photographed
	before := superuser(t)
	changed := time.Now()
	g.restarted(t)
	first := g.stock(t, changed, "process")["process"]
	after := superuser(t)
	rounds = append(rounds, g.checkProcesses(t, "first", "the service shows the agent every process", first, before, after))
	held := items(first)
	if named := held[probe]; named.GetName() != strconv.Quote(chosenName) || named.GetUser() != "nobody" || named.GetPath() != "" || named.GetParentPid() != 1 {
		t.Errorf("the process of nobody that named itself %q was delivered as %v", chosenName, named)
	}
	if admitted := g.logged(t, "inventory_admitted"); admitted["because"] != "first" {
		t.Errorf("the agent admitted %v", admitted)
	}
	g.statusSays(t, true, "\nmodule processes: running")

	run(t, "systemctl", "stop", namedUnit)
	before = superuser(t)
	changed = time.Now()
	g.restarted(t)
	second := g.stock(t, changed, "process")["process"]
	after = superuser(t)
	rounds = append(rounds, g.checkProcesses(t, "ended", "the process that named itself ended", second, before, after))
	if _, found := items(second)[probe]; found {
		t.Errorf("the agent delivered the process that ended in its next snapshot")
	}
	if admitted := g.logged(t, "inventory_admitted"); admitted["because"] != "changed" {
		t.Errorf("once a process ended, the agent admitted %v", admitted)
	}
	took := g.logged(t, "inventory_taken")
	t.Logf("the agent took %d processes in a round of %v ns", len(second.GetItems()), took["took"])
	if *evidence != "" {
		g.photographed(t, rounds)
	}

	if err := os.Remove(filepath.Join(overrides, shownDropIn)); err != nil {
		t.Fatal(err)
	}
	run(t, "systemctl", "daemon-reload")
	g.running, g.debugging = false, false
	g.collecting(t, g.collects)
	g.restarted(t)
}

func (g *gate) namedProbe(t *testing.T) identified {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		pid, _ := strconv.ParseUint(answer("systemctl", "show", "--property", "MainPID", "--value", namedUnit), 10, 32)
		for _, process := range superuser(t) {
			if process.PID == uint32(pid) && process.Name == chosenName {
				return identifying(process.PID, process.StartedAt)
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("the probe did not name itself:\n%s", answer("journalctl", "--no-pager", "--unit", namedUnit))
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// statusSays waits for the status the service account reads to say all it is
// given, which the agent writes again every 30 seconds.
func (g *gate) statusSays(t *testing.T, running bool, said ...string) {
	t.Helper()
	deadline := time.Now().Add(45 * time.Second)
	for {
		read, err := as(t, "-config", configuration, "status")
		missing := slices.DeleteFunc(slices.Clone(said), func(line string) bool { return strings.Contains(read, line) })
		if (err == nil) == running && strings.Contains(read, "process "+property(t, "MainPID")+" started ") && len(missing) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the service account reads the status as %v, without %q:\n%s", err, missing, read)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func superuser(t *testing.T) []processes.Process {
	t.Helper()
	listed, err := processes.List(t.Context(), 1<<16)
	if err != nil {
		t.Fatalf("read the processes as the superuser: %v", err)
	}
	return listed
}

func items(record *inventoryv1.Record) map[identified]*inventoryv1.Process {
	held := map[identified]*inventoryv1.Process{}
	for _, item := range record.GetItems() {
		running := item.GetProcess()
		held[identifying(running.GetPid(), running.GetStartedAt().AsTime())] = running
	}
	return held
}

func (g *gate) photographs() []*inventoryv1.Record {
	records, _ := g.platform.inventories()
	var held []*inventoryv1.Record
	for _, record := range records {
		if record.GetKind() == inventoryv1.Kind_KIND_PROCESS {
			held = append(held, record)
		}
	}
	return held
}

// checkProcesses holds a snapshot to what the superuser read before and after
// the round: every process it read both times is in it as procfs said of it,
// only the agent's own processes carry their executable, and none carries a
// command line or a parent that started after it.
func (g *gate) checkProcesses(t *testing.T, name, changed string, record *inventoryv1.Record, before, after []processes.Process) photographed {
	t.Helper()
	if record.GetMode() != inventoryv1.Mode_MODE_SNAPSHOT || record.GetCollection().GetCollector() != "processes" || record.GetCollection().GetSource() != "procfs" {
		t.Errorf("the processes were delivered as %v", record)
	}
	database, err := accounts.Read()
	if err != nil {
		t.Fatal(err)
	}
	called := map[uint32]string{}
	for _, account := range database.Accounts {
		if _, found := called[account.UID]; !found {
			called[account.UID] = account.Name
		}
	}
	held := items(record)
	earlier := map[uint32]processes.Process{}
	for _, process := range before {
		earlier[process.PID] = process
	}
	stable := map[uint32]processes.Process{}
	for _, process := range after {
		if read, found := earlier[process.PID]; found && read == process {
			stable[process.PID] = process
		}
	}
	for _, process := range stable {
		delivered, found := held[identifying(process.PID, process.StartedAt)]
		if !found {
			t.Errorf("the snapshot leaves out process %d (%q), which ran as it was before and after the round", process.PID, process.Name)
			continue
		}
		user, known := called[process.User]
		if !known {
			user = strconv.FormatUint(uint64(process.User), 10)
		}
		path := ""
		if process.User == uint32(g.uid) {
			path = process.Executable
		}
		worker, _, _ := strings.Cut(process.Name, "-")
		working := process.Parent == 2 && strings.HasPrefix(worker, "kworker/")
		named := delivered.GetName() == process.Name || working && (delivered.GetName() == worker || strings.HasPrefix(delivered.GetName(), worker+"-"))
		if delivered.GetUser() != user || delivered.GetPath() != path || printable(process.Name) && !named {
			t.Errorf("process %d (%q of %d, run from %q) was delivered as %v", process.PID, process.Name, process.User, process.Executable, delivered)
		}
		if parent, found := stable[process.Parent]; found && !parent.StartedAt.After(process.StartedAt) && delivered.GetParentPid() != process.Parent {
			t.Errorf("process %d, child of %d, was delivered as the child of %d", process.PID, process.Parent, delivered.GetParentPid())
		}
	}
	agent, _ := strconv.ParseUint(property(t, "MainPID"), 10, 32)
	seen := false
	for key, delivered := range held {
		if delivered.GetCommandLine() != "" {
			t.Errorf("process %d was delivered with the command line %q", key.pid, delivered.GetCommandLine())
		}
		if delivered.GetUser() != account && delivered.GetPath() != "" {
			t.Errorf("process %d of %s was delivered as run from %q, which procfs shows the agent's account of its own processes alone", key.pid, delivered.GetUser(), delivered.GetPath())
		}
		if parent := delivered.GetParentPid(); parent != 0 && !hasParent(held, parent, key.started) {
			t.Errorf("process %d names as its parent %d, which the snapshot holds as no process started before it", key.pid, parent)
		}
		if key.pid == uint32(agent) {
			seen = delivered.GetPath() == agentPath && delivered.GetUser() == account && delivered.GetParentPid() == 1
		}
	}
	if !seen || len(stable) == 0 {
		t.Errorf("of %d processes, %d read alike before and after the round, the agent delivered itself, process %d, as %v", len(held), len(stable), agent, record.GetItems())
	}
	return photographed{Name: name, Changed: changed, Stable: len(stable), Items: len(held),
		Records: []map[string]string{{"kind": "process", "record_id": record.GetRecordId(), "collected_at": record.GetCollectedAt().AsTime().Format(time.RFC3339Nano)}}}
}

func hasParent(held map[identified]*inventoryv1.Process, parent uint32, child int64) bool {
	for key := range held {
		if key.pid == parent && key.started <= child {
			return true
		}
	}
	return false
}

func (g *gate) logged(t *testing.T, message string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		for _, entry := range journal(t, g.invocation) {
			if entry["msg"] == message && entry["module"] == "processes" {
				return entry
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("the processes module logged no %s:\n%s", message, answer("journalctl", "--no-pager", "--output", "cat", "_SYSTEMD_INVOCATION_ID="+g.invocation))
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func printable(text string) bool {
	return text != "" && utf8.ValidString(text) && strings.IndexFunc(text, func(held rune) bool { return !unicode.IsPrint(held) }) < 0
}

func (g *gate) photographed(t *testing.T, rounds []photographed) {
	t.Helper()
	directory := filepath.Join(*evidence, "processes")
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	_, batches := g.platform.inventories()
	written := 0
	for _, batch := range batches {
		var decoded inventoryv1.RecordBatch
		if err := proto.Unmarshal(batch, &decoded); err != nil || len(decoded.GetRecords()) == 0 || decoded.GetRecords()[0].GetKind() != inventoryv1.Kind_KIND_PROCESS {
			continue
		}
		if err := os.WriteFile(filepath.Join(directory, fmt.Sprintf("batch-%03d.pb", written)), batch, 0o644); err != nil {
			t.Fatal(err)
		}
		written++
	}
	scenario := map[string]any{
		"recorded_at":     time.Now().UTC(),
		"build":           run(t, agentPath, "-version"),
		"installation_id": g.installation,
		"agent_id":        agentID,
		"host":            map[string]string{"kernel": run(t, "uname", "-r"), "systemd": strings.SplitN(run(t, "systemctl", "--version"), "\n", 2)[0]},
		"probe":           map[string]string{"unit": namedUnit, "named": strconv.Quote(chosenName), "account": "nobody"},
		"batches":         written,
		"rounds":          rounds,
	}
	encoded, err := json.MarshalIndent(scenario, "", "  ")
	if err == nil {
		err = os.WriteFile(filepath.Join(directory, "scenario.json"), append(encoded, '\n'), 0o644)
	}
	if err != nil {
		t.Fatal(err)
	}
}
