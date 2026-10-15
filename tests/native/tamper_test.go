//go:build linux

package native_test

import (
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
	updatev1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/update/v1"
)

const intruder = "seagull-native-intruder"

// The platform hears from the installed agent every interval and as it stops,
// and each report says how the run before it ended: stopped as asked, or
// killed without a word. The sequence never goes back across any of it.
func (g *gate) reports(t *testing.T) {
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatalf("read the boot of this host: %v", err)
	}
	heard := len(g.platform.told())
	run(t, "systemctl", "reset-failed", unit)
	run(t, "systemctl", "start", unit)
	g.invocation = started(t, g.invocation)
	first := g.told(t, heard)
	privileges, build := first.GetPrivileges(), first.GetBuild()
	if first.GetInstallationId() != g.installation || first.GetRun().GetBootId() != strings.TrimSpace(string(boot)) ||
		first.GetRun().GetPreviousEnding() != agentv1.Status_ENDING_STOPPED || first.GetRun().GetPreviousReason() != "the agent was asked to stop" ||
		first.GetCondition() == agentv1.Status_CONDITION_STOPPED || first.GetInterval().AsDuration() != time.Minute ||
		len(first.GetConfiguration().GetDigestSha256()) != 64 || first.GetCredential().GetGeneration() < 2 || len(first.GetModules()) != 6 {
		t.Errorf("after a stop, the agent reported %v", first)
	}
	if privileges.GetUser() != strconv.Itoa(g.uid) || !privileges.GetNoNewPrivileges() || privileges.GetSeccomp() != "filter" || len(privileges.GetCapabilities()) != 0 ||
		!strings.HasPrefix(build.GetVersion(), "v") || !strings.HasPrefix(build.GetToolchain(), "go") || build.GetOs() != "linux" {
		t.Errorf("the agent reported it runs as %v, built as %v", privileges, build)
	}
	if spoken := first.GetCompatibility(); spoken.GetContracts() != contractsOf(t, agentPath) || spoken.GetProtocolVersion() != 1 ||
		spoken.GetEventSchemaVersion() != 1 || spoken.GetInventorySchemaVersion() != 1 || spoken.GetPolicySchemaVersion() != 1 ||
		spoken.GetUpdateSchemaVersion() != 1 || spoken.GetUpdates().GetEnabled() || spoken.GetUpdates().GetFormat() != updatev1.Format_FORMAT_DEB ||
		spoken.GetUpdates().GetStateGeneration() != 1 || spoken.GetAssessmentSchemaVersion() != 1 {
		t.Errorf("an agent that takes no update said it speaks %v", spoken)
	}
	if previous := await(t, g.invocation, "agent_previous_run", 10*time.Second); previous["level"] != "INFO" || previous["ending"] != "stopped" {
		t.Errorf("the agent logged its previous run as %v", previous)
	}

	pid, err := strconv.Atoi(property(t, "MainPID"))
	if err != nil || pid <= 0 {
		t.Fatalf("the service runs no agent: %v", err)
	}
	heard = len(g.platform.told())
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		t.Fatalf("kill the agent: %v", err)
	}
	g.invocation = started(t, g.invocation)
	killed := g.told(t, heard)
	if killed.GetRun().GetPreviousEnding() != agentv1.Status_ENDING_INTERRUPTED || killed.GetSequence() <= first.GetSequence() {
		t.Errorf("after a kill, the agent reported %v", killed.GetRun())
	}
	if previous := await(t, g.invocation, "agent_previous_run", 10*time.Second); previous["level"] != "WARN" || previous["ending"] != "interrupted" {
		t.Errorf("after a kill, the agent logged its previous run as %v", previous)
	}

	heard = len(g.platform.told())
	run(t, "systemctl", "stop", unit)
	last := g.told(t, heard)
	if last.GetCondition() != agentv1.Status_CONDITION_STOPPED || last.GetSequence() <= killed.GetSequence() {
		t.Errorf("as it was stopped, the agent reported %v with sequence %d", last.GetCondition(), last.GetSequence())
	}
	time.Sleep(8 * time.Second)
	if active := answer("systemctl", "is-active", unit); active != "inactive" {
		t.Errorf("a service an operator stopped is %s", active)
	}
	told := g.platform.told()
	for i := 1; i < len(told); i++ {
		if told[i].GetSequence() <= told[i-1].GetSequence() {
			t.Errorf("report %d carried sequence %d after %d", i, told[i].GetSequence(), told[i-1].GetSequence())
		}
	}
	if *evidence != "" {
		g.recordReports(t, strings.TrimSpace(string(boot)))
	}
}

func (g *gate) told(t *testing.T, after int) *agentv1.Status {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		if told := g.platform.told(); len(told) > after {
			return told[after]
		}
		if time.Now().After(deadline) {
			t.Fatalf("the platform heard nothing of the agent within 30s:\n%s", answer("journalctl", "--no-pager", "--output", "cat", "_SYSTEMD_INVOCATION_ID="+g.invocation))
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// What decides what the agent runs belongs to root, and neither another
// account nor the agent's own changes any of it, stops the service, reads the
// installation or touches the process. What root changes while the agent is
// stopped is said as it starts again, and a configuration another account could
// change is refused until root owns it again, with the service trying again on
// its own and further apart each time.
func (g *gate) tamper(t *testing.T) {
	run(t, "useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", intruder)
	t.Cleanup(func() { exec.Command("userdel", intruder).Run() })
	g.collects = true
	g.write(t)
	run(t, "systemctl", "reset-failed", unit)
	run(t, "systemctl", "start", unit)
	g.invocation = started(t, g.invocation)
	pid := property(t, "MainPID")
	decides := []string{agentPath, unitPath, configuration, bundle}
	before := digests(t, decides)

	attempts := []string{
		": >> " + agentPath,
		"mv " + agentPath + " " + agentPath + ".moved",
		": >> " + unitPath,
		"mkdir -p " + overrides + " && : > " + filepath.Join(overrides, "intruder.conf"),
		": >> " + configuration,
		": > " + filepath.Join(settingsDir, "intruder.json"),
		"systemctl stop " + unit,
		"systemctl disable " + unit,
		"systemctl mask " + unit,
		"dpkg --remove " + packageName,
		": > " + filepath.Join(installerState, "pending"),
		"systemctl start " + installerUnit,
	}
	for _, who := range []string{intruder, account} {
		for _, attempt := range attempts {
			if said, err := exec.Command("runuser", "-u", who, "--", "sh", "-c", attempt).CombinedOutput(); err == nil {
				t.Errorf("%s could %s: %s", who, attempt, said)
			}
		}
	}
	for _, attempt := range []string{
		"ls " + state,
		"cat " + filepath.Join(state, "installation.json"),
		"kill -TERM " + pid,
		"cat /proc/" + pid + "/environ",
	} {
		if said, err := exec.Command("runuser", "-u", intruder, "--", "sh", "-c", attempt).CombinedOutput(); err == nil {
			t.Errorf("%s could %s: %s", intruder, attempt, said)
		}
	}
	if property(t, "InvocationID") != g.invocation || property(t, "ActiveState") != "active" {
		t.Errorf("an account without privileges disturbed the service")
	}
	if after := digests(t, decides); !slices.Equal(before, after) {
		t.Errorf("what decides the agent changed: %v, then %v", before, after)
	}
	for _, left := range []string{filepath.Join(overrides, "intruder.conf"), filepath.Join(settingsDir, "intruder.json"), agentPath + ".moved"} {
		if _, err := os.Lstat(left); err == nil {
			t.Errorf("an account without privileges left %s", left)
		}
	}

	restarts := property(t, "NRestarts")
	if said, err := exec.Command("runuser", "-u", account, "--", "kill", "-TERM", pid).CombinedOutput(); err != nil {
		t.Fatalf("the agent's own account could not signal the agent: %v: %s", err, said)
	}
	g.invocation = started(t, g.invocation)
	if property(t, "NRestarts") == restarts {
		t.Errorf("the service started the agent again without counting a restart")
	}
	if previous := await(t, g.invocation, "agent_previous_run", 10*time.Second); previous["ending"] != "stopped" {
		t.Errorf("after a signal outside the service manager, the agent logged %v", previous)
	}

	run(t, "systemctl", "stop", unit)
	g.collects = false
	g.write(t)
	granted := filepath.Join(overrides, "tamper.conf")
	place(t, granted, []byte("[Service]\nCapabilityBoundingSet=CAP_NET_RAW\nAmbientCapabilities=CAP_NET_RAW\n"))
	run(t, "systemctl", "daemon-reload")
	heard := len(g.platform.told())
	run(t, "systemctl", "reset-failed", unit)
	run(t, "systemctl", "start", unit)
	g.invocation = started(t, g.invocation)
	changed := await(t, g.invocation, "agent_changed", 10*time.Second)
	modules, _ := changed["modules"].(map[string]any)
	granting, _ := changed["privileges"].(map[string]any)
	if changed["level"] != "WARN" || modules["weakens"] != true || granting["weakens"] != true || changed["recovery"] == nil ||
		!strings.Contains(fmt.Sprint(modules["before"]), "authentication") || strings.Contains(fmt.Sprint(modules["after"]), "authentication") {
		t.Errorf("after root changed the agent while it was stopped, it logged %v", changed)
	}
	if held := await(t, g.invocation, "agent_privileges", time.Second); held["level"] != "WARN" || !strings.Contains(fmt.Sprint(held["beyond"]), "CAP_NET_RAW") {
		t.Errorf("the agent reported its privileges as %v", held)
	}
	if told := g.told(t, heard); !slices.Contains(told.GetPrivileges().GetCapabilities(), "CAP_NET_RAW") {
		t.Errorf("the platform was told the agent holds %v", told.GetPrivileges().GetCapabilities())
	}
	run(t, "systemctl", "stop", unit)
	if err := os.Remove(granted); err != nil {
		t.Fatalf("take the capability back: %v", err)
	}
	run(t, "systemctl", "daemon-reload")

	if err := os.Chown(configuration, g.uid, 0); err != nil {
		t.Fatalf("hand the configuration to the agent's account: %v", err)
	}
	since := time.Now()
	run(t, "systemctl", "reset-failed", unit)
	run(t, "systemctl", "start", unit)
	refusals := 0
	deadline := time.Now().Add(45 * time.Second)
	for refusals < 2 {
		refusals = 0
		for _, line := range strings.Split(answer("journalctl", "--no-pager", "--output", "cat", "--unit", unit, "--since", "@"+strconv.FormatInt(since.Unix(), 10)), "\n") {
			var entry map[string]any
			if json.Unmarshal([]byte(line), &entry) == nil && entry["msg"] == "agent_not_started" &&
				strings.Contains(fmt.Sprint(entry["error"]), configuration+" belongs to uid "+strconv.Itoa(g.uid)) && entry["recovery"] != nil {
				refusals++
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("the agent did not refuse a configuration its own account owns twice within 45s:\n%s", answer("journalctl", "--no-pager", "--unit", unit, "--lines", "30"))
		}
		time.Sleep(500 * time.Millisecond)
	}
	if next, first := property(t, "RestartUSecNext"), property(t, "RestartUSec"); next == first {
		t.Errorf("the service tries again every %s, as it did the first time", next)
	}
	if err := os.Chown(configuration, 0, 0); err != nil {
		t.Fatalf("give the configuration back to root: %v", err)
	}
	g.invocation = started(t, g.invocation)
	await(t, g.invocation, "agent_starting", 10*time.Second)
	run(t, "systemctl", "stop", unit)
	run(t, "systemctl", "reset-failed", unit)
}

func digests(t *testing.T, paths []string) []string {
	t.Helper()
	var held []string
	for _, path := range paths {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		sum := sha256.Sum256(content)
		described, err := os.Lstat(path)
		if err != nil {
			t.Fatalf("inspect %s: %v", path, err)
		}
		owner := described.Sys().(*syscall.Stat_t)
		held = append(held, fmt.Sprintf("%s %s %d:%d %s", path, described.Mode(), owner.Uid, owner.Gid, hex.EncodeToString(sum[:])))
	}
	return held
}

// What the installed agent reported, byte for byte as the platform received
// it, for a platform's own pipeline to be measured against.
func (g *gate) recordReports(t *testing.T, boot string) {
	t.Helper()
	directory := filepath.Join(*evidence, "status")
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatalf("create %s: %v", directory, err)
	}
	batches := g.platform.statusBatches()
	type told struct {
		Batch     string `json:"batch"`
		Sequence  uint64 `json:"sequence"`
		Condition string `json:"condition"`
		Previous  string `json:"previous_ending"`
	}
	scenario := struct {
		RecordedAt     time.Time `json:"recorded_at"`
		Build          string    `json:"build"`
		InstallationID string    `json:"installation_id"`
		AgentID        string    `json:"agent_id"`
		Boot           string    `json:"boot_id"`
		Reports        []told    `json:"reports"`
	}{RecordedAt: time.Now().UTC(), Build: run(t, agentPath, "-version"), InstallationID: g.installation, AgentID: agentID, Boot: boot}
	reports := g.platform.told()
	for index, batch := range batches {
		name := fmt.Sprintf("batch-%03d.pb", index)
		if err := os.WriteFile(filepath.Join(directory, name), batch, 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		report := reports[index]
		scenario.Reports = append(scenario.Reports, told{Batch: name, Sequence: report.GetSequence(), Condition: report.GetCondition().String(), Previous: report.GetRun().GetPreviousEnding().String()})
	}
	encoded, err := json.MarshalIndent(scenario, "", "  ")
	if err != nil {
		t.Fatalf("encode the scenario: %v", err)
	}
	if err := os.WriteFile(filepath.Join(directory, "scenario.json"), append(encoded, '\n'), 0o644); err != nil {
		t.Fatalf("write the scenario: %v", err)
	}
}

// The contracts release the installed agent was built with, as Go recorded it
// in the binary.
func contractsOf(t *testing.T, binary string) string {
	t.Helper()
	info, err := buildinfo.ReadFile(binary)
	if err != nil {
		t.Fatalf("read how %s was built: %v", binary, err)
	}
	for _, module := range info.Deps {
		if module.Path == "github.com/dynasmon/Seagull-contracts" {
			return module.Version
		}
	}
	t.Fatalf("%s was built with no contracts", binary)
	return ""
}
