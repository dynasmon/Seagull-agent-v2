//go:build linux

package native_test

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"maps"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-agent-v2/internal/identity"
	systemjournal "github.com/dynasmon/Seagull-agent-v2/internal/platform/journal"
	"github.com/dynasmon/Seagull-agent-v2/internal/spool"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
)

var (
	packaged = flag.String("package", "", "the Debian package the gate installs on this host, as root")
	evidence = flag.String("evidence", "", "a directory to write what sshd decided and what the agent delivered of it to")
)

const (
	admitVariable  = "SEAGULL_NATIVE_ADMIT"
	packageName    = "seagull-agent"
	unit           = "seagull-agent.service"
	account        = "seagull-agent"
	agentPath      = "/usr/bin/seagull-agent"
	unitPath       = "/usr/lib/systemd/system/seagull-agent.service"
	settingsDir    = "/etc/seagull-agent"
	configuration  = "/etc/seagull-agent/agent.json"
	bundle         = "/etc/seagull-agent/platform-ca.pem"
	template       = "/usr/share/seagull-agent/agent.json"
	state          = "/var/lib/seagull-agent"
	wants          = "/etc/systemd/system/multi-user.target.wants/seagull-agent.service"
	overrides      = "/etc/systemd/system/seagull-agent.service.d"
	agentID        = "web-01"
	admittedEvents = 3
	admittedItems  = 2
	guesses        = 24
)

func TestMain(m *testing.M) {
	if directory, ok := os.LookupEnv(admitVariable); ok {
		os.Exit(admit(directory))
	}
	if marker, ok := os.LookupEnv(probeVariable); ok {
		os.Exit(probe(marker))
	}
	os.Exit(m.Run())
}

// The package installed, run and removed on this host as an operator would,
// with systemd managing the service: every step depends on the state the
// steps before it left, so the gate stops at the first one that fails.
func TestTheDebianPackageRunsTheAgentAsAServiceFromInstallationToPurge(t *testing.T) {
	g := open(t)
	for _, step := range []struct {
		name string
		run  func(*testing.T)
	}{
		{name: "installing creates the account and the directories and starts nothing", run: g.install},
		{name: "the service account reads the settings and authenticates the platform", run: g.configure},
		{name: "an operator enrolls the installation as the service account", run: g.enroll},
		{name: "the service runs the agent with no privilege and within its ceilings", run: g.start},
		{name: "the service confines the agent to its installation, the network and the system calls it makes", run: g.confine},
		{name: "the running service renews the credential under the installed permissions", run: g.renew},
		{name: "a reload has the agent read its configuration again", run: g.reload},
		{name: "a stop ends the agent cleanly and a start reads back its backlog", run: g.backlog},
		{name: "the service starts the agent again after it is killed", run: g.crash},
		{name: "an upgrade restarts the service on the same installation and backlog", run: g.upgrade},
		{name: "a drop-in bounds the service differently", run: g.override},
		{name: "removing the package stops the service and keeps the installation", run: g.remove},
		{name: "installing the package again runs the same installation", run: g.reinstall},
		{name: "the service delivers its backlog once the platform takes it", run: g.deliver},
		{name: "the service collects what sshd decides and nothing that only names sshd", run: g.collect},
		{name: "the service account writes a bundle of what troubleshooting needs beside the running agent", run: g.diagnose},
		{name: "purging deletes the installation, its settings and the service's", run: g.purge},
		{name: "installing after a purge makes a new installation", run: g.fresh},
	} {
		if !t.Run(step.name, step.run) {
			t.Fatalf("the gate stops at %q: every later step depends on it", step.name)
		}
	}
}

type gate struct {
	built        string
	version      string
	next         string
	nextVersion  string
	scratch      string
	platform     *platform
	uid          int
	gid          int
	invocation   string
	installation string
	held         map[string]string
	collects     bool
}

func open(t *testing.T) *gate {
	built := *packaged
	if built == "" {
		t.Skip("-package names no package: the gate installs one on this host, as root, so it runs only where it is asked to")
	}
	if os.Geteuid() != 0 {
		t.Fatal("the gate installs a package and manages a service: run it as root, on a host you can discard")
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		t.Fatalf("systemd does not manage this host: %v", err)
	}
	if status, _ := exec.Command("dpkg-query", "--show", "--showformat=${db:Status-Status}", packageName).Output(); len(status) > 0 && string(status) != "not-installed" {
		t.Fatalf("%s is %s on this host: the gate purges what it installs, so it runs only where it is not", packageName, status)
	}
	for _, left := range []string{state, settingsDir, overrides} {
		if _, err := os.Lstat(left); err == nil {
			t.Fatalf("%s exists on this host: the gate purges it, so remove it first", left)
		}
	}
	built, err := filepath.Abs(built)
	if err != nil {
		t.Fatalf("find the package: %v", err)
	}
	scratch, err := os.MkdirTemp("", "seagull-native-")
	if err == nil {
		err = os.Chmod(scratch, 0o755)
	}
	if err != nil {
		t.Fatalf("create a directory the service account can read: %v", err)
	}
	t.Cleanup(func() {
		exec.Command("dpkg", "--purge", packageName).Run()
		os.RemoveAll(scratch)
	})
	g := &gate{built: built, scratch: scratch, platform: emulate(t)}
	g.version = strings.TrimSpace(run(t, "dpkg-deb", "--field", built, "Version"))
	g.next, g.nextVersion = repack(t, built, g.version, scratch)
	return g
}

func (g *gate) install(t *testing.T) {
	apt(t, "install", g.built)
	held, err := user.Lookup(account)
	if err != nil {
		t.Fatalf("the package created no account: %v", err)
	}
	g.uid, _ = strconv.Atoi(held.Uid)
	g.gid, _ = strconv.Atoi(held.Gid)
	entry := strings.Split(strings.TrimSpace(run(t, "getent", "passwd", account)), ":")
	if g.uid == 0 || g.uid >= 1000 || len(entry) != 7 || entry[6] != "/usr/sbin/nologin" {
		t.Errorf("the package created the account %q, and a system account without a shell is wanted", entry)
	}
	if group := strings.Split(run(t, "getent", "group", "systemd-journal"), ":"); len(group) != 4 || !slices.Contains(strings.Split(group[3], ","), account) {
		t.Errorf("the package left %s out of systemd-journal, whose members read the system journal: %q", account, group)
	}
	owns(t, state, g.uid, g.gid, fs.ModeDir|0o700)
	owns(t, settingsDir, 0, 0, fs.ModeDir|0o755)
	if enabled, active := answer("systemctl", "is-enabled", unit), answer("systemctl", "is-active", unit); enabled != "disabled" || active != "inactive" {
		t.Errorf("a first installation leaves the service %s and %s, and it starts nothing until an operator enables it", enabled, active)
	}
	if changed := run(t, "dpkg", "--verify", packageName); changed != "" {
		t.Errorf("the installed files are not what the package holds:\n%s", changed)
	}
	if installed := run(t, "dpkg-query", "--show", "--showformat=${Version}", packageName); installed != g.version {
		t.Errorf("dpkg installed %s from a package of version %s", installed, g.version)
	}
	if identity := run(t, agentPath, "-version"); !strings.HasPrefix(identity, "seagull-agent v") {
		t.Errorf("the installed agent says it is %q", identity)
	}
}

func (g *gate) configure(t *testing.T) {
	g.write(t)
	if said, err := as(t, "-config", configuration, "config", "check"); err != nil {
		t.Fatalf("the service account cannot read the settings: %v\n%s", err, said)
	}
	said, err := as(t, "-config", configuration, "platform", "check")
	if err != nil || strings.Count(said, "is authenticated") != 2 || strings.Count(said, "asks for the certificate of an enrolled agent") != 2 {
		t.Fatalf("the service account checked the platform as %v:\n%s", err, said)
	}
}

func (g *gate) write(t *testing.T) {
	t.Helper()
	content, err := os.ReadFile(template)
	if err != nil {
		t.Fatalf("read the settings the package installs: %v", err)
	}
	var settings map[string]any
	if err := json.Unmarshal(content, &settings); err != nil {
		t.Fatalf("read the settings the package installs: %v", err)
	}
	server, ok := settings["server"].(map[string]any)
	if !ok || server["trust_bundle"] != bundle {
		t.Fatalf("the settings the package installs name %v", settings["server"])
	}
	server["ingest_url"], server["renewal_url"] = g.platform.ingest.URL, g.platform.renewal.URL
	if collected, ok := settings["modules"].(map[string]any)["authentication"].(map[string]any); !ok || collected["enabled"] != true {
		t.Fatalf("the settings the package installs collect with %v", settings["modules"])
	}
	settings["modules"] = map[string]any{"authentication": map[string]any{"enabled": g.collects}}
	rewritten, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		t.Fatalf("write the settings: %v", err)
	}
	place(t, bundle, g.platform.bundle())
	place(t, configuration, append(rewritten, '\n'))
}

func (g *gate) enroll(t *testing.T) {
	requested, err := as(t, "-config", configuration, "enrollment", "request", agentID)
	if err != nil {
		t.Fatalf("ask for a certificate: %v\n%s", err, requested)
	}
	issuedAt := time.Now().UTC().Truncate(time.Second)
	issued, err := g.platform.issue([]byte(requested), agentID, issuedAt, issuedAt.Add(30*time.Second))
	if err != nil {
		t.Fatalf("the platform refused the request: %v", err)
	}
	answer := filepath.Join(g.scratch, "issued.pb")
	place(t, answer, issued)
	said, err := as(t, "-config", configuration, "enrollment", "import", answer)
	if err != nil || !strings.Contains(said, "is enrolled as agent "+agentID) {
		t.Fatalf("import the certificate: %v\n%s", err, said)
	}
	g.recorded(t, "enrollment_requested", "credential_imported")
}

func (g *gate) start(t *testing.T) {
	run(t, "systemctl", "enable", "--now", unit)
	g.invocation = started(t, "")
	agent := await(t, g.invocation, "agent_starting", 10*time.Second)
	g.installation, _ = agent["installation_id"].(string)
	if agent["agent_id"] != agentID || agent["credential_generation"] != float64(1) || g.installation == "" {
		t.Errorf("the service started the agent as %v", agent)
	}
	held := await(t, g.invocation, "agent_privileges", time.Second)
	reader, err := user.LookupGroup("systemd-journal")
	if err != nil {
		t.Fatalf("this host has no group that reads the system journal: %v", err)
	}
	journalGroup, _ := strconv.Atoi(reader.Gid)
	groups := []float64{float64(g.gid), float64(journalGroup)}
	slices.Sort(groups)
	if held["level"] != "INFO" || held["user"] != float64(g.uid) || held["group"] != float64(g.gid) ||
		!slices.Equal(numbers(held["groups"]), groups) || fmt.Sprint(held["capabilities"]) != "[]" ||
		held["no_new_privs"] != true || held["seccomp"] != "filter" {
		t.Errorf("the agent holds %v, and it runs as %d:%d with nothing more", held, g.uid, g.gid)
	}
	if dumps := await(t, g.invocation, "agent_core_dumps", time.Second); dumps["withheld"] != true {
		t.Errorf("the agent reports %v", dumps)
	}
	spent := await(t, g.invocation, "agent_resources", time.Second)
	ceilings, _ := spent["ceilings"].(map[string]any)
	if spent["level"] != "INFO" || fmt.Sprint(spent["unenforced"]) != "[]" ||
		!within(ceilings["memory"], 512<<20) || !within(ceilings["cpus"], 0.5) ||
		!within(ceilings["tasks"], 256) || !within(ceilings["descriptors"], 4096) {
		t.Errorf("the agent is bounded by %v", spent)
	}
	cgroup := property(t, "ControlGroup")
	if swapped, err := os.ReadFile(filepath.Join("/sys/fs/cgroup", cgroup, "memory.swap.max")); err != nil || strings.TrimSpace(string(swapped)) != "0" {
		t.Errorf("the service lets %q of the agent's memory reach swap: %v", swapped, err)
	}
	await(t, g.invocation, "spool_opened", time.Second)
	said := g.reported(t, true)
	if !strings.HasPrefix(said, "the agent is running: ") || !strings.Contains(said, "agent "+agentID+", installation "+g.installation) || !strings.Contains(said, "delivery: running\n") {
		t.Errorf("the service account reads the status of the running agent as:\n%s", said)
	}
	owns(t, filepath.Join(state, "status", "status.json"), g.uid, g.gid, 0o600)
}

func (g *gate) renew(t *testing.T) {
	renewed := await(t, g.invocation, "credential_renewed", time.Minute)
	if renewed["credential_generation"] != float64(2) || renewed["key"] != "kept" {
		t.Errorf("the agent renewed its credential as %v", renewed)
	}
	if renewals, agent := g.platform.renewals.Load(), g.platform.renewed.Load(); renewals != 1 || agent == nil || *agent != agentID {
		t.Errorf("the platform renewed %d certificates, the last as %v", renewals, agent)
	}
	var held struct {
		Enrollment struct {
			Generation  uint64 `json:"generation"`
			Certificate struct {
				Fingerprint string `json:"fingerprint_sha256"`
			} `json:"certificate"`
		} `json:"enrollment"`
	}
	content, err := os.ReadFile(filepath.Join(state, "installation.json"))
	if err == nil {
		err = json.Unmarshal(content, &held)
	}
	if err != nil || held.Enrollment.Generation != 2 {
		t.Fatalf("after renewing, the installation holds %s: %v", content, err)
	}
	owns(t, filepath.Join(state, "certificates", held.Enrollment.Certificate.Fingerprint+".pem"), g.uid, g.gid, 0o600)
	owns(t, filepath.Join(state, "installation.json"), g.uid, g.gid, 0o600)
}

func (g *gate) reload(t *testing.T) {
	run(t, "systemctl", "reload", unit)
	await(t, g.invocation, "configuration_reloaded", 10*time.Second)
	if property(t, "InvocationID") != g.invocation {
		t.Error("reloading the service started another agent")
	}
}

func (g *gate) backlog(t *testing.T) {
	run(t, "systemctl", "stop", unit)
	await(t, g.invocation, "agent_stopped", 10*time.Second)
	if result, status := property(t, "Result"), property(t, "ExecMainStatus"); result != "success" || status != "0" {
		t.Errorf("the agent stopped with %s and exit status %s", result, status)
	}
	if said, err := as(t, "-config", configuration, "status"); err == nil || !strings.HasPrefix(said, "the agent stopped: ") || !strings.Contains(said, ": the agent was asked to stop\n") {
		t.Errorf("once the service stopped, the service account read its status as %v:\n%s", err, said)
	}
	if said := g.admit(t); said != fmt.Sprintf("%d %d", admittedEvents, admittedItems) {
		t.Fatalf("the spool admitted %q", said)
	}
	run(t, "systemctl", "start", unit)
	g.invocation = started(t, g.invocation)
	g.same(t, 2)
}

func (g *gate) crash(t *testing.T) {
	pid, err := strconv.Atoi(property(t, "MainPID"))
	if err != nil || pid <= 0 {
		t.Fatalf("the service runs no agent: %q", property(t, "MainPID"))
	}
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		t.Fatalf("kill the agent: %v", err)
	}
	g.invocation = started(t, g.invocation)
	if restarts := property(t, "NRestarts"); restarts != "1" {
		t.Errorf("the service restarted the agent %s times", restarts)
	}
	g.same(t, 2)
}

func (g *gate) upgrade(t *testing.T) {
	g.held = snapshot(t)
	apt(t, "install", g.next)
	g.invocation = started(t, g.invocation)
	g.same(t, 2)
	if installed := run(t, "dpkg-query", "--show", "--showformat=${Version}", packageName); installed != g.nextVersion {
		t.Errorf("dpkg holds %s after upgrading to %s", installed, g.nextVersion)
	}
	unchanged(t, g.held)
}

func (g *gate) override(t *testing.T) {
	if err := os.MkdirAll(overrides, 0o755); err != nil {
		t.Fatalf("create %s: %v", overrides, err)
	}
	place(t, filepath.Join(overrides, "memory.conf"), []byte("[Service]\nMemoryMax=768M\n"))
	run(t, "systemctl", "daemon-reload")
	run(t, "systemctl", "restart", unit)
	g.invocation = started(t, g.invocation)
	spent := await(t, g.invocation, "agent_resources", 10*time.Second)
	if ceilings, _ := spent["ceilings"].(map[string]any); ceilings["memory"] != float64(768<<20) {
		t.Errorf("after the drop-in, the agent is bounded by %v", spent)
	}
	g.same(t, 2)
}

func (g *gate) remove(t *testing.T) {
	apt(t, "remove", packageName)
	if active := answer("systemctl", "is-active", unit); active != "inactive" {
		t.Errorf("after the removal the service is %s", active)
	}
	for _, removed := range []string{agentPath, unitPath} {
		if _, err := os.Lstat(removed); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("the removal left %s: %v", removed, err)
		}
	}
	for _, kept := range []string{configuration, bundle, wants} {
		if _, err := os.Lstat(kept); err != nil {
			t.Errorf("the removal took %s: %v", kept, err)
		}
	}
	if _, err := user.Lookup(account); err != nil {
		t.Errorf("the removal took the account: %v", err)
	}
	if status := run(t, "dpkg-query", "--show", "--showformat=${db:Status-Status}", packageName); status != "config-files" {
		t.Errorf("after the removal dpkg holds the package as %s", status)
	}
	unchanged(t, g.held)
}

func (g *gate) reinstall(t *testing.T) {
	apt(t, "install", g.next)
	g.invocation = started(t, g.invocation)
	g.same(t, 2)
	if enabled := answer("systemctl", "is-enabled", unit); enabled != "enabled" {
		t.Errorf("after the reinstallation the service is %s", enabled)
	}
}

func (g *gate) deliver(t *testing.T) {
	g.platform.taking.Store(true)
	events, inventory := admittedIDs("events", admittedEvents), admittedIDs("inventory", admittedItems)
	deadline := time.Now().Add(time.Minute)
	for !slices.Equal(admittedHere(g.platform.holds("/v1/events")), events) || !slices.Equal(g.platform.holds("/v1/inventory"), inventory) {
		if time.Now().After(deadline) {
			t.Fatalf("the platform holds %v and %v:\n%s", g.platform.holds("/v1/events"), g.platform.holds("/v1/inventory"),
				answer("journalctl", "--no-pager", "--output", "cat", "_SYSTEMD_INVOCATION_ID="+g.invocation))
		}
		time.Sleep(100 * time.Millisecond)
	}
	if resumed := await(t, g.invocation, "delivery_resumed", 10*time.Second); resumed["stream"] == nil {
		t.Errorf("the agent reported %v as it delivered again", resumed)
	}
	run(t, "systemctl", "reset-failed", unit)
	run(t, "systemctl", "restart", unit)
	g.invocation = started(t, g.invocation)
	opened := await(t, g.invocation, "spool_opened", 10*time.Second)
	for stream, count := range map[string]int{"events": admittedEvents, "inventory": admittedItems} {
		held, _ := opened[stream].(map[string]any)
		if held["outstanding"] != float64(0) || held["delivered"] != float64(count) {
			t.Errorf("after delivering, the agent read back %s as %v", stream, held)
		}
		owns(t, filepath.Join(state, "spool", stream, "ledger"), g.uid, g.gid, 0o600)
	}
	said := g.reported(t, true)
	for _, line := range []string{
		"events: nothing waiting; nothing delivered since the agent started\n",
		fmt.Sprintf("  kept: %d delivered, 0 expired, 0 lost, 0 quarantined\n", admittedEvents),
		fmt.Sprintf("  kept: %d delivered, 0 expired, 0 lost, 0 quarantined\n", admittedItems),
	} {
		if !strings.Contains(said, line) {
			t.Errorf("after delivering, the status does not say %q:\n%s", line, said)
		}
	}
}

func admittedHere(held []string) []string {
	return slices.DeleteFunc(held, func(id string) bool { return !strings.HasPrefix(id, "native-") })
}

func (g *gate) collect(t *testing.T) {
	served := openSSH(t, g.scratch)
	g.collecting(t, true)
	await(t, g.invocation, "collection_started", 10*time.Second)
	began := time.Now()
	forge(t, g.scratch)
	served.guess(t, "admin", guesses, 8)
	for _, accepted := range []bool{false, true} {
		if err := served.attempt(gateAccount, accepted); err != nil {
			t.Fatal(err)
		}
	}
	burst := g.delivered(t, guesses+2)
	judged := map[string]int{}
	for _, event := range burst {
		body := event.GetAuthentication()
		happened := event.GetTime().GetEventTime().AsTime()
		if event.GetEventClass() != eventv1.EventClass_EVENT_CLASS_AUTHENTICATION || !slices.Contains([]string{"journal:sshd", "journal:sshd-session"}, event.GetCollection().GetSource()) ||
			event.GetOrigin().GetHost().GetOs() != "linux" || body.GetActivity() != eventv1.Authentication_ACTIVITY_LOGON || body.GetMethod() != "password" ||
			body.GetService().GetName() != "sshd" || body.GetService().GetProtocol() != "ssh" || body.GetNetwork().GetSource().GetIp() != outside ||
			body.GetNetwork().GetSource().GetPort() == 0 || happened.Before(began.Add(-time.Second)) || happened.After(time.Now()) {
			t.Errorf("the agent delivered %v", event)
		}
		judged[fmt.Sprintf("%s %s %s", body.GetUser().GetName(), body.GetOutcome(), body.GetOutcomeReason())]++
	}
	want := map[string]int{
		"admin OUTCOME_FAILURE invalid user": guesses,
		gateAccount + " OUTCOME_FAILURE ":    1,
		gateAccount + " OUTCOME_SUCCESS ":    1,
	}
	if !maps.Equal(judged, want) {
		t.Errorf("the agent delivered %v, and sshd decided %v", judged, want)
	}
	if *evidence != "" {
		g.record(t, began)
	}

	run(t, "systemctl", "stop", unit)
	g.attempts(t, served, "restarted", 3)
	run(t, "systemctl", "start", unit)
	g.invocation = started(t, g.invocation)
	await(t, g.invocation, "collection_resumed", 10*time.Second)
	g.delivered(t, guesses+5)
	if said := g.reported(t, true); !strings.Contains(said, "\ncollection: running") || !strings.Contains(said, "\nmodule authentication: ") {
		t.Errorf("the service account reads the status of the collecting agent as:\n%s", said)
	}

	run(t, "journalctl", "--rotate")
	g.attempts(t, served, "rotated", 2)
	g.delivered(t, guesses+7)
	for _, entry := range journal(t, g.invocation) {
		if entry["msg"] == "collection_gap" {
			t.Errorf("restarted and with its journal rotated, the agent reported %v", entry)
		}
	}

	run(t, "systemctl", "stop", unit)
	g.attempts(t, served, "vacuumed", 2)
	run(t, "journalctl", "--rotate")
	time.Sleep(2 * time.Second)
	run(t, "journalctl", "--vacuum-time=1s")
	run(t, "systemctl", "start", unit)
	g.invocation = started(t, g.invocation)
	if gap := await(t, g.invocation, "collection_gap", 10*time.Second); gap["level"] != "WARN" || gap["after"] == nil || gap["recovery"] == nil {
		t.Errorf("the agent reported what the journal dropped as %v", gap)
	}
	g.attempts(t, served, "returned", 1)
	delivered := g.delivered(t, guesses+8)
	users := map[string]int{}
	for _, event := range delivered {
		users[event.GetAuthentication().GetUser().GetName()]++
	}
	if len(delivered) != guesses+8 || users["restarted"] != 3 || users["rotated"] != 2 || users["vacuumed"] != 0 || users["returned"] != 1 {
		t.Errorf("the agent delivered %d events, by user %v", len(delivered), users)
	}
}

func (g *gate) attempts(t *testing.T, served *sshd, account string, count int) {
	t.Helper()
	for range count {
		if err := served.attempt(account, false); err != nil {
			t.Fatal(err)
		}
	}
}

func (g *gate) collecting(t *testing.T, enabled bool) {
	t.Helper()
	g.collects = enabled
	g.write(t)
	before := len(slices.DeleteFunc(journal(t, g.invocation), func(entry map[string]any) bool { return entry["msg"] != "configuration_reloaded" }))
	run(t, "systemctl", "reload", unit)
	deadline := time.Now().Add(10 * time.Second)
	for len(slices.DeleteFunc(journal(t, g.invocation), func(entry map[string]any) bool { return entry["msg"] != "configuration_reloaded" })) == before {
		if time.Now().After(deadline) {
			t.Fatalf("the agent did not read its configuration again:\n%s", answer("journalctl", "--no-pager", "--output", "cat", "_SYSTEMD_INVOCATION_ID="+g.invocation))
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func (g *gate) delivered(t *testing.T, count int) []*eventv1.Event {
	t.Helper()
	deadline := time.Now().Add(time.Minute)
	for {
		events, _ := g.platform.authentications()
		if len(events) >= count {
			return events
		}
		if time.Now().After(deadline) {
			t.Fatalf("the platform took %d authentications, want %d:\n%s", len(events), count,
				answer("journalctl", "--no-pager", "--output", "cat", "_SYSTEMD_INVOCATION_ID="+g.invocation))
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (g *gate) record(t *testing.T, began time.Time) {
	t.Helper()
	if err := os.MkdirAll(*evidence, 0o755); err != nil {
		t.Fatal(err)
	}
	read, err := systemjournal.New(systemjournal.Query{
		Matches: []systemjournal.Match{{Field: "_COMM", Value: "sshd"}, {Field: "_COMM", Value: "sshd-session"}, {Field: "_UID", Value: "0"}},
		Fields:  []string{"MESSAGE", "_COMM", "_UID", "_HOSTNAME", "_SOURCE_REALTIME_TIMESTAMP"},
	})
	if err != nil {
		t.Fatal(err)
	}
	reader, err := read.Open(t.Context(), systemjournal.Position{Since: began.Add(-time.Second)}, false)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	var entries []systemjournal.Entry
	for {
		entry, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("read what sshd wrote: %v", err)
		}
		entries = append(entries, entry)
	}
	_, batches := g.platform.authentications()
	for i, batch := range batches {
		if err := os.WriteFile(filepath.Join(*evidence, fmt.Sprintf("batch-%03d.pb", i)), batch, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	openssh, _ := exec.Command("ssh", "-V").CombinedOutput()
	systemd := strings.SplitN(run(t, "systemctl", "--version"), "\n", 2)[0]
	release := run(t, "sh", "-c", ". /etc/os-release && echo $PRETTY_NAME")
	scenario := map[string]any{
		"recorded_at":     time.Now().UTC(),
		"began":           began.UTC(),
		"build":           run(t, agentPath, "-version"),
		"installation_id": g.installation,
		"agent_id":        agentID,
		"host":            map[string]string{"os": release, "openssh": strings.TrimSpace(string(openssh)), "systemd": systemd},
		"outside":         outside,
		"account":         gateAccount,
		"guesses":         guesses,
		"batches":         len(batches),
		"journal":         entries,
	}
	written, err := json.MarshalIndent(scenario, "", "  ")
	if err == nil {
		err = os.WriteFile(filepath.Join(*evidence, "scenario.json"), append(written, '\n'), 0o644)
	}
	if err != nil {
		t.Fatal(err)
	}
}

func (g *gate) reported(t *testing.T, running bool) string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		said, err := as(t, "-config", configuration, "status")
		pid := property(t, "MainPID")
		if (err == nil) == running && strings.Contains(said, "process "+pid+" started ") {
			return said
		}
		if time.Now().After(deadline) {
			t.Fatalf("the service account read the status of process %s as %v:\n%s", pid, err, said)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (g *gate) purge(t *testing.T) {
	apt(t, "purge", packageName)
	for _, purged := range []string{state, settingsDir, wants, overrides, agentPath, unitPath} {
		if _, err := os.Lstat(purged); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("the purge left %s: %v", purged, err)
		}
	}
	if _, err := user.Lookup(account); err != nil {
		t.Errorf("the purge took the account, whose uid may still own files elsewhere: %v", err)
	}
	if status, _ := exec.Command("dpkg-query", "--show", "--showformat=${db:Status-Status}", packageName).Output(); len(status) > 0 && string(status) != "not-installed" {
		t.Errorf("after the purge dpkg holds the package as %s", status)
	}
}

func (g *gate) fresh(t *testing.T) {
	apt(t, "install", g.built)
	if enabled, active := answer("systemctl", "is-enabled", unit), answer("systemctl", "is-active", unit); enabled != "disabled" || active != "inactive" {
		t.Errorf("after a purge, installing leaves the service %s and %s", enabled, active)
	}
	owns(t, state, g.uid, g.gid, fs.ModeDir|0o700)
	if left, err := os.ReadDir(state); err != nil || len(left) != 0 {
		t.Fatalf("after a purge the installation holds %v: %v", left, err)
	}
	g.write(t)
	run(t, "systemctl", "start", unit)
	g.invocation = started(t, g.invocation)
	created := await(t, g.invocation, "installation_created", 10*time.Second)
	if created["installation_id"] == g.installation || created["installation_id"] == nil {
		t.Errorf("after a purge the agent runs installation %v, and the purged one was %s", created["installation_id"], g.installation)
	}
	run(t, "systemctl", "stop", unit)
}

func (g *gate) same(t *testing.T, generation int) {
	t.Helper()
	agent := await(t, g.invocation, "agent_starting", 10*time.Second)
	if agent["installation_id"] != g.installation || agent["credential_generation"] != float64(generation) {
		t.Errorf("the agent started as %v, and it was installation %s at generation %d", agent, g.installation, generation)
	}
	opened := await(t, g.invocation, "spool_opened", time.Second)
	events, _ := opened["events"].(map[string]any)
	inventory, _ := opened["inventory"].(map[string]any)
	if events["outstanding"] != float64(admittedEvents) || inventory["outstanding"] != float64(admittedItems) {
		t.Errorf("the agent read back %v", opened)
	}
	for _, entry := range journal(t, g.invocation) {
		if entry["msg"] == "installation_created" {
			t.Errorf("the agent made a new installation: %v", entry)
		}
	}
}

// Records admitted to the spool while the agent is stopped, by the account the
// service runs as, in a copy of this test the account can run.
func (g *gate) admit(t *testing.T) string {
	t.Helper()
	copied := filepath.Join(g.scratch, "native.test")
	copySelf(t, copied)
	command := exec.Command("runuser", "-u", account, "--", copied)
	command.Env = append(os.Environ(), admitVariable+"="+state)
	said, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("admit records as %s: %v\n%s", account, err, said)
	}
	return strings.TrimSpace(string(said))
}

func copySelf(t *testing.T, destination string) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("find this test: %v", err)
	}
	content, err := os.ReadFile(self)
	if err != nil {
		t.Fatalf("read this test: %v", err)
	}
	if err := os.WriteFile(destination, content, 0o755); err != nil {
		t.Fatalf("copy this test: %v", err)
	}
}

func admit(directory string) int {
	installation, err := identity.Open(directory)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer installation.Close()
	root, err := installation.Directory("spool")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	kept := 72 * time.Hour
	held, err := spool.Open(root, spool.Limits{
		MaxBytes:       512 << 20,
		MaxRecordBytes: 4<<20 - 1<<10,
		MaxAge:         map[spool.Stream]time.Duration{spool.Events: kept, spool.Inventory: kept},
	}, slog.New(slog.DiscardHandler))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer held.Close()
	now := timestamppb.Now()
	var records []spool.Record
	for _, id := range admittedIDs("events", admittedEvents) {
		payload, err := proto.Marshal(&eventv1.Event{
			EventId: id, SchemaVersion: 1, EventClass: eventv1.EventClass_EVENT_CLASS_AUTHENTICATION,
			Time: &eventv1.Timestamps{EventTime: now, ObservedTime: now},
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		records = append(records, spool.Record{ID: id, Payload: payload})
	}
	if _, err := held.Admit(spool.Events, records...); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	records = nil
	for _, id := range admittedIDs("inventory", admittedItems) {
		payload, err := proto.Marshal(&inventoryv1.Record{RecordId: id, SchemaVersion: 1, Kind: inventoryv1.Kind_KIND_PACKAGE, Mode: inventoryv1.Mode_MODE_SNAPSHOT, CollectedAt: now})
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		records = append(records, spool.Record{ID: id, Payload: payload})
	}
	if _, err := held.Admit(spool.Inventory, records...); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	counts := map[spool.Stream]int{spool.Events: admittedEvents, spool.Inventory: admittedItems}
	fmt.Printf("%d %d\n", counts[spool.Events], counts[spool.Inventory])
	return 0
}

func admittedIDs(stream string, count int) []string {
	var ids []string
	for i := range count {
		ids = append(ids, fmt.Sprintf("native-%s-%d", stream, i))
	}
	return ids
}

// The same package at the next revision, which is what an upgrade installs:
// the files and the maintainer scripts are those of the package under test.
func repack(t *testing.T, built, version, scratch string) (string, string) {
	t.Helper()
	root := filepath.Join(scratch, "next")
	run(t, "dpkg-deb", "--raw-extract", built, root)
	control := filepath.Join(root, "DEBIAN", "control")
	content, err := os.ReadFile(control)
	if err != nil {
		t.Fatalf("read the control file: %v", err)
	}
	next := version + ".1"
	bumped := strings.Replace(string(content), "\nVersion: "+version+"\n", "\nVersion: "+next+"\n", 1)
	if bumped == string(content) {
		t.Fatalf("the control file declares no version %s:\n%s", version, content)
	}
	if err := os.WriteFile(control, []byte(bumped), 0o644); err != nil {
		t.Fatalf("write the control file: %v", err)
	}
	upgrade := filepath.Join(scratch, "seagull-agent_next.deb")
	run(t, "dpkg-deb", "--root-owner-group", "--build", root, upgrade)
	return upgrade, next
}

func apt(t *testing.T, action, target string) string {
	t.Helper()
	return run(t, "apt-get", action, "--yes", "--option", "DPkg::Lock::Timeout=300", target)
}

func run(t *testing.T, name string, args ...string) string {
	t.Helper()
	command := exec.Command(name, args...)
	command.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive", "LC_ALL=C")
	var stderr bytes.Buffer
	command.Stderr = &stderr
	said, err := command.Output()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s%s", name, strings.Join(args, " "), err, said, stderr.String())
	}
	return strings.TrimSpace(string(said))
}

// What a command says, whatever its exit status: systemctl answers a question
// about a unit with a word and an exit status that is not zero for most of them.
func answer(name string, args ...string) string {
	said, _ := exec.Command(name, args...).Output()
	return strings.TrimSpace(string(said))
}

func as(t *testing.T, args ...string) (string, error) {
	t.Helper()
	command := exec.Command("runuser", append([]string{"-u", account, "--", agentPath}, args...)...)
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	err := command.Run()
	if err != nil {
		return stdout.String() + stderr.String(), err
	}
	return stdout.String(), nil
}

func property(t *testing.T, name string) string {
	t.Helper()
	return run(t, "systemctl", "show", "--property", name, "--value", unit)
}

func started(t *testing.T, previous string) string {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		invocation := property(t, "InvocationID")
		if invocation != "" && invocation != previous && property(t, "ActiveState") == "active" {
			return invocation
		}
		if time.Now().After(deadline) {
			t.Fatalf("the service ran no new agent within 30s:\n%s", answer("journalctl", "--no-pager", "--unit", unit, "--lines", "40"))
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func journal(t *testing.T, invocation string) []map[string]any {
	t.Helper()
	var entries []map[string]any
	lines := bufio.NewScanner(strings.NewReader(run(t, "journalctl", "--no-pager", "--output", "cat", "_SYSTEMD_INVOCATION_ID="+invocation)))
	lines.Buffer(nil, 1<<20)
	for lines.Scan() {
		entry := map[string]any{}
		if err := json.Unmarshal(lines.Bytes(), &entry); err == nil {
			entries = append(entries, entry)
		}
	}
	return entries
}

func await(t *testing.T, invocation, message string, within time.Duration) map[string]any {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		for _, entry := range journal(t, invocation) {
			if entry["msg"] == message {
				return entry
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("the agent logged no %s within %s:\n%s", message, within,
				answer("journalctl", "--no-pager", "--output", "cat", "_SYSTEMD_INVOCATION_ID="+invocation))
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func place(t *testing.T, path string, content []byte) {
	t.Helper()
	err := os.WriteFile(path, content, 0o644)
	if err == nil {
		err = os.Chmod(path, 0o644)
	}
	if err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func owns(t *testing.T, path string, uid, gid int, mode fs.FileMode) {
	t.Helper()
	described, err := os.Lstat(path)
	if err != nil {
		t.Errorf("inspect %s: %v", path, err)
		return
	}
	held := described.Sys().(*syscall.Stat_t)
	if int(held.Uid) != uid || int(held.Gid) != gid || described.Mode() != mode {
		t.Errorf("%s is %s and belongs to %d:%d, want %s and %d:%d", path, described.Mode(), held.Uid, held.Gid, mode, uid, gid)
	}
}

func snapshot(t *testing.T) map[string]string {
	t.Helper()
	held := map[string]string{}
	err := filepath.WalkDir(state, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == filepath.Join(state, "status") {
			return filepath.SkipDir
		}
		described, err := entry.Info()
		if err != nil {
			return err
		}
		owner := described.Sys().(*syscall.Stat_t)
		record := fmt.Sprintf("%s %d:%d", described.Mode(), owner.Uid, owner.Gid)
		if described.Mode().IsRegular() {
			file, err := os.Open(path)
			if err != nil {
				return err
			}
			digest := sha256.New()
			_, err = io.Copy(digest, file)
			file.Close()
			if err != nil {
				return err
			}
			record += fmt.Sprintf(" %x", digest.Sum(nil))
		}
		held[path] = record
		return nil
	})
	if err != nil {
		t.Fatalf("read the installation: %v", err)
	}
	return held
}

func unchanged(t *testing.T, before map[string]string) {
	t.Helper()
	after := snapshot(t)
	if maps.Equal(before, after) {
		return
	}
	for _, path := range slices.Sorted(maps.Keys(before)) {
		if before[path] != after[path] {
			t.Errorf("%s was %q and is %q", path, before[path], after[path])
		}
	}
	for _, path := range slices.Sorted(maps.Keys(after)) {
		if _, held := before[path]; !held {
			t.Errorf("%s appeared as %q", path, after[path])
		}
	}
}

func numbers(value any) []float64 {
	listed, _ := value.([]any)
	var found []float64
	for _, item := range listed {
		if number, ok := item.(float64); ok {
			found = append(found, number)
		}
	}
	return found
}

func within(value any, most float64) bool {
	number, ok := value.(float64)
	return ok && number > 0 && number <= most
}
