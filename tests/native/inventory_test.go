//go:build linux

package native_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-agent-v2/internal/modules/inventory"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/accounts"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/dpkg"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/interfaces"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/machine"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/processes"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/services"
	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
)

const (
	probePackage = "seagull-native-gate-probe"
	probeSource  = "seagull-native-gate-source"
	probeAccount = "seagull-native-toor"
	probeLink    = "seagull0"
	probeUnit    = "seagull-native-gate-probe.service"
)

var stocked = []string{"operating_system", "kernel", "hardware", "package", "service", "network_interface", "user"}

// What the host had when the agent took stock of it in one round, as the
// platform adapters read it, and the records the agent delivered of it.
type round struct {
	Name     string              `json:"name"`
	Changed  string              `json:"changed"`
	Observed observed            `json:"observed"`
	Records  []map[string]string `json:"records"`
}

type observed struct {
	Hostname   string                 `json:"hostname"`
	Release    machine.Release        `json:"release"`
	Kernel     machine.Kernel         `json:"kernel"`
	Hardware   machine.Hardware       `json:"hardware"`
	Packages   []dpkg.Package         `json:"packages"`
	Services   []services.Service     `json:"services"`
	Interfaces []interfaces.Interface `json:"interfaces"`
	Accounts   accounts.Database      `json:"accounts"`
}

func (g *gate) inventory(t *testing.T) {
	g.inventories, g.debugging = true, true
	g.collecting(t, g.collects)
	began := time.Now()
	var rounds []round
	first := g.stock(t, began.Add(-time.Second), stocked...)
	g.checkHost(t, first)
	rounds = append(rounds, g.observe(t, "first", "the agent takes stock of the host for the first time", first))

	versions := g.probes(t)
	t.Cleanup(func() {
		exec.Command("dpkg", "--purge", probePackage).Run()
		exec.Command("userdel", "--force", probeAccount).Run()
		exec.Command("ip", "link", "delete", probeLink).Run()
		exec.Command("systemctl", "stop", probeUnit).Run()
	})
	run(t, "dpkg", "--install", versions["1.0"])
	run(t, "useradd", "--non-unique", "--uid", "0", "--gid", "0", "--no-create-home", "--no-user-group", "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", probeAccount)
	run(t, "ip", "link", "add", probeLink, "type", "dummy")
	run(t, "ip", "address", "add", "198.51.100.7/24", "dev", probeLink)
	run(t, "ip", "address", "add", "2001:db8::7/64", "dev", probeLink, "nodad")
	run(t, "ip", "link", "set", probeLink, "up")
	run(t, "systemd-run", "--unit="+probeUnit, "--property=Type=exec", "/usr/bin/sleep", "infinity")
	changed := time.Now()
	g.restarted(t)
	added := g.stock(t, changed, "package", "service", "network_interface", "user")
	g.checkAdded(t, added)
	if merged := await(t, g.invocation, "inventory_items_merged", 10*time.Second); merged["level"] != "WARN" || !strings.Contains(fmt.Sprint(merged["merged"]), `user "0": "root", "`+probeAccount+`"`) {
		t.Errorf("the agent reported accounts sharing uid 0 as %v", merged)
	}
	rounds = append(rounds, g.observe(t, "installed", "a package, an account with uid 0, a dummy interface and a transient service are added", added))

	run(t, "dpkg", "--install", versions["2.0"])
	changed = time.Now()
	g.restarted(t)
	upgraded := g.stock(t, changed, "package")
	if probes := probesIn(upgraded["package"]); len(probes) != 1 || probes[0].GetVersion() != "2.0" || probes[0].GetSource() != probeSource+" (2.0)" {
		t.Errorf("after an upgrade the agent delivered the probe as %v", probes)
	}
	rounds = append(rounds, g.observe(t, "upgraded", "the package is upgraded", upgraded))

	run(t, "dpkg", "--purge", probePackage)
	run(t, "userdel", "--force", probeAccount)
	run(t, "ip", "link", "delete", probeLink)
	run(t, "systemctl", "stop", probeUnit)
	changed = time.Now()
	g.restarted(t)
	removed := g.stock(t, changed, "package", "service", "network_interface", "user")
	g.checkRemoved(t, removed)
	rounds = append(rounds, g.observe(t, "removed", "the package is purged and the account, the interface and the service removed", removed))

	g.restarted(t)
	ended := await(t, g.invocation, "inventory_taken", time.Minute)
	for _, entry := range journal(t, g.invocation) {
		if entry["msg"] == "inventory_admitted" && slices.Contains([]string{"operating_system", "kernel", "package", "user"}, fmt.Sprint(entry["kind"])) {
			t.Errorf("started again on a host whose %s did not change, the agent admitted it: %v", entry["kind"], entry)
		}
	}
	if ended["level"] != "DEBUG" {
		t.Errorf("the agent ended its round with %v", ended)
	}
	if *evidence != "" {
		g.inventoried(t, rounds)
	}
	g.inventories, g.debugging = false, false
	g.collecting(t, g.collects)
}

// stock waits for the platform to hold a record of every kind named that was
// taken at or after since, and returns the last of each.
func (g *gate) stock(t *testing.T, since time.Time, kinds ...string) map[string]*inventoryv1.Record {
	t.Helper()
	deadline := time.Now().Add(time.Minute)
	for {
		records, _ := g.platform.inventories()
		latest := map[string]*inventoryv1.Record{}
		for _, record := range records {
			if !record.GetCollectedAt().AsTime().Before(since) {
				latest[inventory.KindName(record.GetKind())] = record
			}
		}
		if !slices.ContainsFunc(kinds, func(kind string) bool { return latest[kind] == nil }) {
			return latest
		}
		if time.Now().After(deadline) {
			t.Fatalf("the platform holds %v taken since %s, want %v:\n%s", slices.Sorted(maps.Keys(latest)), since, kinds,
				answer("journalctl", "--no-pager", "--output", "cat", "_SYSTEMD_INVOCATION_ID="+g.invocation))
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (g *gate) restarted(t *testing.T) {
	t.Helper()
	run(t, "systemctl", "reset-failed", unit)
	run(t, "systemctl", "restart", unit)
	g.invocation = started(t, g.invocation)
}

func (g *gate) checkHost(t *testing.T, first map[string]*inventoryv1.Record) {
	t.Helper()
	for kind, record := range first {
		if record.GetMode() != inventoryv1.Mode_MODE_SNAPSHOT || record.GetCollection().GetCollector() != "inventory" || record.GetOrigin().GetHost().GetOs() != "linux" {
			t.Errorf("the agent delivered the %s as %v", kind, record)
		}
	}
	released := strings.Fields(run(t, "sh", "-c", ". /etc/os-release && echo $ID $VERSION_ID $VERSION_CODENAME"))
	system := first["operating_system"].GetItems()[0].GetOperatingSystem()
	if len(released) != 3 || system.GetPlatform() != released[0] || system.GetVersion() != released[1] || system.GetCodename() != released[2] || system.GetFamily() != "debian" {
		t.Errorf("the agent delivered the distribution %v, and os-release says %q", system, released)
	}
	kernel := first["kernel"].GetItems()[0].GetKernel()
	if kernel.GetRelease() != run(t, "uname", "-r") || kernel.GetArchitecture() != run(t, "uname", "-m") || kernel.GetName() != "Linux" {
		t.Errorf("the agent delivered the kernel %v", kernel)
	}
	memory := strings.Fields(run(t, "grep", "MemTotal", "/proc/meminfo"))
	if kib, _ := strconv.ParseUint(memory[1], 10, 64); first["hardware"].GetItems()[0].GetHardware().GetMemoryTotalBytes() != kib*1024 {
		t.Errorf("the agent delivered the hardware %v, and the host holds %s KiB", first["hardware"], memory[1])
	}

	var installed []string
	for line := range strings.SplitSeq(run(t, "dpkg-query", "--show", "--showformat=${Package}:${Architecture} ${Version} ${db:Status-Status}\n"), "\n") {
		if fields := strings.Fields(line); len(fields) == 3 && fields[2] != "config-files" && fields[2] != "not-installed" {
			installed = append(installed, fields[0]+" "+fields[1])
		}
	}
	var delivered []string
	for _, item := range first["package"].GetItems() {
		held := item.GetPackage()
		delivered = append(delivered, held.GetName()+":"+held.GetArchitecture()+" "+held.GetVersion())
		if held.GetManager() != "dpkg" || !strings.Contains(held.GetSource(), " (") {
			t.Errorf("the agent delivered the package %v", held)
		}
	}
	slices.Sort(installed)
	slices.Sort(delivered)
	missing := slices.DeleteFunc(slices.Clone(installed), func(held string) bool { return slices.Contains(delivered, held) })
	extra := slices.DeleteFunc(slices.Clone(delivered), func(held string) bool { return slices.Contains(installed, held) })
	own := packageName + ":" + run(t, "dpkg", "--print-architecture") + " " + run(t, "dpkg-query", "--show", "--showformat=${Version}", packageName)
	if len(missing) > 0 || len(extra) > 0 || !slices.Contains(delivered, own) {
		t.Errorf("the agent delivered %d packages, without %q and with %q, and dpkg holds %d, %s among them", len(delivered), missing, extra, len(installed), own)
	}

	service := func(name string) *inventoryv1.Service {
		for _, item := range first["service"].GetItems() {
			if item.GetService().GetName() == name {
				return item.GetService()
			}
		}
		return nil
	}
	if own := service(unit); own == nil || own.GetState() != inventoryv1.Service_STATE_RUNNING || own.GetStartMode() != "enabled" {
		t.Errorf("the agent delivered its own service as %v", own)
	}
	if journald := service("systemd-journald.service"); journald == nil || journald.GetState() != inventoryv1.Service_STATE_RUNNING || journald.GetStartMode() != "static" {
		t.Errorf("the agent delivered journald's service as %v", journald)
	}

	loopback := link(first["network_interface"], "lo")
	if loopback == nil || loopback.GetType() != "loopback" || loopback.GetState() != inventoryv1.NetworkInterface_STATE_UP || !slices.Contains(loopback.GetAddresses(), "127.0.0.1/8") {
		t.Errorf("the agent delivered the loopback as %v", loopback)
	}

	content, err := os.ReadFile("/etc/passwd")
	if err != nil {
		t.Fatal(err)
	}
	var named []string
	for line := range strings.SplitSeq(strings.TrimSpace(string(content)), "\n") {
		named = append(named, strings.SplitN(line, ":", 2)[0])
	}
	var users []string
	for _, item := range first["user"].GetItems() {
		users = append(users, item.GetUser().GetName())
		if held := item.GetUser(); held.GetName() == account && (held.GetUid() != strconv.Itoa(g.uid) || !slices.Contains(held.GetGroups(), "systemd-journal")) {
			t.Errorf("the agent delivered its own account as %v", held)
		}
	}
	slices.Sort(named)
	slices.Sort(users)
	if !slices.Equal(users, named) {
		t.Errorf("the agent delivered the accounts %v, and /etc/passwd holds %v", users, named)
	}
}

func (g *gate) checkAdded(t *testing.T, added map[string]*inventoryv1.Record) {
	t.Helper()
	probes := probesIn(added["package"])
	if len(probes) != 1 || probes[0].GetVersion() != "1.0" || probes[0].GetArchitecture() != "all" || probes[0].GetSource() != probeSource+" (1.0)" || probes[0].GetSizeBytes() != 4<<10 {
		t.Errorf("after the probe was installed the agent delivered it as %v", probes)
	}
	var root, toor bool
	for _, item := range added["user"].GetItems() {
		held := item.GetUser()
		root = root || held.GetName() == "root" && held.GetUid() == "0"
		toor = toor || held.GetName() == probeAccount && held.GetUid() == "0"
	}
	if !root || !toor {
		t.Errorf("after an account with uid 0 was added the agent delivered %v", added["user"].GetItems())
	}
	dummy := link(added["network_interface"], probeLink)
	if dummy == nil || dummy.GetState() != inventoryv1.NetworkInterface_STATE_UP || !slices.Contains(dummy.GetAddresses(), "198.51.100.7/24") || !slices.Contains(dummy.GetAddresses(), "2001:db8::7/64") {
		t.Errorf("after a dummy interface was added the agent delivered it as %v", dummy)
	}
	if !slices.ContainsFunc(added["service"].GetItems(), func(item *inventoryv1.Item) bool {
		return item.GetService().GetName() == probeUnit && item.GetService().GetState() == inventoryv1.Service_STATE_RUNNING && item.GetService().GetStartMode() == "transient"
	}) {
		t.Errorf("after a transient service started the agent delivered the services without it running")
	}
}

func (g *gate) checkRemoved(t *testing.T, removed map[string]*inventoryv1.Record) {
	t.Helper()
	if probes := probesIn(removed["package"]); len(probes) != 0 {
		t.Errorf("after the probe was purged the agent delivered %v", probes)
	}
	if slices.ContainsFunc(removed["user"].GetItems(), func(item *inventoryv1.Item) bool { return item.GetUser().GetName() == probeAccount }) ||
		link(removed["network_interface"], probeLink) != nil ||
		slices.ContainsFunc(removed["service"].GetItems(), func(item *inventoryv1.Item) bool {
			return item.GetService().GetName() == probeUnit && item.GetService().GetState() == inventoryv1.Service_STATE_RUNNING
		}) {
		t.Errorf("after the account, the interface and the service went the agent still delivered one of them")
	}
}

func probesIn(record *inventoryv1.Record) []*inventoryv1.Package {
	var held []*inventoryv1.Package
	for _, item := range record.GetItems() {
		if item.GetPackage().GetName() == probePackage {
			held = append(held, item.GetPackage())
		}
	}
	return held
}

func link(record *inventoryv1.Record, name string) *inventoryv1.NetworkInterface {
	for _, item := range record.GetItems() {
		if item.GetNetworkInterface().GetName() == name {
			return item.GetNetworkInterface()
		}
	}
	return nil
}

// probes builds the package the gate installs, upgrades and purges, at two
// versions of one source package, each holding one file.
func (g *gate) probes(t *testing.T) map[string]string {
	t.Helper()
	built := map[string]string{}
	for _, version := range []string{"1.0", "2.0"} {
		root := filepath.Join(g.scratch, "probe-"+version)
		for _, directory := range []string{filepath.Join(root, "DEBIAN"), filepath.Join(root, "usr/share/doc", probePackage)} {
			if err := os.MkdirAll(directory, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		place(t, filepath.Join(root, "usr/share/doc", probePackage, "probe"), []byte("taken stock of by the native gate\n"))
		place(t, filepath.Join(root, "DEBIAN/control"), fmt.Appendf(nil, "Package: %s\nVersion: %s\nArchitecture: all\nMaintainer: Seagull native gate <gate@seagull.invalid>\nSource: %s\nInstalled-Size: 4\nDescription: what the native gate installs to see the agent take stock of it\n",
			probePackage, version, probeSource))
		built[version] = filepath.Join(g.scratch, probePackage+"_"+version+"_all.deb")
		run(t, "dpkg-deb", "--root-owner-group", "--build", root, built[version])
	}
	return built
}

// observe reads the host again, as the agent's adapters read it, right after
// the agent delivered what it took in a round, and holds it with the records
// of that round. When the evidence is recorded, every record must come out of
// what was read again byte for byte, so the host did not change in between.
func (g *gate) observe(t *testing.T, name, changed string, records map[string]*inventoryv1.Record) round {
	t.Helper()
	seen, err := readHost(t.Context(), inventory.System())
	if err != nil {
		t.Fatalf("read the host as the agent does: %v", err)
	}
	held := round{Name: name, Changed: changed, Observed: seen}
	for _, kind := range stocked {
		record := records[kind]
		if record == nil {
			continue
		}
		held.Records = append(held.Records, map[string]string{"kind": kind, "record_id": record.GetRecordId(), "collected_at": record.GetCollectedAt().AsTime().Format(time.RFC3339Nano)})
		if *evidence == "" {
			continue
		}
		again, err := inventory.Take(t.Context(), recorded{seen}, g.installation, record.GetKind(), record.GetCollectedAt().AsTime())
		if err != nil {
			t.Fatalf("take the %s again from what was read: %v", kind, err)
		}
		if !proto.Equal(again.Record, record) {
			t.Fatalf("the %s the agent delivered in round %s is not what the host holds a moment later:\n%v\n%v", kind, name, record, again.Record)
		}
	}
	return held
}

func readHost(ctx context.Context, host inventory.Host) (observed, error) {
	var seen observed
	var err error
	seen.Hostname, _ = host.Hostname()
	if seen.Release, err = host.Distribution(); err != nil {
		return observed{}, err
	}
	if seen.Kernel, err = host.Kernel(); err != nil {
		return observed{}, err
	}
	if seen.Hardware, err = host.Hardware(); err != nil {
		return observed{}, err
	}
	if seen.Packages, err = host.Packages(ctx); err != nil {
		return observed{}, err
	}
	if seen.Services, err = host.Services(ctx); err != nil {
		return observed{}, err
	}
	if seen.Interfaces, err = host.Interfaces(); err != nil {
		return observed{}, err
	}
	seen.Accounts, err = host.Accounts()
	return seen, err
}

type recorded struct{ observed }

func (r recorded) Hostname() (string, error)                        { return r.observed.Hostname, nil }
func (r recorded) Distribution() (machine.Release, error)           { return r.Release, nil }
func (r recorded) Kernel() (machine.Kernel, error)                  { return r.observed.Kernel, nil }
func (r recorded) Hardware() (machine.Hardware, error)              { return r.observed.Hardware, nil }
func (r recorded) Interfaces() ([]interfaces.Interface, error)      { return r.observed.Interfaces, nil }
func (r recorded) Accounts() (accounts.Database, error)             { return r.observed.Accounts, nil }
func (r recorded) Packages(context.Context) ([]dpkg.Package, error) { return r.observed.Packages, nil }
func (r recorded) Services(context.Context) ([]services.Service, error) {
	return r.observed.Services, nil
}
func (recorded) Processes(context.Context) ([]processes.Process, error) {
	return nil, fmt.Errorf("the processes of the host are not read again: %w", errors.ErrUnsupported)
}

func (g *gate) inventoried(t *testing.T, rounds []round) {
	t.Helper()
	directory := filepath.Join(*evidence, "inventory")
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	_, batches := g.platform.inventories()
	for i, batch := range batches {
		if err := os.WriteFile(filepath.Join(directory, fmt.Sprintf("batch-%03d.pb", i)), batch, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	systemd := strings.SplitN(run(t, "systemctl", "--version"), "\n", 2)[0]
	release := run(t, "sh", "-c", ". /etc/os-release && echo $PRETTY_NAME")
	scenario := map[string]any{
		"recorded_at":     time.Now().UTC(),
		"build":           run(t, agentPath, "-version"),
		"installation_id": g.installation,
		"agent_id":        agentID,
		"host":            map[string]string{"os": release, "systemd": systemd, "dpkg": strings.SplitN(run(t, "dpkg", "--version"), "\n", 2)[0]},
		"probe":           map[string]string{"package": probePackage, "source": probeSource, "account": probeAccount, "interface": probeLink, "service": probeUnit},
		"batches":         len(batches),
		"rounds":          rounds,
	}
	written, err := json.MarshalIndent(scenario, "", "  ")
	if err == nil {
		err = os.WriteFile(filepath.Join(directory, "scenario.json"), append(written, '\n'), 0o644)
	}
	if err != nil {
		t.Fatal(err)
	}
}
