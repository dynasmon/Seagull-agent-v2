package inventory_test

import (
	"context"
	"errors"
	"net/netip"
	"runtime"
	"slices"
	"strings"
	"sync"
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
	"github.com/dynasmon/Seagull-agent-v2/internal/protocol"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
)

const installation = "6a0f2b8a-9e11-4b6f-8c55-0d550b6f6c55"

// A host the test describes, as each platform adapter would read it, which
// the test can change between two rounds of the collector.
type fakeHost struct {
	mu         sync.Mutex
	hostname   string
	release    machine.Release
	kernel     machine.Kernel
	hardware   machine.Hardware
	packages   []dpkg.Package
	services   []services.Service
	interfaces []interfaces.Interface
	accounts   accounts.Database
	processes  []processes.Process
	failures   map[string]error
}

func newHost() *fakeHost {
	return &fakeHost{
		hostname: "web-01",
		release:  machine.Release{ID: "ubuntu", Like: []string{"debian"}, Name: "Ubuntu", Version: "24.04", Codename: "noble"},
		kernel:   machine.Kernel{Name: "Linux", Release: "6.8.0-45-generic", Version: "#45-Ubuntu SMP PREEMPT_DYNAMIC Fri Aug 30 12:02:04 UTC 2024", Machine: "x86_64"},
		hardware: machine.Hardware{CPU: "AMD Ryzen 7 5700X 8-Core Processor", Cores: 8, MHz: 3394, Memory: 16 << 30, Vendor: "VMware, Inc.", Model: "VMware Virtual Platform"},
		packages: []dpkg.Package{
			{Name: "openssl", Version: "3.0.13-0ubuntu3.4", Architecture: "amd64", Source: "openssl", SourceVersion: "3.0.13-0ubuntu3.4", InstalledKiB: 2111, Status: "installed"},
			{Name: "libssl3t64", Version: "3.0.13-0ubuntu3.4", Architecture: "amd64", Source: "openssl", SourceVersion: "3.0.13-0ubuntu3.4", InstalledKiB: 6372, Status: "installed"},
			{Name: "libc6", Version: "2.39-0ubuntu8.3", Architecture: "i386", Source: "glibc", SourceVersion: "2.39-0ubuntu8.3", InstalledKiB: 12345, Status: "installed"},
			{Name: "libc6", Version: "2.39-0ubuntu8.3", Architecture: "amd64", Source: "glibc", SourceVersion: "2.39-0ubuntu8.3", InstalledKiB: 13608, Status: "installed"},
		},
		services: []services.Service{
			{Name: "ssh.service", Description: "OpenBSD Secure Shell server", Load: "loaded", Active: "active", Sub: "running", File: "enabled"},
			{Name: "cron.service", Active: "inactive", Sub: "dead", File: "disabled"},
		},
		interfaces: []interfaces.Interface{
			{Name: "lo", Index: 1, MAC: "00:00:00:00:00:00", MTU: 65536, Up: true, Type: "loopback", Addresses: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/8"), netip.MustParsePrefix("::1/128")}},
			{Name: "ens33", Index: 2, MAC: "00:0c:29:22:5b:23", MTU: 1500, Up: true, Type: "ether", Addresses: []netip.Prefix{netip.MustParsePrefix("192.168.132.128/24")}},
		},
		accounts: accounts.Database{
			Accounts: []accounts.Account{{Name: "root", Home: "/root", Shell: "/bin/bash"}, {Name: "seagull-agent", UID: 997, GID: 997, Home: "/", Shell: "/usr/sbin/nologin"}},
			Groups:   []accounts.Group{{Name: "root"}, {Name: "systemd-journal", GID: 999, Members: []string{"seagull-agent"}}, {Name: "seagull-agent", GID: 997}},
		},
		processes: []processes.Process{
			{PID: 1, Name: "systemd", StartedAt: booted.Add(2 * time.Second)},
			{PID: 2, Name: "kthreadd", StartedAt: booted.Add(2 * time.Second)},
			{PID: 812, Parent: 1, Name: "sshd", StartedAt: booted.Add(9 * time.Second)},
			{PID: 4242, Parent: 1, User: 997, Name: "seagull-agent", StartedAt: booted.Add(time.Hour), Executable: "/usr/bin/seagull-agent"},
		},
		failures: map[string]error{},
	}
}

var booted = time.Date(2026, 10, 6, 9, 0, 0, 0, time.UTC)

func (h *fakeHost) change(change func(*fakeHost)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	change(h)
}

func (h *fakeHost) Hostname() (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.hostname, nil
}

func (h *fakeHost) Distribution() (machine.Release, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.release, h.failures["operating_system"]
}

func (h *fakeHost) Kernel() (machine.Kernel, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.kernel, h.failures["kernel"]
}

func (h *fakeHost) Hardware() (machine.Hardware, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.hardware, h.failures["hardware"]
}

func (h *fakeHost) Packages(context.Context) ([]dpkg.Package, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.packages), h.failures["package"]
}

func (h *fakeHost) Services(context.Context) ([]services.Service, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.services), h.failures["service"]
}

func (h *fakeHost) Interfaces() ([]interfaces.Interface, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.interfaces), h.failures["network_interface"]
}

func (h *fakeHost) Accounts() (accounts.Database, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.accounts, h.failures["user"]
}

func (h *fakeHost) Processes(context.Context) ([]processes.Process, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.processes), h.failures["process"]
}

func taken(t *testing.T, host inventory.Host, kind inventoryv1.Kind, at time.Time) inventory.Snapshot {
	t.Helper()
	held, err := inventory.Take(t.Context(), host, installation, kind, at)
	if err != nil {
		t.Fatalf("take the %s: %v", inventory.KindName(kind), err)
	}
	return held
}

func TestEachKindIsWhatItsSourceSaysOfTheHost(t *testing.T) {
	at := time.Date(2026, 10, 5, 13, 0, 0, 123456789, time.UTC)
	host := newHost()
	host.services = append(host.services,
		services.Service{Name: "failing.service", Description: "Fails", Load: "loaded", Active: "failed", Sub: "failed", File: "static"},
		services.Service{Name: "starting.service", Description: "Starts", Load: "loaded", Active: "activating", Sub: "auto-restart"},
		services.Service{Name: "oneshot.service", Description: "Ran once", Load: "loaded", Active: "active", Sub: "exited", File: "enabled"},
		services.Service{Name: "nginx.service", Description: "nginx", Load: "loaded", Active: "reloading", Sub: "reload"})
	host.interfaces[1].Up = false
	for kind, want := range map[inventoryv1.Kind][]*inventoryv1.Item{
		inventoryv1.Kind_KIND_OPERATING_SYSTEM: {{Body: &inventoryv1.Item_OperatingSystem{OperatingSystem: &inventoryv1.OperatingSystem{
			Name: "Ubuntu", Version: "24.04", Platform: "ubuntu", Codename: "noble", Family: "debian"}}}},
		inventoryv1.Kind_KIND_KERNEL: {{Body: &inventoryv1.Item_Kernel{Kernel: &inventoryv1.Kernel{
			Name: "Linux", Release: "6.8.0-45-generic", Version: "#45-Ubuntu SMP PREEMPT_DYNAMIC Fri Aug 30 12:02:04 UTC 2024", Architecture: "x86_64"}}}},
		inventoryv1.Kind_KIND_HARDWARE: {{Body: &inventoryv1.Item_Hardware{Hardware: &inventoryv1.Hardware{
			CpuName: "AMD Ryzen 7 5700X 8-Core Processor", CpuCores: 8, CpuMhz: 3394, MemoryTotalBytes: 16 << 30, Vendor: "VMware, Inc.", Model: "VMware Virtual Platform"}}}},
		inventoryv1.Kind_KIND_PACKAGE: {
			{Body: &inventoryv1.Item_Package{Package: &inventoryv1.Package{Name: "libc6", Version: "2.39-0ubuntu8.3", Architecture: "amd64", Manager: "dpkg", Source: "glibc (2.39-0ubuntu8.3)", SizeBytes: 13608 << 10}}},
			{Body: &inventoryv1.Item_Package{Package: &inventoryv1.Package{Name: "libc6", Version: "2.39-0ubuntu8.3", Architecture: "i386", Manager: "dpkg", Source: "glibc (2.39-0ubuntu8.3)", SizeBytes: 12345 << 10}}},
			{Body: &inventoryv1.Item_Package{Package: &inventoryv1.Package{Name: "libssl3t64", Version: "3.0.13-0ubuntu3.4", Architecture: "amd64", Manager: "dpkg", Source: "openssl (3.0.13-0ubuntu3.4)", SizeBytes: 6372 << 10}}},
			{Body: &inventoryv1.Item_Package{Package: &inventoryv1.Package{Name: "openssl", Version: "3.0.13-0ubuntu3.4", Architecture: "amd64", Manager: "dpkg", Source: "openssl (3.0.13-0ubuntu3.4)", SizeBytes: 2111 << 10}}},
		},
		inventoryv1.Kind_KIND_SERVICE: {
			{Body: &inventoryv1.Item_Service{Service: &inventoryv1.Service{Name: "cron.service", State: inventoryv1.Service_STATE_STOPPED, StartMode: "disabled"}}},
			{Body: &inventoryv1.Item_Service{Service: &inventoryv1.Service{Name: "failing.service", DisplayName: "Fails", State: inventoryv1.Service_STATE_FAILED, StartMode: "static"}}},
			{Body: &inventoryv1.Item_Service{Service: &inventoryv1.Service{Name: "nginx.service", DisplayName: "nginx", State: inventoryv1.Service_STATE_RUNNING}}},
			{Body: &inventoryv1.Item_Service{Service: &inventoryv1.Service{Name: "oneshot.service", DisplayName: "Ran once", State: inventoryv1.Service_STATE_RUNNING, StartMode: "enabled"}}},
			{Body: &inventoryv1.Item_Service{Service: &inventoryv1.Service{Name: "ssh.service", DisplayName: "OpenBSD Secure Shell server", State: inventoryv1.Service_STATE_RUNNING, StartMode: "enabled"}}},
			{Body: &inventoryv1.Item_Service{Service: &inventoryv1.Service{Name: "starting.service", DisplayName: "Starts"}}},
		},
		inventoryv1.Kind_KIND_NETWORK_INTERFACE: {
			{Body: &inventoryv1.Item_NetworkInterface{NetworkInterface: &inventoryv1.NetworkInterface{
				Name: "ens33", Mac: "00:0c:29:22:5b:23", Addresses: []string{"192.168.132.128/24"}, State: inventoryv1.NetworkInterface_STATE_DOWN, Mtu: 1500, Type: "ether"}}},
			{Body: &inventoryv1.Item_NetworkInterface{NetworkInterface: &inventoryv1.NetworkInterface{
				Name: "lo", Mac: "00:00:00:00:00:00", Addresses: []string{"127.0.0.1/8", "::1/128"}, State: inventoryv1.NetworkInterface_STATE_UP, Mtu: 65536, Type: "loopback"}}},
		},
		inventoryv1.Kind_KIND_USER: {
			{Body: &inventoryv1.Item_User{User: &inventoryv1.User{Name: "root", Uid: "0", Gid: "0", Home: "/root", Shell: "/bin/bash", Groups: []string{"root"}}}},
			{Body: &inventoryv1.Item_User{User: &inventoryv1.User{Name: "seagull-agent", Uid: "997", Gid: "997", Home: "/", Shell: "/usr/sbin/nologin", Groups: []string{"seagull-agent", "systemd-journal"}}}},
		},
	} {
		held := taken(t, host, kind, at)
		record := held.Record
		if record.GetKind() != kind || record.GetMode() != inventoryv1.Mode_MODE_SNAPSHOT || record.GetSchemaVersion() != protocol.InventorySchemaVersion ||
			!record.GetCollectedAt().AsTime().Equal(at) || record.GetCollection().GetCollector() != "inventory" ||
			!proto.Equal(record.GetOrigin(), &eventv1.Origin{Host: &eventv1.Host{Hostname: "web-01", Os: runtime.GOOS, Architecture: runtime.GOARCH}}) {
			t.Errorf("the %s record is %v", inventory.KindName(kind), record)
		}
		if !slices.EqualFunc(record.GetItems(), want, func(a, b *inventoryv1.Item) bool { return proto.Equal(a, b) }) {
			t.Errorf("the %s items are\n%v\nwant\n%v", inventory.KindName(kind), record.GetItems(), want)
		}
	}
	for kind, source := range map[inventoryv1.Kind]string{
		inventoryv1.Kind_KIND_OPERATING_SYSTEM: "os-release", inventoryv1.Kind_KIND_KERNEL: "uname", inventoryv1.Kind_KIND_HARDWARE: "procfs",
		inventoryv1.Kind_KIND_PACKAGE: "dpkg", inventoryv1.Kind_KIND_SERVICE: "systemd", inventoryv1.Kind_KIND_NETWORK_INTERFACE: "sysfs", inventoryv1.Kind_KIND_USER: "passwd",
	} {
		if got := taken(t, host, kind, at).Record.GetCollection().GetSource(); got != source {
			t.Errorf("the %s is read from %q, want %q", inventory.KindName(kind), got, source)
		}
	}
}

func TestADistributionThatNamesNoRelativeIsItsOwnFamily(t *testing.T) {
	host := newHost()
	host.release = machine.Release{ID: "debian", Name: "Debian GNU/Linux", Version: "12", Codename: "bookworm"}
	system := taken(t, host, inventoryv1.Kind_KIND_OPERATING_SYSTEM, time.Now()).Record.GetItems()[0].GetOperatingSystem()
	if system.GetFamily() != "debian" || system.GetPlatform() != "debian" {
		t.Errorf("debian is described as %v", system)
	}
	host.release = machine.Release{ID: "rocky", Like: []string{"rhel", "centos", "fedora"}, Name: "Rocky Linux", Version: "9.4"}
	if system := taken(t, host, inventoryv1.Kind_KIND_OPERATING_SYSTEM, time.Now()).Record.GetItems()[0].GetOperatingSystem(); system.GetFamily() != "rhel" {
		t.Errorf("rocky is described as %v", system)
	}
}

func TestADescriptionIsCutToWhatThePlatformTakesAndAnIdentityNever(t *testing.T) {
	host := newHost()
	host.services[0].Description = strings.Repeat("é", 200)
	host.hardware.Model = "Model \xff\xfe"
	service := taken(t, host, inventoryv1.Kind_KIND_SERVICE, time.Now()).Record.GetItems()[1].GetService()
	if shown := service.GetDisplayName(); len(shown) > 256 || !strings.HasSuffix(shown, "é...") {
		t.Errorf("a description of 400 bytes is shown as %q, %d bytes", shown, len(shown))
	}
	if model := taken(t, host, inventoryv1.Kind_KIND_HARDWARE, time.Now()).Record.GetItems()[0].GetHardware().GetModel(); model != "Model \uFFFD" {
		t.Errorf("a model that is not UTF-8 is shown as %q", model)
	}
	host.services[0].Name = strings.Repeat("s", 300) + ".service"
	var inadmissible *protocol.Inadmissible
	if _, err := inventory.Take(t.Context(), host, installation, inventoryv1.Kind_KIND_SERVICE, time.Now()); !errors.As(err, &inadmissible) || inadmissible.Field != "items[1].service.name" {
		t.Errorf("a service name longer than the platform takes gave %v", err)
	}
}

func TestAnAccountBelongsToItsOwnGroupAndToEveryGroupThatListsIt(t *testing.T) {
	host := newHost()
	host.accounts = accounts.Database{
		Accounts: []accounts.Account{{Name: "alice", UID: 1000, GID: 1000, Home: "/home/alice", Shell: "/bin/bash"}, {Name: "orphan", UID: 1001, GID: 4242, Home: "/", Shell: "/bin/sh"}},
		Groups: []accounts.Group{
			{Name: "alice", GID: 1000}, {Name: "sudo", GID: 27, Members: []string{"alice"}}, {Name: "adm", GID: 4, Members: []string{"bob", "alice"}},
			{Name: "alice-again", GID: 1000, Members: []string{"alice"}}, {Name: "docker", GID: 998, Members: []string{"alice", "alice"}},
		},
	}
	items := taken(t, host, inventoryv1.Kind_KIND_USER, time.Now()).Record.GetItems()
	if groups := items[0].GetUser().GetGroups(); !slices.Equal(groups, []string{"adm", "alice", "alice-again", "docker", "sudo"}) {
		t.Errorf("alice belongs to %q", groups)
	}
	if user := items[1].GetUser(); user.GetGid() != "4242" || len(user.GetGroups()) != 0 {
		t.Errorf("an account whose group the host does not name is %v", user)
	}
}
