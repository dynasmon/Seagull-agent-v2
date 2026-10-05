package inventory

import (
	"context"
	"os"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/dynasmon/Seagull-agent-v2/internal/platform/accounts"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/dpkg"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/interfaces"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/machine"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/services"
	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
)

const (
	manager    = "dpkg"
	cut        = "..."
	maxDisplay = 256
)

// Host is what the collector reads of the machine it runs on, each kind
// through the platform adapter that owns its source.
type Host interface {
	Hostname() (string, error)
	Distribution() (machine.Release, error)
	Kernel() (machine.Kernel, error)
	Hardware() (machine.Hardware, error)
	Packages(ctx context.Context) ([]dpkg.Package, error)
	Services(ctx context.Context) ([]services.Service, error)
	Interfaces() ([]interfaces.Interface, error)
	Accounts() (accounts.Database, error)
}

type system struct{}

func System() Host { return system{} }

func (system) Hostname() (string, error)                            { return os.Hostname() }
func (system) Distribution() (machine.Release, error)               { return machine.Distribution() }
func (system) Kernel() (machine.Kernel, error)                      { return machine.Running() }
func (system) Hardware() (machine.Hardware, error)                  { return machine.Described() }
func (system) Packages(ctx context.Context) ([]dpkg.Package, error) { return dpkg.Installed(ctx) }
func (system) Services(ctx context.Context) ([]services.Service, error) {
	return services.List(ctx)
}
func (system) Interfaces() ([]interfaces.Interface, error) { return interfaces.List() }
func (system) Accounts() (accounts.Database, error)        { return accounts.Read() }

type taker struct {
	kind   inventoryv1.Kind
	source string
	take   func(ctx context.Context, host Host) ([]*inventoryv1.Item, int, error)
}

var kinds = []taker{
	{kind: inventoryv1.Kind_KIND_OPERATING_SYSTEM, source: "os-release", take: takeDistribution},
	{kind: inventoryv1.Kind_KIND_KERNEL, source: "uname", take: takeKernel},
	{kind: inventoryv1.Kind_KIND_HARDWARE, source: "procfs", take: takeHardware},
	{kind: inventoryv1.Kind_KIND_PACKAGE, source: "dpkg", take: takePackages},
	{kind: inventoryv1.Kind_KIND_SERVICE, source: "systemd", take: takeServices},
	{kind: inventoryv1.Kind_KIND_NETWORK_INTERFACE, source: "sysfs", take: takeInterfaces},
	{kind: inventoryv1.Kind_KIND_USER, source: "passwd", take: takeAccounts},
}

func takeDistribution(_ context.Context, host Host) ([]*inventoryv1.Item, int, error) {
	release, err := host.Distribution()
	if err != nil {
		return nil, 0, err
	}
	family := release.ID
	if len(release.Like) > 0 {
		family = release.Like[0]
	}
	return []*inventoryv1.Item{{Body: &inventoryv1.Item_OperatingSystem{OperatingSystem: &inventoryv1.OperatingSystem{
		Name: shown(release.Name), Version: release.Version, Build: release.Build, Platform: release.ID, Codename: release.Codename, Family: family,
	}}}}, 0, nil
}

func takeKernel(_ context.Context, host Host) ([]*inventoryv1.Item, int, error) {
	booted, err := host.Kernel()
	if err != nil {
		return nil, 0, err
	}
	return []*inventoryv1.Item{{Body: &inventoryv1.Item_Kernel{Kernel: &inventoryv1.Kernel{
		Name: booted.Name, Release: booted.Release, Version: booted.Version, Architecture: booted.Machine,
	}}}}, 0, nil
}

func takeHardware(_ context.Context, host Host) ([]*inventoryv1.Item, int, error) {
	made, err := host.Hardware()
	if err != nil {
		return nil, 0, err
	}
	return []*inventoryv1.Item{{Body: &inventoryv1.Item_Hardware{Hardware: &inventoryv1.Hardware{
		CpuName: shown(made.CPU), CpuCores: made.Cores, CpuMhz: made.MHz, MemoryTotalBytes: made.Memory, Vendor: shown(made.Vendor), Model: shown(made.Model),
	}}}}, 0, nil
}

// A package's source is the source package dpkg built it from, with the
// version it was built at, as dpkg writes a Source field: the name and the
// version a distribution's advisories speak of, which a binary's may not be.
func takePackages(ctx context.Context, host Host) ([]*inventoryv1.Item, int, error) {
	installed, err := host.Packages(ctx)
	if err != nil {
		return nil, 0, err
	}
	items := make([]*inventoryv1.Item, 0, len(installed))
	for _, held := range installed {
		source := held.Source
		if held.SourceVersion != "" {
			source += " (" + held.SourceVersion + ")"
		}
		items = append(items, &inventoryv1.Item{Body: &inventoryv1.Item_Package{Package: &inventoryv1.Package{
			Name: held.Name, Version: held.Version, Architecture: held.Architecture, Manager: manager, Source: source, SizeBytes: held.InstalledKiB << 10,
		}}})
	}
	return items, 0, nil
}

func takeServices(ctx context.Context, host Host) ([]*inventoryv1.Item, int, error) {
	listed, err := host.Services(ctx)
	if err != nil {
		return nil, 0, err
	}
	items := make([]*inventoryv1.Item, 0, len(listed))
	for _, held := range listed {
		state := inventoryv1.Service_STATE_UNSPECIFIED
		switch held.Active {
		case "active", "reloading", "refreshing":
			state = inventoryv1.Service_STATE_RUNNING
		case "inactive":
			state = inventoryv1.Service_STATE_STOPPED
		case "failed":
			state = inventoryv1.Service_STATE_FAILED
		}
		items = append(items, &inventoryv1.Item{Body: &inventoryv1.Item_Service{Service: &inventoryv1.Service{
			Name: held.Name, DisplayName: shown(held.Description), State: state, StartMode: held.File,
		}}})
	}
	return items, 0, nil
}

func takeInterfaces(_ context.Context, host Host) ([]*inventoryv1.Item, int, error) {
	listed, err := host.Interfaces()
	if err != nil {
		return nil, 0, err
	}
	items := make([]*inventoryv1.Item, 0, len(listed))
	for _, held := range listed {
		state := inventoryv1.NetworkInterface_STATE_DOWN
		if held.Up {
			state = inventoryv1.NetworkInterface_STATE_UP
		}
		addresses := make([]string, 0, len(held.Addresses))
		for _, address := range held.Addresses {
			addresses = append(addresses, address.String())
		}
		items = append(items, &inventoryv1.Item{Body: &inventoryv1.Item_NetworkInterface{NetworkInterface: &inventoryv1.NetworkInterface{
			Name: held.Name, Mac: held.MAC, Addresses: addresses, State: state, Mtu: held.MTU, Type: held.Type,
		}}})
	}
	return items, 0, nil
}

// An account belongs to the group its own gid names and to every group that
// lists it as a member, each named once, by name.
func takeAccounts(_ context.Context, host Host) ([]*inventoryv1.Item, int, error) {
	held, err := host.Accounts()
	if err != nil {
		return nil, 0, err
	}
	primary := map[uint32]string{}
	member := map[string][]string{}
	for _, group := range held.Groups {
		if _, named := primary[group.GID]; !named {
			primary[group.GID] = group.Name
		}
		for _, name := range group.Members {
			member[name] = append(member[name], group.Name)
		}
	}
	items := make([]*inventoryv1.Item, 0, len(held.Accounts))
	for _, account := range held.Accounts {
		groups := slices.Clone(member[account.Name])
		if name, named := primary[account.GID]; named {
			groups = append(groups, name)
		}
		slices.Sort(groups)
		items = append(items, &inventoryv1.Item{Body: &inventoryv1.Item_User{User: &inventoryv1.User{
			Name: account.Name, Uid: strconv.FormatUint(uint64(account.UID), 10), Gid: strconv.FormatUint(uint64(account.GID), 10),
			Home: account.Home, Shell: account.Shell, Groups: slices.Compact(groups),
		}}})
	}
	return items, held.Skipped, nil
}

// shown is text the host describes something with, as the platform keeps it:
// a description is no identity, so one longer than the platform takes is cut
// rather than lose the whole kind it belongs to, and what is not UTF-8 is
// replaced rather than refused.
func shown(text string) string {
	text = strings.ToValidUTF8(text, "\uFFFD")
	if len(text) <= maxDisplay {
		return text
	}
	held := text[:maxDisplay-len(cut)]
	for !utf8.ValidString(held) {
		held = held[:len(held)-1]
	}
	return held + cut
}
