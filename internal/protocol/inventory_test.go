package protocol

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
)

func snapshot(kind inventoryv1.Kind, items ...*inventoryv1.Item) *inventoryv1.Record {
	return &inventoryv1.Record{
		RecordId:      "0b6f6c55-0d55-8c0e-9b55-6a0f2b8a9e11",
		SchemaVersion: InventorySchemaVersion,
		Kind:          kind,
		Mode:          inventoryv1.Mode_MODE_SNAPSHOT,
		CollectedAt:   timestamppb.New(time.Date(2026, 10, 5, 13, 0, 0, 0, time.UTC)),
		Origin:        &eventv1.Origin{Host: &eventv1.Host{Hostname: "web-01", Os: "linux", Architecture: "amd64"}},
		Collection:    &eventv1.Collection{Collector: "inventory", Source: "dpkg"},
		Items:         items,
	}
}

func installed(name string) *inventoryv1.Item {
	return &inventoryv1.Item{Body: &inventoryv1.Item_Package{Package: &inventoryv1.Package{Name: name, Version: "1.0-1", Architecture: "amd64", Manager: "dpkg", Source: name + " (1.0-1)"}}}
}

func account(name, uid string, groups ...string) *inventoryv1.Item {
	return &inventoryv1.Item{Body: &inventoryv1.Item_User{User: &inventoryv1.User{Name: name, Uid: uid, Gid: uid, Home: "/home/" + name, Shell: "/bin/sh", Groups: groups}}}
}

func adapter(name string, addresses ...string) *inventoryv1.Item {
	return &inventoryv1.Item{Body: &inventoryv1.Item_NetworkInterface{NetworkInterface: &inventoryv1.NetworkInterface{
		Name: name, Mac: "00:0c:29:22:5b:23", Addresses: addresses, State: inventoryv1.NetworkInterface_STATE_UP, Mtu: 1500, Type: "ether",
	}}}
}

func TestARecordOfEveryKindTheAgentSendsIsAdmissible(t *testing.T) {
	for _, record := range []*inventoryv1.Record{
		snapshot(inventoryv1.Kind_KIND_OPERATING_SYSTEM, &inventoryv1.Item{Body: &inventoryv1.Item_OperatingSystem{OperatingSystem: &inventoryv1.OperatingSystem{
			Name: "Ubuntu", Version: "24.04", Platform: "ubuntu", Codename: "noble", Family: "debian"}}}),
		snapshot(inventoryv1.Kind_KIND_KERNEL, &inventoryv1.Item{Body: &inventoryv1.Item_Kernel{Kernel: &inventoryv1.Kernel{
			Name: "Linux", Release: "6.8.0-45-generic", Version: "#45-Ubuntu SMP PREEMPT_DYNAMIC", Architecture: "x86_64"}}}),
		snapshot(inventoryv1.Kind_KIND_HARDWARE, &inventoryv1.Item{Body: &inventoryv1.Item_Hardware{Hardware: &inventoryv1.Hardware{
			CpuName: "AMD Ryzen 7 5700X 8-Core Processor", CpuCores: 8, CpuMhz: 3394, MemoryTotalBytes: 16 << 30, Vendor: "VMware, Inc.", Model: "VMware Virtual Platform"}}}),
		snapshot(inventoryv1.Kind_KIND_PACKAGE, installed("openssl"), installed("libssl3")),
		snapshot(inventoryv1.Kind_KIND_SERVICE, &inventoryv1.Item{Body: &inventoryv1.Item_Service{Service: &inventoryv1.Service{
			Name: "ssh.service", DisplayName: "OpenBSD Secure Shell server", State: inventoryv1.Service_STATE_RUNNING, StartMode: "enabled"}}},
			&inventoryv1.Item{Body: &inventoryv1.Item_Service{Service: &inventoryv1.Service{Name: "odd.service"}}}),
		snapshot(inventoryv1.Kind_KIND_NETWORK_INTERFACE, adapter("lo", "127.0.0.1/8", "::1/128"), adapter("ens33", "192.168.132.128", "fe80::20c:29ff:fe22:5b23/64")),
		snapshot(inventoryv1.Kind_KIND_USER, account("root", "0", "root"), account("seagull-agent", "997", "seagull-agent", "systemd-journal")),
		snapshot(inventoryv1.Kind_KIND_PACKAGE),
	} {
		if err := CheckInventory(record); err != nil {
			t.Errorf("a %s record was refused: %v", record.GetKind(), err)
		}
	}
}

func TestWhatThePlatformRefusesOfARecordIsRefusedNamingTheField(t *testing.T) {
	over := func(bound int) string { return strings.Repeat("x", bound+1) }
	addresses := make([]string, MaxInterfaceAddresses+1)
	for i := range addresses {
		addresses[i] = fmt.Sprintf("10.0.%d.%d/16", i/256, i%256)
	}
	groups := make([]string, MaxAccountGroups+1)
	for i := range groups {
		groups[i] = fmt.Sprintf("group%d", i)
	}
	many := make([]*inventoryv1.Item, MaxInventoryItemsPerRecord+1)
	for i := range many {
		many[i] = installed(fmt.Sprintf("package%d", i))
	}
	delta := snapshot(inventoryv1.Kind_KIND_PACKAGE)
	delta.Mode = inventoryv1.Mode_MODE_DELTA
	unmoded := snapshot(inventoryv1.Kind_KIND_PACKAGE, installed("a"))
	unmoded.Mode = inventoryv1.Mode_MODE_UNSPECIFIED
	undated := snapshot(inventoryv1.Kind_KIND_PACKAGE, installed("a"))
	undated.CollectedAt = nil
	unnamed := snapshot(inventoryv1.Kind_KIND_PACKAGE, installed("a"))
	unnamed.Collection = nil
	hosted := snapshot(inventoryv1.Kind_KIND_PACKAGE, installed("a"))
	hosted.Origin.Host.Hostname = over(maxHostname)
	addressed := snapshot(inventoryv1.Kind_KIND_PACKAGE, installed("a"))
	addressed.Origin.Host.Ip = "10.0.0.300"
	stated := snapshot(inventoryv1.Kind_KIND_SERVICE, &inventoryv1.Item{Body: &inventoryv1.Item_Service{Service: &inventoryv1.Service{Name: "ssh.service", State: 9}}})

	for name, refused := range map[string]struct {
		record *inventoryv1.Record
		field  string
	}{
		"an undeclared kind":          {record: snapshot(inventoryv1.Kind_KIND_UNSPECIFIED, installed("a")), field: "kind"},
		"an unstated mode":            {record: unmoded, field: "mode"},
		"an empty delta":              {record: delta, field: "items"},
		"too many items":              {record: snapshot(inventoryv1.Kind_KIND_PACKAGE, many...), field: "items"},
		"two kernels":                 {record: snapshot(inventoryv1.Kind_KIND_KERNEL, &inventoryv1.Item{Body: &inventoryv1.Item_Kernel{Kernel: &inventoryv1.Kernel{Name: "Linux"}}}, &inventoryv1.Item{Body: &inventoryv1.Item_Kernel{Kernel: &inventoryv1.Kernel{Name: "Linux"}}}), field: "items"},
		"no moment":                   {record: undated, field: "collected_at"},
		"no collector":                {record: unnamed, field: "collection.collector"},
		"a host name too long":        {record: hosted, field: "origin.host.hostname"},
		"a host address that is none": {record: addressed, field: "origin.host.ip"},
		"a body of another kind":      {record: snapshot(inventoryv1.Kind_KIND_SERVICE, installed("a")), field: "items[0]"},
		"a package with no name":      {record: snapshot(inventoryv1.Kind_KIND_PACKAGE, installed("a"), installed("")), field: "items[1].package.name"},
		"a package name too long":     {record: snapshot(inventoryv1.Kind_KIND_PACKAGE, installed(over(maxInventoryName))), field: "items[0].package.name"},
		"a source that is not text":   {record: snapshot(inventoryv1.Kind_KIND_PACKAGE, installed("\xff\xfe")), field: "items[0].package.name"},
		"an undeclared service state": {record: stated, field: "items[0].service.state"},
		"too many addresses":          {record: snapshot(inventoryv1.Kind_KIND_NETWORK_INTERFACE, adapter("lo", addresses...)), field: "items[0].network_interface.addresses"},
		"an address that is none":     {record: snapshot(inventoryv1.Kind_KIND_NETWORK_INTERFACE, adapter("lo", "127.0.0.1/8", "localhost")), field: "items[0].network_interface.addresses[1]"},
		"too many groups":             {record: snapshot(inventoryv1.Kind_KIND_USER, account("root", "0", groups...)), field: "items[0].user.groups"},
		"an empty group":              {record: snapshot(inventoryv1.Kind_KIND_USER, account("root", "0", "root", "")), field: "items[0].user.groups[1]"},
		"a home over a path":          {record: snapshot(inventoryv1.Kind_KIND_USER, &inventoryv1.Item{Body: &inventoryv1.Item_User{User: &inventoryv1.User{Name: "a", Home: over(maxPath)}}}), field: "items[0].user.home"},
		"a system with no name":       {record: snapshot(inventoryv1.Kind_KIND_OPERATING_SYSTEM, &inventoryv1.Item{Body: &inventoryv1.Item_OperatingSystem{OperatingSystem: &inventoryv1.OperatingSystem{Version: "24.04"}}}), field: "items[0].operating_system.name"},
		"a family too long":           {record: snapshot(inventoryv1.Kind_KIND_OPERATING_SYSTEM, &inventoryv1.Item{Body: &inventoryv1.Item_OperatingSystem{OperatingSystem: &inventoryv1.OperatingSystem{Name: "Rocky", Family: over(maxFamily)}}}), field: "items[0].operating_system.family"},
		"a hardware model too long":   {record: snapshot(inventoryv1.Kind_KIND_HARDWARE, &inventoryv1.Item{Body: &inventoryv1.Item_Hardware{Hardware: &inventoryv1.Hardware{Model: over(maxModel)}}}), field: "items[0].hardware.model"},
	} {
		err := CheckInventory(refused.record)
		var inadmissible *Inadmissible
		if !errors.As(err, &inadmissible) || inadmissible.Field != refused.field {
			t.Errorf("%s: the record was judged %v, want a refusal of %s", name, err, refused.field)
		}
	}
}

func TestEveryBoundAdmitsWhatReachesIt(t *testing.T) {
	at := func(bound int) string { return strings.Repeat("x", bound) }
	addresses := make([]string, MaxInterfaceAddresses)
	for i := range addresses {
		addresses[i] = fmt.Sprintf("ffff:ffff:ffff:ffff:ffff:ffff:%d.%d.255.255/128", i/256, i%256)
	}
	groups := make([]string, MaxAccountGroups)
	for i := range groups {
		groups[i] = at(maxInventoryName)
	}
	many := make([]*inventoryv1.Item, MaxInventoryItemsPerRecord)
	for i := range many {
		many[i] = &inventoryv1.Item{Body: &inventoryv1.Item_Package{Package: &inventoryv1.Package{
			Name: at(maxInventoryName), Version: at(maxVersion), Architecture: at(maxArchitecture), Manager: at(maxManager), Source: at(maxSource), Vendor: at(maxVendor)}}}
	}
	for _, record := range []*inventoryv1.Record{
		snapshot(inventoryv1.Kind_KIND_PACKAGE, many...),
		snapshot(inventoryv1.Kind_KIND_NETWORK_INTERFACE, adapter(at(maxInventoryName), addresses...)),
		snapshot(inventoryv1.Kind_KIND_USER, &inventoryv1.Item{Body: &inventoryv1.Item_User{User: &inventoryv1.User{
			Name: at(maxInventoryName), Uid: at(maxAccountID), Gid: at(maxAccountID), Home: at(maxPath), Shell: at(maxPath), Groups: groups}}}),
		snapshot(inventoryv1.Kind_KIND_SERVICE, &inventoryv1.Item{Body: &inventoryv1.Item_Service{Service: &inventoryv1.Service{
			Name: at(maxInventoryName), DisplayName: at(maxDisplayName), StartMode: at(maxStartMode), Path: at(maxPath)}}}),
		snapshot(inventoryv1.Kind_KIND_OPERATING_SYSTEM, &inventoryv1.Item{Body: &inventoryv1.Item_OperatingSystem{OperatingSystem: &inventoryv1.OperatingSystem{
			Name: at(maxInventoryName), Version: at(maxVersion), Build: at(maxBuild), Platform: at(maxPlatform), Codename: at(maxCodename), Family: at(maxFamily)}}}),
		snapshot(inventoryv1.Kind_KIND_KERNEL, &inventoryv1.Item{Body: &inventoryv1.Item_Kernel{Kernel: &inventoryv1.Kernel{
			Name: at(maxInventoryName), Release: at(maxRelease), Version: at(maxVersion), Architecture: at(maxArchitecture)}}}),
		snapshot(inventoryv1.Kind_KIND_HARDWARE, &inventoryv1.Item{Body: &inventoryv1.Item_Hardware{Hardware: &inventoryv1.Hardware{
			CpuName: at(maxInventoryName), Serial: at(maxSerial), Vendor: at(maxVendor), Model: at(maxModel)}}}),
	} {
		if err := CheckInventory(record); err != nil {
			t.Errorf("a %s record at its bounds was refused: %v", record.GetKind(), err)
		}
	}
	if encoded, err := proto.Marshal(snapshot(inventoryv1.Kind_KIND_PACKAGE, many...)); err != nil || len(encoded) <= MaxInventoryRecordBytes {
		t.Errorf("items at every bound encode to %d bytes and %v: the item ceiling alone would keep a record under the one the backbone carries", len(encoded), err)
	}
}

func TestThePlatformIdentifiesAnItemByWhatADR27Names(t *testing.T) {
	upgraded := installed("openssl")
	upgraded.GetPackage().Version = "3.0.13-0ubuntu3.4"
	for name, identity := range map[string]struct {
		kind  inventoryv1.Kind
		item  *inventoryv1.Item
		parts []string
	}{
		"a package":                  {kind: inventoryv1.Kind_KIND_PACKAGE, item: upgraded, parts: []string{"openssl", "amd64", "dpkg"}},
		"an account":                 {kind: inventoryv1.Kind_KIND_USER, item: account("toor", "0"), parts: []string{"0"}},
		"an account without a uid":   {kind: inventoryv1.Kind_KIND_USER, item: account("nobody", ""), parts: []string{"nobody"}},
		"an interface":               {kind: inventoryv1.Kind_KIND_NETWORK_INTERFACE, item: adapter("ens33"), parts: []string{"ens33"}},
		"a service":                  {kind: inventoryv1.Kind_KIND_SERVICE, item: &inventoryv1.Item{Body: &inventoryv1.Item_Service{Service: &inventoryv1.Service{Name: "ssh.service"}}}, parts: []string{"ssh.service"}},
		"the one kernel of an asset": {kind: inventoryv1.Kind_KIND_KERNEL, item: &inventoryv1.Item{Body: &inventoryv1.Item_Kernel{Kernel: &inventoryv1.Kernel{Name: "Linux"}}}},
		"a process": {kind: inventoryv1.Kind_KIND_PROCESS, item: &inventoryv1.Item{Body: &inventoryv1.Item_Process{Process: &inventoryv1.Process{
			Pid: 42, StartedAt: timestamppb.New(time.Unix(1, 5))}}}, parts: []string{"42", "1000000005"}},
	} {
		if got := InventoryIdentity(identity.kind, identity.item); !slices.Equal(got, identity.parts) {
			t.Errorf("%s is identified by %q, want %q", name, got, identity.parts)
		}
	}
}
