package protocol

import (
	"fmt"
	"net/netip"
	"strconv"
	"unicode/utf8"

	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
)

// What the recorded platform admits of an inventory record beyond the shape of
// its contract: at most MaxInventoryItemsPerRecord items, each field within the
// length its gateway checks, and, once its gateway stamped the record, no more
// than its backbone's producer carries in one record, 1,000,012 bytes, which
// MaxInventoryRecordBytes stays below with room for that stamp. A record over
// that ceiling is admitted, then never published, and answered 503 for good.
const (
	MaxInventoryItemsPerRecord = 10_000
	MaxInventoryRecordBytes    = 960 << 10
	MaxInterfaceAddresses      = 64
	MaxAccountGroups           = 256
)

const (
	maxInventoryName   = 256
	maxVersion         = 128
	maxArchitecture    = 32
	maxManager         = 32
	maxSource          = 256
	maxVendor          = 256
	maxPath            = 4096
	maxCommandLine     = 8192
	maxDisplayName     = 256
	maxStartMode       = 32
	maxBuild           = 128
	maxPlatform        = 64
	maxCodename        = 64
	maxFamily          = 32
	maxRelease         = 128
	maxSerial          = 128
	maxModel           = 256
	maxLinkType        = 32
	maxAccountID       = 192
	maxMAC             = 64
	maxInterfaceAddr   = 49
	maxHostname        = 255
	maxOperatingSystem = 128
	maxCollector       = 64
	maxCollection      = 512
	maxAddress         = 45
)

type Inadmissible struct {
	Field  string
	Reason string
}

func (i *Inadmissible) Error() string { return i.Field + " " + i.Reason }

type inventoryShape struct {
	singleton bool
	present   func(*inventoryv1.Item) bool
}

var inventoryShapes = map[inventoryv1.Kind]inventoryShape{
	inventoryv1.Kind_KIND_OPERATING_SYSTEM:  {singleton: true, present: func(item *inventoryv1.Item) bool { return item.GetOperatingSystem() != nil }},
	inventoryv1.Kind_KIND_KERNEL:            {singleton: true, present: func(item *inventoryv1.Item) bool { return item.GetKernel() != nil }},
	inventoryv1.Kind_KIND_HARDWARE:          {singleton: true, present: func(item *inventoryv1.Item) bool { return item.GetHardware() != nil }},
	inventoryv1.Kind_KIND_PACKAGE:           {present: func(item *inventoryv1.Item) bool { return item.GetPackage() != nil }},
	inventoryv1.Kind_KIND_SERVICE:           {present: func(item *inventoryv1.Item) bool { return item.GetService() != nil }},
	inventoryv1.Kind_KIND_NETWORK_INTERFACE: {present: func(item *inventoryv1.Item) bool { return item.GetNetworkInterface() != nil }},
	inventoryv1.Kind_KIND_USER:              {present: func(item *inventoryv1.Item) bool { return item.GetUser() != nil }},
	inventoryv1.Kind_KIND_PROCESS:           {present: func(item *inventoryv1.Item) bool { return item.GetProcess() != nil }},
}

// InventoryIdentity is what the recorded platform tells one item of a kind
// from another on the same asset by. It derives the identity itself and keeps
// one item for each, so two items of a record with the same identity are held
// as one: a package by its name, architecture and manager, never its version,
// and an account by its uid, or by its name when it carries no uid.
func InventoryIdentity(kind inventoryv1.Kind, item *inventoryv1.Item) []string {
	switch kind {
	case inventoryv1.Kind_KIND_PACKAGE:
		installed := item.GetPackage()
		return []string{installed.GetName(), installed.GetArchitecture(), installed.GetManager()}
	case inventoryv1.Kind_KIND_SERVICE:
		return []string{item.GetService().GetName()}
	case inventoryv1.Kind_KIND_NETWORK_INTERFACE:
		return []string{item.GetNetworkInterface().GetName()}
	case inventoryv1.Kind_KIND_USER:
		if uid := item.GetUser().GetUid(); uid != "" {
			return []string{uid}
		}
		return []string{item.GetUser().GetName()}
	case inventoryv1.Kind_KIND_PROCESS:
		started := ""
		if at := item.GetProcess().GetStartedAt(); at != nil {
			started = strconv.FormatInt(at.AsTime().UTC().UnixNano(), 10)
		}
		return []string{strconv.FormatUint(uint64(item.GetProcess().GetPid()), 10), started}
	}
	return nil
}

// CheckInventory refuses what the recorded platform would refuse of a record
// whatever moment it reached it, naming the field as the platform names it.
func CheckInventory(record *inventoryv1.Record) error {
	kind, items := record.GetKind(), record.GetItems()
	shape, shaped := inventoryShapes[kind]
	switch {
	case !shaped:
		return &Inadmissible{Field: "kind", Reason: "is not a kind the platform identifies an item of"}
	case record.GetMode() != inventoryv1.Mode_MODE_SNAPSHOT && record.GetMode() != inventoryv1.Mode_MODE_DELTA:
		return &Inadmissible{Field: "mode", Reason: "is neither a snapshot nor a delta"}
	case len(items) == 0 && record.GetMode() == inventoryv1.Mode_MODE_DELTA:
		return &Inadmissible{Field: "items", Reason: "is empty and a delta states nothing"}
	case len(items) > MaxInventoryItemsPerRecord:
		return &Inadmissible{Field: "items", Reason: fmt.Sprintf("carries %d items and the platform takes %d", len(items), MaxInventoryItemsPerRecord)}
	case shape.singleton && len(items) > 1:
		return &Inadmissible{Field: "items", Reason: fmt.Sprintf("carries %d items and an asset has one", len(items))}
	case record.GetCollectedAt() == nil || !record.GetCollectedAt().IsValid():
		return &Inadmissible{Field: "collected_at", Reason: "is not a moment"}
	}
	host := record.GetOrigin().GetHost()
	collection := record.GetCollection()
	if err := firstOf(
		text("origin.host.hostname", host.GetHostname(), maxHostname, false),
		text("origin.host.os", host.GetOs(), maxOperatingSystem, false),
		text("origin.host.architecture", host.GetArchitecture(), maxArchitecture, false),
		hostAddress(host),
		text("collection.collector", collection.GetCollector(), maxCollector, true),
		text("collection.source", collection.GetSource(), maxCollection, false),
	); err != nil {
		return err
	}
	for index, item := range items {
		field := fmt.Sprintf("items[%d]", index)
		if !shape.present(item) {
			return &Inadmissible{Field: field, Reason: "carries no body of the kind the record declares"}
		}
		if err := checkItem(field, kind, item); err != nil {
			return err
		}
	}
	return nil
}

func checkItem(field string, kind inventoryv1.Kind, item *inventoryv1.Item) error {
	switch kind {
	case inventoryv1.Kind_KIND_OPERATING_SYSTEM:
		system := item.GetOperatingSystem()
		return firstOf(
			text(field+".operating_system.name", system.GetName(), maxInventoryName, true),
			text(field+".operating_system.version", system.GetVersion(), maxVersion, false),
			text(field+".operating_system.build", system.GetBuild(), maxBuild, false),
			text(field+".operating_system.platform", system.GetPlatform(), maxPlatform, false),
			text(field+".operating_system.codename", system.GetCodename(), maxCodename, false),
			text(field+".operating_system.family", system.GetFamily(), maxFamily, false),
		)
	case inventoryv1.Kind_KIND_KERNEL:
		kernel := item.GetKernel()
		return firstOf(
			text(field+".kernel.name", kernel.GetName(), maxInventoryName, true),
			text(field+".kernel.release", kernel.GetRelease(), maxRelease, false),
			text(field+".kernel.version", kernel.GetVersion(), maxVersion, false),
			text(field+".kernel.architecture", kernel.GetArchitecture(), maxArchitecture, false),
		)
	case inventoryv1.Kind_KIND_PACKAGE:
		installed := item.GetPackage()
		return firstOf(
			text(field+".package.name", installed.GetName(), maxInventoryName, true),
			text(field+".package.version", installed.GetVersion(), maxVersion, false),
			text(field+".package.architecture", installed.GetArchitecture(), maxArchitecture, false),
			text(field+".package.manager", installed.GetManager(), maxManager, false),
			text(field+".package.source", installed.GetSource(), maxSource, false),
			text(field+".package.vendor", installed.GetVendor(), maxVendor, false),
			moment(field+".package.installed_at", installed.GetInstalledAt() == nil || installed.GetInstalledAt().IsValid()),
		)
	case inventoryv1.Kind_KIND_SERVICE:
		service := item.GetService()
		return firstOf(
			text(field+".service.name", service.GetName(), maxInventoryName, true),
			text(field+".service.display_name", service.GetDisplayName(), maxDisplayName, false),
			enumerated(field+".service.state", inventoryv1.Service_State_name[int32(service.GetState())]),
			text(field+".service.start_mode", service.GetStartMode(), maxStartMode, false),
			text(field+".service.path", service.GetPath(), maxPath, false),
		)
	case inventoryv1.Kind_KIND_NETWORK_INTERFACE:
		return checkInterface(field, item.GetNetworkInterface())
	case inventoryv1.Kind_KIND_USER:
		return checkAccount(field, item.GetUser())
	case inventoryv1.Kind_KIND_HARDWARE:
		hardware := item.GetHardware()
		return firstOf(
			text(field+".hardware.cpu_name", hardware.GetCpuName(), maxInventoryName, false),
			text(field+".hardware.serial", hardware.GetSerial(), maxSerial, false),
			text(field+".hardware.vendor", hardware.GetVendor(), maxVendor, false),
			text(field+".hardware.model", hardware.GetModel(), maxModel, false),
		)
	case inventoryv1.Kind_KIND_PROCESS:
		running := item.GetProcess()
		return firstOf(
			text(field+".process.name", running.GetName(), maxInventoryName, true),
			text(field+".process.path", running.GetPath(), maxPath, false),
			text(field+".process.command_line", running.GetCommandLine(), maxCommandLine, false),
			text(field+".process.user", running.GetUser(), maxInventoryName, false),
			moment(field+".process.started_at", running.GetStartedAt() == nil || running.GetStartedAt().IsValid()),
		)
	}
	return nil
}

func checkInterface(field string, adapter *inventoryv1.NetworkInterface) error {
	if err := firstOf(
		text(field+".network_interface.name", adapter.GetName(), maxInventoryName, true),
		text(field+".network_interface.mac", adapter.GetMac(), maxMAC, false),
		enumerated(field+".network_interface.state", inventoryv1.NetworkInterface_State_name[int32(adapter.GetState())]),
		text(field+".network_interface.type", adapter.GetType(), maxLinkType, false),
	); err != nil {
		return err
	}
	addresses := adapter.GetAddresses()
	if len(addresses) > MaxInterfaceAddresses {
		return &Inadmissible{Field: field + ".network_interface.addresses", Reason: fmt.Sprintf("carries %d addresses and the platform takes %d", len(addresses), MaxInterfaceAddresses)}
	}
	for index, written := range addresses {
		name := fmt.Sprintf("%s.network_interface.addresses[%d]", field, index)
		if err := text(name, written, maxInterfaceAddr, true); err != nil {
			return err
		}
		if _, err := netip.ParsePrefix(written); err == nil {
			continue
		}
		if _, err := netip.ParseAddr(written); err != nil {
			return &Inadmissible{Field: name, Reason: "is not an IP address or prefix"}
		}
	}
	return nil
}

func checkAccount(field string, account *inventoryv1.User) error {
	if err := firstOf(
		text(field+".user.name", account.GetName(), maxInventoryName, true),
		text(field+".user.uid", account.GetUid(), maxAccountID, false),
		text(field+".user.gid", account.GetGid(), maxAccountID, false),
		text(field+".user.home", account.GetHome(), maxPath, false),
		text(field+".user.shell", account.GetShell(), maxPath, false),
		moment(field+".user.last_login", account.GetLastLogin() == nil || account.GetLastLogin().IsValid()),
	); err != nil {
		return err
	}
	groups := account.GetGroups()
	if len(groups) > MaxAccountGroups {
		return &Inadmissible{Field: field + ".user.groups", Reason: fmt.Sprintf("carries %d groups and the platform takes %d", len(groups), MaxAccountGroups)}
	}
	for index, group := range groups {
		if err := text(fmt.Sprintf("%s.user.groups[%d]", field, index), group, maxInventoryName, true); err != nil {
			return err
		}
	}
	return nil
}

func hostAddress(host *eventv1.Host) error {
	written := host.GetIp()
	if written == "" {
		return nil
	}
	if _, err := netip.ParseAddr(written); err != nil || len(written) > maxAddress {
		return &Inadmissible{Field: "origin.host.ip", Reason: "is not an IP address"}
	}
	return nil
}

func text(field, value string, most int, required bool) error {
	switch {
	case value == "" && required:
		return &Inadmissible{Field: field, Reason: "is required"}
	case len(value) > most:
		return &Inadmissible{Field: field, Reason: fmt.Sprintf("is longer than %d bytes", most)}
	case !utf8.ValidString(value):
		return &Inadmissible{Field: field, Reason: "is not UTF-8 text"}
	}
	return nil
}

func enumerated(field, name string) error {
	if name == "" {
		return &Inadmissible{Field: field, Reason: "is not a value the contract declares"}
	}
	return nil
}

func moment(field string, valid bool) error {
	if !valid {
		return &Inadmissible{Field: field, Reason: "is not a moment"}
	}
	return nil
}

func firstOf(found ...error) error {
	for _, err := range found {
		if err != nil {
			return err
		}
	}
	return nil
}
