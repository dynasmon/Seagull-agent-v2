package inventory_test

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-agent-v2/internal/modules/inventory"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/accounts"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/dpkg"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/services"
	"github.com/dynasmon/Seagull-agent-v2/internal/protocol"
	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
)

var uuid = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-8[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func TestASnapshotIsTheSameBytesWhateverOrderTheHostListsItsItemsIn(t *testing.T) {
	at := time.Date(2026, 10, 5, 13, 0, 0, 0, time.UTC)
	host := newHost()
	first := taken(t, host, inventoryv1.Kind_KIND_PACKAGE, at)
	slices.Reverse(host.packages)
	second := taken(t, host, inventoryv1.Kind_KIND_PACKAGE, at)
	if !bytes.Equal(first.Encoded, second.Encoded) || first.Digest != second.Digest {
		t.Error("the same packages listed in another order make another snapshot")
	}
	decoded := &inventoryv1.Record{}
	if err := proto.Unmarshal(first.Encoded, decoded); err != nil || !proto.Equal(decoded, first.Record) {
		t.Errorf("the snapshot's bytes read back as %v, %v", decoded, err)
	}
}

func TestASnapshotIsNamedByTheInstallationTheKindAndTheMomentItWasTaken(t *testing.T) {
	at := time.Date(2026, 10, 5, 13, 0, 0, 0, time.UTC)
	host := newHost()
	named := taken(t, host, inventoryv1.Kind_KIND_PACKAGE, at).Record.GetRecordId()
	if !uuid.MatchString(named) {
		t.Errorf("a snapshot is named %q", named)
	}
	if again := taken(t, host, inventoryv1.Kind_KIND_PACKAGE, at).Record.GetRecordId(); again != named {
		t.Errorf("the same snapshot was named %q and %q", named, again)
	}
	others := []string{
		taken(t, host, inventoryv1.Kind_KIND_SERVICE, at).Record.GetRecordId(),
		taken(t, host, inventoryv1.Kind_KIND_PACKAGE, at.Add(time.Nanosecond)).Record.GetRecordId(),
	}
	other, err := inventory.Take(t.Context(), host, "0d550b6f-6c55-4b6f-8c55-6a0f2b8a9e11", inventoryv1.Kind_KIND_PACKAGE, at)
	if err != nil {
		t.Fatal(err)
	}
	if others = append(others, other.Record.GetRecordId()); slices.Contains(others, named) || len(slices.Compact(slices.Sorted(slices.Values(others)))) != 3 {
		t.Errorf("snapshots of another kind, moment or installation are named %v, and this one %q", others, named)
	}
}

func TestTheDigestSaysWhatTheHostHoldsAndNothingOfWhenOrUnderWhichNameItWasTaken(t *testing.T) {
	host := newHost()
	at := time.Date(2026, 10, 5, 13, 0, 0, 0, time.UTC)
	digest := taken(t, host, inventoryv1.Kind_KIND_PACKAGE, at).Digest
	if later := taken(t, host, inventoryv1.Kind_KIND_PACKAGE, at.Add(time.Hour)).Digest; later != digest {
		t.Error("an unchanged host took an hour later has another digest")
	}
	for name, change := range map[string]func(*fakeHost){
		"an upgrade": func(h *fakeHost) { h.packages[0].Version = "3.0.13-0ubuntu3.5" },
		"a removal":  func(h *fakeHost) { h.packages = h.packages[1:] },
		"an installation": func(h *fakeHost) {
			h.packages = append(h.packages, dpkg.Package{Name: "curl", Version: "8.5.0-2ubuntu10.4", Architecture: "amd64"})
		},
		"another source":    func(h *fakeHost) { h.packages[0].SourceVersion = "3.0.13-0ubuntu3.5" },
		"another host name": func(h *fakeHost) { h.hostname = "web-02" },
	} {
		changed := newHost()
		change(changed)
		if taken(t, changed, inventoryv1.Kind_KIND_PACKAGE, at).Digest == digest {
			t.Errorf("%s leaves the digest as it was", name)
		}
	}
}

func TestAKindTheHostCannotHoldIsUnsupportedAndOneItFailsToReadIsNoSnapshot(t *testing.T) {
	host := newHost()
	for kind, absent := range map[string]error{
		"package":           fmt.Errorf("%w: %s", dpkg.ErrAbsent, "no dpkg-query"),
		"service":           fmt.Errorf("%w: %s", services.ErrAbsent, "/run/systemd/system is not there"),
		"network_interface": fmt.Errorf("read the network interfaces of darwin: %w", errors.ErrUnsupported),
	} {
		host.failures[kind] = absent
	}
	host.failures["user"] = fmt.Errorf("%w: permission denied", accounts.ErrUnreadable)
	for _, kind := range inventory.Kinds() {
		held, err := inventory.Take(t.Context(), host, installation, kind, time.Now())
		name := inventory.KindName(kind)
		switch name {
		case "package", "service", "network_interface":
			if !errors.Is(err, inventory.ErrUnsupported) || held.Record != nil {
				t.Errorf("a host without what the %s is read from gave %v", name, err)
			}
		case "user":
			if err == nil || errors.Is(err, inventory.ErrUnsupported) || held.Record != nil {
				t.Errorf("account files that could not be read gave %v", err)
			}
		default:
			if err != nil {
				t.Errorf("the %s gave %v", name, err)
			}
		}
	}
}

func TestAnEnumerationOfNothingIsAnEmptySnapshot(t *testing.T) {
	host := newHost()
	host.packages = []dpkg.Package{}
	held := taken(t, host, inventoryv1.Kind_KIND_PACKAGE, time.Now())
	if len(held.Record.GetItems()) != 0 || held.Record.GetMode() != inventoryv1.Mode_MODE_SNAPSHOT || len(held.Encoded) == 0 {
		t.Errorf("a host with no package is described as %v", held.Record)
	}
}

func TestARecordThePlatformWouldNotTakeIsNeverTaken(t *testing.T) {
	host := newHost()
	host.packages = make([]dpkg.Package, protocol.MaxInventoryItemsPerRecord+1)
	for i := range host.packages {
		host.packages[i] = dpkg.Package{Name: fmt.Sprintf("package-%05d", i), Version: "1.0", Architecture: "all"}
	}
	if _, err := inventory.Take(t.Context(), host, installation, inventoryv1.Kind_KIND_PACKAGE, time.Now()); !errors.Is(err, inventory.ErrTooLarge) {
		t.Errorf("one package more than the platform takes in a record gave %v", err)
	}

	host.packages = make([]dpkg.Package, 4000)
	for i := range host.packages {
		host.packages[i] = dpkg.Package{Name: fmt.Sprintf("%0200d", i), Version: strings.Repeat("9", 100), Architecture: "amd64", Source: fmt.Sprintf("%0200d", i)}
	}
	if _, err := inventory.Take(t.Context(), host, installation, inventoryv1.Kind_KIND_PACKAGE, time.Now()); !errors.Is(err, inventory.ErrTooLarge) || !strings.Contains(err.Error(), "4000 items encode to") {
		t.Errorf("4000 packages of long names gave %v", err)
	}
	host.packages = host.packages[:1500]
	if held := taken(t, host, inventoryv1.Kind_KIND_PACKAGE, time.Now()); len(held.Encoded) > protocol.MaxInventoryRecordBytes {
		t.Errorf("a snapshot of %d bytes was taken", len(held.Encoded))
	}

	host = newHost()
	host.accounts.Accounts[0].Home = "/root/\xff"
	var inadmissible *protocol.Inadmissible
	if _, err := inventory.Take(t.Context(), host, installation, inventoryv1.Kind_KIND_USER, time.Now()); !errors.As(err, &inadmissible) || inadmissible.Field != "items[0].user.home" {
		t.Errorf("a home that is not UTF-8 gave %v", err)
	}
}

func TestItemsThePlatformHoldsAsOneAreNamedAndKept(t *testing.T) {
	host := newHost()
	host.accounts.Accounts = append(host.accounts.Accounts, accounts.Account{Name: "toor", Home: "/root", Shell: "/bin/sh"}, accounts.Account{Name: "nobody", UID: 65534, GID: 65534, Home: "/nonexistent", Shell: "/usr/sbin/nologin"})
	held := taken(t, host, inventoryv1.Kind_KIND_USER, time.Now())
	if len(held.Record.GetItems()) != 4 || !slices.Equal(held.Merged, []string{`user "0": "root", "toor"`}) {
		t.Errorf("two accounts with uid 0 were taken as %d items, merged %q", len(held.Record.GetItems()), held.Merged)
	}
	if merged := taken(t, newHost(), inventoryv1.Kind_KIND_PACKAGE, time.Now()).Merged; len(merged) != 0 {
		t.Errorf("packages of two architectures were merged as %q", merged)
	}
}
