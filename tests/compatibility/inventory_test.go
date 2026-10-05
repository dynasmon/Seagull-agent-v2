package compatibility_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-agent-v2/internal/modules/inventory"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/accounts"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/dpkg"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/interfaces"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/machine"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/services"
	"github.com/dynasmon/Seagull-agent-v2/internal/protocol"
	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
)

// What the native gate recorded of an Ubuntu 24.04 host as the installed
// agent took stock of it, round by round: what the platform adapters read of
// the host right after each round, and the records the agent delivered of
// it. A probe package is installed, upgraded and purged across the rounds,
// beside an account that shares uid 0 with root, a dummy interface and a
// transient service, each added and then removed.
type stockScenario struct {
	RecordedAt     time.Time         `json:"recorded_at"`
	Build          string            `json:"build"`
	InstallationID string            `json:"installation_id"`
	AgentID        string            `json:"agent_id"`
	Host           map[string]string `json:"host"`
	Probe          map[string]string `json:"probe"`
	Batches        int               `json:"batches"`
	Rounds         []stockRound      `json:"rounds"`
}

type stockRound struct {
	Name     string              `json:"name"`
	Changed  string              `json:"changed"`
	Observed observedHost        `json:"observed"`
	Records  []map[string]string `json:"records"`
}

type observedHost struct {
	Hostname   string                 `json:"hostname"`
	Release    machine.Release        `json:"release"`
	Kernel     machine.Kernel         `json:"kernel"`
	Hardware   machine.Hardware       `json:"hardware"`
	Packages   []dpkg.Package         `json:"packages"`
	Services   []services.Service     `json:"services"`
	Interfaces []interfaces.Interface `json:"interfaces"`
	Accounts   accounts.Database      `json:"accounts"`
}

type recordedHost struct{ observedHost }

func (r recordedHost) Hostname() (string, error)              { return r.observedHost.Hostname, nil }
func (r recordedHost) Distribution() (machine.Release, error) { return r.Release, nil }
func (r recordedHost) Kernel() (machine.Kernel, error)        { return r.observedHost.Kernel, nil }
func (r recordedHost) Hardware() (machine.Hardware, error)    { return r.observedHost.Hardware, nil }
func (r recordedHost) Packages(context.Context) ([]dpkg.Package, error) {
	return r.observedHost.Packages, nil
}
func (r recordedHost) Services(context.Context) ([]services.Service, error) {
	return r.observedHost.Services, nil
}
func (r recordedHost) Interfaces() ([]interfaces.Interface, error) {
	return r.observedHost.Interfaces, nil
}
func (r recordedHost) Accounts() (accounts.Database, error) { return r.observedHost.Accounts, nil }

func stock(t *testing.T) (stockScenario, map[string][]byte, []string) {
	t.Helper()
	directory := filepath.Join("testdata", "inventory")
	encoded, err := os.ReadFile(filepath.Join(directory, "scenario.json"))
	if err != nil {
		t.Fatalf("read the inventory scenario: %v", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var held stockScenario
	if err := decoder.Decode(&held); err != nil {
		t.Fatalf("decode the inventory scenario: %v", err)
	}
	if held.InstallationID == "" || held.Build == "" || held.RecordedAt.IsZero() || held.Host["dpkg"] == "" || len(held.Rounds) != 4 {
		t.Fatalf("the inventory scenario does not say what recorded it, where and when: %+v", held)
	}
	records := map[string][]byte{}
	var names []string
	for i := range held.Batches {
		name := fmt.Sprintf("batch-%03d.pb", i)
		body, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		batch := &inventoryv1.RecordBatch{}
		if err := proto.Unmarshal(body, batch); err != nil {
			t.Fatalf("%s is not an inventory batch: %v", name, err)
		}
		if batch.GetProtocolVersion() != protocol.Version || !batchIdentifier.MatchString(batch.GetBatchId()) {
			t.Fatalf("%s was sent as batch %q of protocol %d", name, batch.GetBatchId(), batch.GetProtocolVersion())
		}
		for _, record := range protocol.Inventory.Records(body) {
			identity, err := protocol.Inventory.Identify(record)
			if err != nil {
				t.Fatalf("%s carries a record that does not read: %v", name, err)
			}
			records[identity.ID] = record
		}
		names = append(names, name)
	}
	return held, records, names
}

func decodedRecord(t *testing.T, held []byte) *inventoryv1.Record {
	t.Helper()
	record := &inventoryv1.Record{}
	if err := proto.Unmarshal(held, record); err != nil {
		t.Fatalf("a delivered record is not an inventory record: %v", err)
	}
	return record
}

// The records the installed agent delivered are the ones the collector of
// this build takes of what the host held: read again by the platform adapters
// right after each round, the host becomes the same records, byte for byte.
func TestTheCollectorTakesOfTheRecordedHostTheRecordsTheAgentDelivered(t *testing.T) {
	held, records, _ := stock(t)
	taken := 0
	for _, round := range held.Rounds {
		for _, sent := range round.Records {
			delivered, found := records[sent["record_id"]]
			if !found {
				t.Fatalf("round %s names record %s, and no batch carries it", round.Name, sent["record_id"])
			}
			collected, err := time.Parse(time.RFC3339Nano, sent["collected_at"])
			if err != nil {
				t.Fatal(err)
			}
			kind := decodedRecord(t, delivered).GetKind()
			again, err := inventory.Take(t.Context(), recordedHost{round.Observed}, held.InstallationID, kind, collected)
			if err != nil {
				t.Fatalf("round %s: take the %s again: %v", round.Name, sent["kind"], err)
			}
			if inventory.KindName(kind) != sent["kind"] || again.Record.GetRecordId() != sent["record_id"] {
				t.Errorf("round %s names the %s record %s, and it is the %s record %s", round.Name, sent["kind"], sent["record_id"], inventory.KindName(kind), again.Record.GetRecordId())
			}
			if runtime.GOOS == "linux" && runtime.GOARCH == recordedArchitecture {
				if !bytes.Equal(again.Encoded, delivered) {
					t.Errorf("round %s: the %s was delivered as\n%x\nand the collector takes\n%x", round.Name, sent["kind"], delivered, again.Encoded)
				}
			} else {
				recorded := decodedRecord(t, delivered)
				again.Record.GetOrigin().GetHost().Os, again.Record.GetOrigin().GetHost().Architecture = recorded.GetOrigin().GetHost().GetOs(), recorded.GetOrigin().GetHost().GetArchitecture()
				if !proto.Equal(recorded, again.Record) {
					t.Errorf("round %s: the %s was delivered as %v and the collector takes %v", round.Name, sent["kind"], recorded, again.Record)
				}
			}
			taken++
		}
	}
	if taken != len(records) {
		t.Errorf("the rounds name %d records and the batches carry %d", taken, len(records))
	}
}

// What each round delivered is what changed on the host before it: every kind
// the first time, then the kinds the probe touched, and after a restart on an
// unchanged host nothing at all, which the gate checks as it runs.
func TestEachRoundDeliveredTheKindsThatChangedOnTheHost(t *testing.T) {
	held, records, _ := stock(t)
	probe := held.Probe
	kinds := func(round stockRound) []string {
		var named []string
		for _, sent := range round.Records {
			named = append(named, sent["kind"])
		}
		return named
	}
	latest := func(round stockRound, kind string) *inventoryv1.Record {
		for _, sent := range round.Records {
			if sent["kind"] == kind {
				return decodedRecord(t, records[sent["record_id"]])
			}
		}
		t.Fatalf("round %s delivered no %s", round.Name, kind)
		return nil
	}
	probed := func(record *inventoryv1.Record) []string {
		var found []string
		for _, item := range record.GetItems() {
			if installed := item.GetPackage(); installed.GetName() == probe["package"] {
				found = append(found, installed.GetVersion()+" "+installed.GetSource())
			}
		}
		return found
	}
	first, installed, upgraded, removed := held.Rounds[0], held.Rounds[1], held.Rounds[2], held.Rounds[3]
	if got := kinds(first); !slices.Equal(got, []string{"operating_system", "kernel", "hardware", "package", "service", "network_interface", "user"}) {
		t.Errorf("the first round delivered %v", got)
	}
	if got := kinds(installed); !slices.Equal(got, []string{"package", "service", "network_interface", "user"}) {
		t.Errorf("after the probes were added the agent delivered %v", got)
	}
	if got := probed(latest(installed, "package")); !slices.Equal(got, []string{"1.0 " + probe["source"] + " (1.0)"}) {
		t.Errorf("the probe was delivered as %v", got)
	}
	var sharing []string
	for _, item := range latest(installed, "user").GetItems() {
		if item.GetUser().GetUid() == "0" {
			sharing = append(sharing, item.GetUser().GetName())
		}
	}
	if !slices.Equal(sharing, []string{"root", probe["account"]}) {
		t.Errorf("the accounts with uid 0 were delivered as %v", sharing)
	}
	if got := kinds(upgraded); !slices.Equal(got, []string{"package"}) || !slices.Equal(probed(latest(upgraded, "package")), []string{"2.0 " + probe["source"] + " (2.0)"}) {
		t.Errorf("after the upgrade the agent delivered %v, the probe as %v", got, probed(latest(upgraded, "package")))
	}
	if got := kinds(removed); !slices.Equal(got, []string{"package", "service", "network_interface", "user"}) || len(probed(latest(removed, "package"))) != 0 {
		t.Errorf("after the probes went the agent delivered %v", got)
	}
}

// Each inventory.json under testdata measured what one platform commit holds
// as current of the batches the agent delivered: admitted by that commit's own
// admitter to a real broker, folded by its own projector into its own store,
// round by round, then sent again, then with one record arriving late, and
// with the store written as a projector stopped between the items of a
// snapshot and the line they are measured against would leave it.
type inventoryMeasurement struct {
	Platform struct {
		Repository     string    `json:"repository"`
		Commit         string    `json:"commit"`
		Contracts      string    `json:"contracts"`
		Broker         string    `json:"broker"`
		Store          string    `json:"store"`
		AdmissionClock time.Time `json:"admission_clock"`
	} `json:"platform"`
	RecordedAt time.Time `json:"recorded_at"`
	Agent      struct {
		Build          string    `json:"build"`
		InstallationID string    `json:"installation_id"`
		AgentID        string    `json:"agent_id"`
		RecordedAt     time.Time `json:"recorded_at"`
	} `json:"agent"`
	Rounds []struct {
		Name    string              `json:"name"`
		Batches []string            `json:"batches"`
		Answers []inventoryAnswer   `json:"answers"`
		Current map[string][]string `json:"current"`
	} `json:"rounds"`
	Final    map[string][]string `json:"final"`
	Replayed struct {
		Answers []inventoryAnswer   `json:"answers"`
		Current map[string][]string `json:"current"`
	} `json:"replayed"`
	Late struct {
		Record  string              `json:"record"`
		Answer  inventoryAnswer     `json:"answer"`
		Current map[string][]string `json:"current"`
	} `json:"late"`
	Interrupted struct {
		Agent     string   `json:"agent"`
		Upgraded  []string `json:"upgraded"`
		ItemsOnly []string `json:"items_only"`
		Retried   []string `json:"retried"`
	} `json:"interrupted"`
	Empty struct {
		Agent   string   `json:"agent"`
		Current []string `json:"current"`
	} `json:"empty"`
	Ceiling struct {
		AtAgentCeiling inventoryAnswer `json:"at_agent_ceiling"`
		OverProducer   inventoryAnswer `json:"over_producer"`
	} `json:"ceiling"`
}

type inventoryAnswer struct {
	Outcome  string `json:"outcome"`
	Accepted bool   `json:"accepted"`
	Durable  bool   `json:"durable"`
	Received int    `json:"received"`
	Code     string `json:"code"`
	Field    string `json:"field"`
	Record   int    `json:"record"`
	Error    string `json:"error"`
	Bytes    int    `json:"bytes"`
	Items    int    `json:"items"`
}

// described is an item as the measurement lists it: what tells it apart from
// the others of its kind, and what changes about it.
func described(kind inventoryv1.Kind, item *inventoryv1.Item) string {
	state := func(name string) string { return strings.ToLower(strings.TrimPrefix(name, "STATE_")) }
	switch kind {
	case inventoryv1.Kind_KIND_PACKAGE:
		held := item.GetPackage()
		return fmt.Sprintf("%s:%s %s (%s)", held.GetName(), held.GetArchitecture(), held.GetVersion(), held.GetSource())
	case inventoryv1.Kind_KIND_SERVICE:
		held := item.GetService()
		return fmt.Sprintf("%s %s %s", held.GetName(), state(held.GetState().String()), held.GetStartMode())
	case inventoryv1.Kind_KIND_NETWORK_INTERFACE:
		held := item.GetNetworkInterface()
		return fmt.Sprintf("%s %s %s", held.GetName(), state(held.GetState().String()), strings.Join(held.GetAddresses(), ","))
	case inventoryv1.Kind_KIND_USER:
		return item.GetUser().GetName() + " " + item.GetUser().GetUid()
	case inventoryv1.Kind_KIND_OPERATING_SYSTEM:
		return item.GetOperatingSystem().GetPlatform() + " " + item.GetOperatingSystem().GetVersion()
	case inventoryv1.Kind_KIND_KERNEL:
		return item.GetKernel().GetRelease()
	case inventoryv1.Kind_KIND_HARDWARE:
		return fmt.Sprint(item.GetHardware().GetMemoryTotalBytes())
	}
	return ""
}

// expected is what the platform should hold as current after the rounds up
// to the one given: of each kind, the items of the latest snapshot the agent
// delivered, one for each identity the platform derives.
func expected(t *testing.T, held stockScenario, records map[string][]byte, through int) map[string][][]string {
	t.Helper()
	latest := map[string]*inventoryv1.Record{}
	for _, round := range held.Rounds[:through+1] {
		for _, sent := range round.Records {
			latest[sent["kind"]] = decodedRecord(t, records[sent["record_id"]])
		}
	}
	held2 := map[string][][]string{}
	for kind, record := range latest {
		groups := map[string][]string{}
		var order []string
		for _, item := range record.GetItems() {
			identity := strings.Join(protocol.InventoryIdentity(record.GetKind(), item), "\x00")
			if _, seen := groups[identity]; !seen {
				order = append(order, identity)
			}
			groups[identity] = append(groups[identity], described(record.GetKind(), item))
		}
		for _, identity := range order {
			held2[kind] = append(held2[kind], groups[identity])
		}
	}
	return held2
}

// holds says whether what the platform holds of a kind is one item of each
// identity the latest snapshot names, and which of those it kept when several
// items of the snapshot share one.
func holds(current []string, groups [][]string) ([]string, bool) {
	if len(current) != len(groups) {
		return nil, false
	}
	var kept []string
	for _, group := range groups {
		found := slices.IndexFunc(group, func(item string) bool { return slices.Contains(current, item) })
		if found < 0 {
			return nil, false
		}
		if len(group) > 1 {
			kept = append(kept, group[found])
		}
	}
	return kept, true
}

func TestARecordedPlatformHoldsWhatTheLatestSnapshotOfEachKindNamed(t *testing.T) {
	held, records, names := stock(t)
	manifests, err := filepath.Glob(filepath.Join("testdata", "*", "inventory.json"))
	if err != nil || len(manifests) == 0 {
		t.Fatalf("no platform was measured holding what the collector delivered: %v", err)
	}
	for _, manifest := range manifests {
		t.Run(filepath.Base(filepath.Dir(manifest)), func(t *testing.T) {
			encoded, err := os.ReadFile(manifest)
			if err != nil {
				t.Fatal(err)
			}
			decoder := json.NewDecoder(bytes.NewReader(encoded))
			decoder.DisallowUnknownFields()
			var measured inventoryMeasurement
			if err := decoder.Decode(&measured); err != nil {
				t.Fatalf("decode %s: %v", manifest, err)
			}
			if measured.Platform.Commit == "" || measured.Platform.Contracts == "" || measured.Agent.InstallationID != held.InstallationID || measured.Agent.Build != held.Build ||
				len(measured.Rounds) != len(held.Rounds) {
				t.Fatalf("%s measured %+v of %+v", manifest, measured.Platform, measured.Agent)
			}
			var carried []string
			for i, round := range measured.Rounds {
				carried = append(carried, round.Batches...)
				for _, answer := range round.Answers {
					if answer.Outcome != "durable" || !answer.Accepted || !answer.Durable || answer.Received < 1 {
						t.Errorf("the platform took a batch of round %s as %+v", round.Name, answer)
					}
				}
				want := expected(t, held, records, i)
				for kind, groups := range want {
					kept, holding := holds(round.Current[kind], groups)
					if !holding {
						t.Errorf("after round %s the platform holds the %s as\n%q\nand the latest snapshot names\n%q", round.Name, kind, round.Current[kind], groups)
					}
					if len(kept) > 0 {
						t.Logf("after round %s, of the %s that share an identity, the platform keeps %q", round.Name, kind, kept)
					}
				}
			}
			if !slices.Equal(carried, names) {
				t.Errorf("the rounds carried %v, and the agent delivered %v", carried, names)
			}
			installed := measured.Rounds[1].Current["user"]
			if slices.Contains(installed, "root 0") == slices.Contains(installed, held.Probe["account"]+" 0") {
				t.Errorf("of two accounts with uid 0 the platform holds %q: it identifies an account by its uid, and was measured keeping one", installed)
			}
			final := measured.Rounds[len(measured.Rounds)-1].Current
			for _, kind := range []string{"package", "user"} {
				if !slices.Equal(measured.Final[kind], final[kind]) || !slices.Equal(measured.Replayed.Current[kind], final[kind]) || !slices.Equal(measured.Late.Current[kind], final[kind]) {
					t.Errorf("sent again, or with a snapshot arriving late, the platform holds the %s differently", kind)
				}
			}
			for _, answer := range append(measured.Replayed.Answers, measured.Late.Answer) {
				if answer.Outcome != "durable" || !answer.Durable {
					t.Errorf("a batch sent again was taken as %+v", answer)
				}
			}
			if late := decodedRecord(t, records[measured.Late.Record]); late.GetKind() != inventoryv1.Kind_KIND_PACKAGE || measured.Late.Record != held.Rounds[1].Records[0]["record_id"] {
				t.Errorf("the record sent late is %s", measured.Late.Record)
			}
			probe := func(current []string) bool {
				return slices.ContainsFunc(current, func(item string) bool { return strings.HasPrefix(item, held.Probe["package"]+":all 2.0 ") })
			}
			if !probe(measured.Interrupted.Upgraded) || !probe(measured.Interrupted.ItemsOnly) || probe(measured.Interrupted.Retried) || len(measured.Interrupted.Retried) != len(final["package"]) {
				t.Errorf("between the items of a snapshot and its line the platform held the probe as %v, %v and %v",
					probe(measured.Interrupted.Upgraded), probe(measured.Interrupted.ItemsOnly), probe(measured.Interrupted.Retried))
			}
			if len(measured.Empty.Current) != 0 {
				t.Errorf("after an empty snapshot the platform holds %d packages", len(measured.Empty.Current))
			}
			at, over := measured.Ceiling.AtAgentCeiling, measured.Ceiling.OverProducer
			if at.Outcome != "durable" || !at.Durable || at.Bytes < protocol.MaxInventoryRecordBytes || at.Bytes > protocol.MaxInventoryRecordBytes+2 {
				t.Errorf("a record of the agent's ceiling, %d bytes, was taken as %+v", protocol.MaxInventoryRecordBytes, at)
			}
			if over.Outcome != "backbone_unavailable" || over.Bytes <= at.Bytes {
				t.Errorf("a record over what the backbone carries was taken as %+v", over)
			}
		})
	}
}
