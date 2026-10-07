package compatibility_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-agent-v2/internal/protocol"
	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
)

type photographs struct {
	RecordedAt     time.Time         `json:"recorded_at"`
	Build          string            `json:"build"`
	InstallationID string            `json:"installation_id"`
	AgentID        string            `json:"agent_id"`
	Host           map[string]string `json:"host"`
	Probe          map[string]string `json:"probe"`
	Batches        int               `json:"batches"`
	Rounds         []struct {
		Name    string              `json:"name"`
		Changed string              `json:"changed"`
		Records []map[string]string `json:"records"`
		Stable  int                 `json:"stable"`
		Items   int                 `json:"items"`
	} `json:"rounds"`
}

type heldProcess struct {
	PID         uint32    `json:"pid"`
	ParentPID   uint32    `json:"parent_pid"`
	Name        string    `json:"name"`
	User        string    `json:"user"`
	Path        string    `json:"path"`
	CommandLine string    `json:"command_line"`
	StartedAt   time.Time `json:"started_at"`
}

// Each processes.json under testdata measured what one platform commit holds
// as the current processes of the host after each snapshot the agent
// delivered, admitted by its own admitter to a real broker and folded by its
// own projector into its own store, and once all of them were sent again.
type processesMeasurement struct {
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
		Name    string            `json:"name"`
		Record  string            `json:"record"`
		Answers []inventoryAnswer `json:"answers"`
		Current []heldProcess     `json:"current"`
	} `json:"rounds"`
	Replayed struct {
		Answers []inventoryAnswer `json:"answers"`
		Current []heldProcess     `json:"current"`
	} `json:"replayed"`
}

func photographed(t *testing.T) (photographs, map[string]*inventoryv1.Record) {
	t.Helper()
	directory := filepath.Join("testdata", "processes")
	encoded, err := os.ReadFile(filepath.Join(directory, "scenario.json"))
	if err != nil {
		t.Fatalf("read the processes scenario: %v", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var held photographs
	if err := decoder.Decode(&held); err != nil {
		t.Fatalf("decode the processes scenario: %v", err)
	}
	if held.InstallationID == "" || held.Build == "" || held.RecordedAt.IsZero() || held.Host["kernel"] == "" || len(held.Rounds) != 2 || held.Batches != len(held.Rounds) {
		t.Fatalf("the processes scenario does not say what recorded it, where and when: %+v", held)
	}
	records := map[string]*inventoryv1.Record{}
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
		if batch.GetProtocolVersion() != protocol.Version || !batchIdentifier.MatchString(batch.GetBatchId()) || len(batch.GetRecords()) != 1 {
			t.Fatalf("%s was sent as batch %q of protocol %d with %d records", name, batch.GetBatchId(), batch.GetProtocolVersion(), len(batch.GetRecords()))
		}
		record := batch.GetRecords()[0]
		records[record.GetRecordId()] = record
	}
	return held, records
}

func photographOf(t *testing.T, held photographs, records map[string]*inventoryv1.Record, round int) *inventoryv1.Record {
	t.Helper()
	sent := held.Rounds[round].Records
	if len(sent) != 1 || sent[0]["kind"] != "process" || records[sent[0]["record_id"]] == nil {
		t.Fatalf("round %s names %v, and the batches carry %d records", held.Rounds[round].Name, sent, len(records))
	}
	return records[sent[0]["record_id"]]
}

// What the installed agent delivered of the processes is a snapshot the
// recorded platform takes whole: one process for each PID and moment, each
// named as text, none with a command line, and every parent a process of the
// same snapshot that started no later than its child.
func TestTheAgentDeliveredTheProcessesAsSnapshotsThePlatformTakesWhole(t *testing.T) {
	held, records := photographed(t)
	for i, round := range held.Rounds {
		record := photographOf(t, held, records, i)
		if err := protocol.CheckInventory(record); err != nil || record.GetKind() != inventoryv1.Kind_KIND_PROCESS || record.GetMode() != inventoryv1.Mode_MODE_SNAPSHOT ||
			record.GetCollection().GetCollector() != "processes" || record.GetCollection().GetSource() != "procfs" || len(record.GetItems()) != round.Items {
			t.Fatalf("round %s delivered %d processes as %v: %v", round.Name, len(record.GetItems()), record.GetCollection(), err)
		}
		started := map[uint32][]time.Time{}
		for _, item := range record.GetItems() {
			running := item.GetProcess()
			started[running.GetPid()] = append(started[running.GetPid()], running.GetStartedAt().AsTime())
			if running.GetCommandLine() != "" {
				t.Errorf("round %s delivered process %d with a command line", round.Name, running.GetPid())
			}
		}
		for _, item := range record.GetItems() {
			running := item.GetProcess()
			if len(started[running.GetPid()]) != 1 {
				t.Errorf("round %s delivered process %d %d times", round.Name, running.GetPid(), len(started[running.GetPid()]))
			}
			parent := running.GetParentPid()
			if parent != 0 && (len(started[parent]) != 1 || started[parent][0].After(running.GetStartedAt().AsTime())) {
				t.Errorf("round %s delivered process %d as the child of %d, which the snapshot holds as no process that started before it", round.Name, running.GetPid(), parent)
			}
		}
	}
	named := func(record *inventoryv1.Record) []*inventoryv1.Process {
		var found []*inventoryv1.Process
		for _, item := range record.GetItems() {
			if item.GetProcess().GetName() == held.Probe["named"] {
				found = append(found, item.GetProcess())
			}
		}
		return found
	}
	if probes := named(photographOf(t, held, records, 0)); len(probes) != 1 || probes[0].GetUser() != held.Probe["account"] || probes[0].GetPath() != "" {
		t.Errorf("the first snapshot holds the process that named itself %s as %v", held.Probe["named"], probes)
	}
	if probes := named(photographOf(t, held, records, 1)); len(probes) != 0 {
		t.Errorf("once it ended, the next snapshot holds the process that named itself as %v", probes)
	}
}

// After each snapshot, a recorded platform holds as current the processes it
// named, as it named them, and nothing it did not; the same snapshots sent
// again change nothing it holds.
func TestARecordedPlatformHoldsTheProcessesTheLatestSnapshotNamed(t *testing.T) {
	held, records := photographed(t)
	manifests, err := filepath.Glob(filepath.Join("testdata", "*", "processes.json"))
	if err != nil || len(manifests) == 0 {
		t.Fatalf("no platform was measured holding what the processes module delivered: %v", err)
	}
	for _, manifest := range manifests {
		t.Run(filepath.Base(filepath.Dir(manifest)), func(t *testing.T) {
			encoded, err := os.ReadFile(manifest)
			if err != nil {
				t.Fatal(err)
			}
			decoder := json.NewDecoder(bytes.NewReader(encoded))
			decoder.DisallowUnknownFields()
			var measured processesMeasurement
			if err := decoder.Decode(&measured); err != nil {
				t.Fatalf("decode %s: %v", manifest, err)
			}
			if measured.Platform.Commit == "" || measured.Platform.Contracts == "" || measured.Agent.InstallationID != held.InstallationID || measured.Agent.Build != held.Build ||
				len(measured.Rounds) != len(held.Rounds) {
				t.Fatalf("%s measured %+v of %+v", manifest, measured.Platform, measured.Agent)
			}
			durable := func(answers []inventoryAnswer, when string) {
				for _, answer := range answers {
					if answer.Outcome != "durable" || !answer.Accepted || !answer.Durable || answer.Received != 1 {
						t.Errorf("%s the platform took a batch as %+v", when, answer)
					}
				}
			}
			for i, round := range measured.Rounds {
				record := photographOf(t, held, records, i)
				durable(round.Answers, "in round "+round.Name)
				if round.Record != record.GetRecordId() || !slices.Equal(round.Current, holding(record)) {
					t.Errorf("after round %s the platform holds %d processes, and the snapshot names %d:\n%v\n%v", round.Name, len(round.Current), len(record.GetItems()), round.Current, holding(record))
				}
			}
			durable(measured.Replayed.Answers, "sent again,")
			if last := photographOf(t, held, records, len(held.Rounds)-1); !slices.Equal(measured.Replayed.Current, holding(last)) {
				t.Errorf("once every snapshot was sent again, the platform holds %v", measured.Replayed.Current)
			}
		})
	}
}

// holding is what a platform holds of a snapshot's processes: each as the
// snapshot names it, at the millisecond its store keeps a moment to.
func holding(record *inventoryv1.Record) []heldProcess {
	var held []heldProcess
	for _, item := range record.GetItems() {
		running := item.GetProcess()
		held = append(held, heldProcess{PID: running.GetPid(), ParentPID: running.GetParentPid(), Name: running.GetName(), User: running.GetUser(), Path: running.GetPath(),
			StartedAt: running.GetStartedAt().AsTime().Truncate(time.Millisecond)})
	}
	slices.SortFunc(held, func(a, b heldProcess) int {
		if a.PID != b.PID {
			return int(a.PID) - int(b.PID)
		}
		return a.StartedAt.Compare(b.StartedAt)
	})
	return held
}
