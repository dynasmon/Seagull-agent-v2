package compatibility_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-agent-v2/internal/protocol"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
	updatev1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/update/v1"
)

// What the installed agent reported in the native gate, byte for byte, and
// what a recorded platform answered and kept of it.
type statusScenario struct {
	RecordedAt     time.Time `json:"recorded_at"`
	Build          string    `json:"build"`
	InstallationID string    `json:"installation_id"`
	AgentID        string    `json:"agent_id"`
	Boot           string    `json:"boot_id"`
	Reports        []struct {
		Batch     string `json:"batch"`
		Sequence  uint64 `json:"sequence"`
		Condition string `json:"condition"`
		Previous  string `json:"previous_ending"`
	} `json:"reports"`
}

type statusRecording struct {
	directory string
	Platform  struct {
		Repository string `json:"repository"`
		Commit     string `json:"commit"`
		Contracts  string `json:"contracts"`
	} `json:"platform"`
	RecordedAt time.Time `json:"recorded_at"`
	Exchanges  []struct {
		Name    string `json:"name"`
		Route   string `json:"route"`
		AgentID string `json:"agent_id"`
		Status  int    `json:"status"`
	} `json:"exchanges"`
}

type statusKept struct {
	Admitted       int    `json:"admitted"`
	Current        uint64 `json:"current_rows"`
	Sequence       uint64 `json:"sequence"`
	Condition      string `json:"condition"`
	PreviousEnding string `json:"previous_ending"`
	InstallationID string `json:"installation_id"`
	Liveness       string `json:"liveness"`
}

var reported = regexp.MustCompile(`^status-[0-9]{3}$`)

var statusAnswers = map[string]protocol.Outcome{
	"status-invalid":              protocol.RecordRefused,
	"status-ahead":                protocol.Disputed,
	"status-protocol-2":           protocol.Incompatible,
	"status-agent-not-registered": protocol.AgentRefused,
	"status-agent-not-admitted":   protocol.AgentRefused,
	"status-unusable-identity":    protocol.AgentRefused,
	"status-malformed":            protocol.BatchUndecodable,
}

func TestEveryReportTheInstalledAgentSentIsOneThePlatformAdmits(t *testing.T) {
	scenario, batches := statusTold(t)
	var last uint64
	for index, batch := range batches {
		var held agentv1.StatusBatch
		if err := proto.Unmarshal(batch, &held); err != nil || len(held.GetReports()) != 1 || held.GetProtocolVersion() != protocol.Version {
			t.Fatalf("report %d is not one batch of one report: %v", index, err)
		}
		report := held.GetReports()[0]
		if err := protocol.CheckStatus(report); err != nil {
			t.Errorf("report %d is one the platform refuses: %v", index, err)
		}
		if report.GetSequence() <= last || report.GetInstallationId() != scenario.InstallationID || report.GetRun().GetBootId() != scenario.Boot {
			t.Errorf("report %d carries sequence %d after %d, installation %s and boot %s", index, report.GetSequence(), last, report.GetInstallationId(), report.GetRun().GetBootId())
		}
		if spoken := report.GetCompatibility(); spoken.GetContracts() == "" || spoken.GetProtocolVersion() != protocol.Version ||
			spoken.GetEventSchemaVersion() != protocol.EventSchemaVersion || spoken.GetInventorySchemaVersion() != protocol.InventorySchemaVersion ||
			spoken.GetUpdates().GetFormat() != updatev1.Format_FORMAT_DEB || spoken.GetUpdates().GetEnabled() {
			t.Errorf("report %d, from an agent that took no update, says it speaks %v", index, spoken)
		}
		last = report.GetSequence()
	}
}

func TestWhatARecordedPlatformAnswersTheStatusOfAnInstalledAgentIsWhatTheAgentReads(t *testing.T) {
	_, batches := statusTold(t)
	for _, recorded := range statusRecordings(t, "status.json") {
		t.Run(filepath.Base(recorded.directory), func(t *testing.T) {
			accepted, refusals := 0, map[string]bool{}
			for _, sent := range recorded.Exchanges {
				request, reply := recorded.read(t, sent.Name+".request.pb"), recorded.read(t, sent.Name+".reply.pb")
				var record []byte
				admitted := recorded.RecordedAt
				if records := protocol.Status.Records(request); len(records) == 1 {
					record = records[0]
					var report agentv1.Status
					if proto.Unmarshal(record, &report) == nil && report.GetReportedAt().IsValid() {
						admitted = report.GetReportedAt().AsTime()
					}
				}
				want, refusing := statusAnswers[sent.Name]
				if !refusing {
					want = protocol.Durable
					if !reported.MatchString(sent.Name) {
						t.Fatalf("nothing says what the agent does after %s", sent.Name)
					}
					index := 0
					if _, err := fmt.Sscanf(sent.Name, "status-%03d", &index); err != nil || index >= len(batches) || !bytes.Equal(request, batches[index]) {
						t.Errorf("%s is not what the installed agent sent", sent.Name)
					}
					accepted++
				}
				refusals[sent.Name] = refusing
				verdict := protocol.Status.Judge([]protocol.Sent{{Record: record, Admitted: admitted}},
					protocol.Answer{Status: sent.Status, ContentType: protocol.ContentType, Body: reply, Date: recorded.RecordedAt})
				if verdict.Outcome != want {
					t.Errorf("%s, answered %d, reads as %s: %v, and %s was expected", sent.Name, sent.Status, verdict.Outcome, verdict.Reason, want)
				}
			}
			if accepted != len(batches) {
				t.Errorf("%d of the %d reports the agent sent were recorded", accepted, len(batches))
			}
			for name := range statusAnswers {
				if !refusals[name] {
					t.Errorf("no %s was recorded", name)
				}
			}
		})
	}
}

// What the installed agent reported while it was updated to a signed release
// and back from one that did not run, and what a recorded platform answered.
type updatesScenario struct {
	RecordedAt     time.Time `json:"recorded_at"`
	InstallationID string    `json:"installation_id"`
	AgentID        string    `json:"agent_id"`
	Reports        []struct {
		Batch    string `json:"batch"`
		Sequence uint64 `json:"sequence"`
		Stage    string `json:"stage"`
		Version  string `json:"version"`
		Failure  string `json:"failure"`
	} `json:"reports"`
}

func TestARecordedPlatformAdmitsWhatTheInstalledAgentReportedOfItsUpdates(t *testing.T) {
	scenario, batches := updatesTold(t)
	stages := map[agentv1.Status_Update_Stage]bool{}
	var last uint64
	for index, batch := range batches {
		var held agentv1.StatusBatch
		if err := proto.Unmarshal(batch, &held); err != nil || len(held.GetReports()) != 1 {
			t.Fatalf("report %d is not one batch of one report: %v", index, err)
		}
		report, told := held.GetReports()[0], scenario.Reports[index]
		update := report.GetUpdate()
		if err := protocol.CheckStatus(report); err != nil || report.GetInstallationId() != scenario.InstallationID || report.GetSequence() <= last ||
			update.GetStage().String() != told.Stage || update.GetVersion() != told.Version || update.GetFailure().String() != told.Failure {
			t.Errorf("report %d says %v of its update as sequence %d after %d: %v", index, update, report.GetSequence(), last, err)
		}
		if takes := report.GetCompatibility().GetUpdates(); !takes.GetEnabled() || takes.GetRootVersion() != update.GetRootVersion() ||
			takes.GetCatalogVersion() < update.GetCatalogVersion() {
			t.Errorf("report %d says the agent takes %v while its update stood at %v", index, takes, update)
		}
		stages[update.GetStage()] = true
		last = report.GetSequence()
	}
	if !stages[agentv1.Status_Update_STAGE_INSTALLED] || !stages[agentv1.Status_Update_STAGE_ROLLED_BACK] {
		t.Errorf("the installed agent reported no update both installed and gone back from: %v", stages)
	}
	for _, recorded := range statusRecordings(t, "update-status.json") {
		t.Run(filepath.Base(recorded.directory), func(t *testing.T) {
			accepted := 0
			for _, sent := range recorded.Exchanges {
				index := 0
				if _, err := fmt.Sscanf(sent.Name, "update-status-%03d", &index); err != nil || index >= len(batches) {
					t.Fatalf("nothing says what the agent does after %s", sent.Name)
				}
				request, reply := recorded.read(t, sent.Name+".request.pb"), recorded.read(t, sent.Name+".reply.pb")
				if !bytes.Equal(request, batches[index]) {
					t.Errorf("%s is not what the installed agent sent", sent.Name)
				}
				records := protocol.Status.Records(request)
				var report agentv1.Status
				if len(records) != 1 || proto.Unmarshal(records[0], &report) != nil {
					t.Fatalf("%s holds no report the agent reads", sent.Name)
				}
				verdict := protocol.Status.Judge([]protocol.Sent{{Record: records[0], Admitted: report.GetReportedAt().AsTime()}},
					protocol.Answer{Status: sent.Status, ContentType: protocol.ContentType, Body: reply, Date: recorded.RecordedAt})
				if verdict.Outcome != protocol.Durable {
					t.Errorf("%s, answered %d, reads as %s: %v", sent.Name, sent.Status, verdict.Outcome, verdict.Reason)
				}
				accepted++
			}
			if accepted != len(batches) {
				t.Errorf("%d of the %d reports the agent sent of its updates were recorded", accepted, len(batches))
			}
		})
	}
}

func TestARecordedPlatformKeepsTheNewestReportOfTheAgentAndJudgesItStopped(t *testing.T) {
	scenario, _ := statusTold(t)
	last := scenario.Reports[len(scenario.Reports)-1]
	manifests, err := filepath.Glob(filepath.Join("testdata", "*", "status-store.json"))
	if err != nil || len(manifests) == 0 {
		t.Fatalf("no platform was recorded keeping what the agent reported: %v", err)
	}
	for _, manifest := range manifests {
		var kept struct {
			Alone    statusKept `json:"alone"`
			Replayed statusKept `json:"replayed"`
		}
		content, err := os.ReadFile(manifest)
		if err == nil {
			err = json.Unmarshal(content, &kept)
		}
		if err != nil {
			t.Fatal(err)
		}
		for name, held := range map[string]statusKept{"alone": kept.Alone, "replayed": kept.Replayed} {
			if held.Current != 1 || held.Sequence != last.Sequence || held.Condition != last.Condition || held.InstallationID != scenario.InstallationID ||
				held.Liveness != agentv1.Liveness_LIVENESS_STOPPED.String() {
				t.Errorf("%s: %s, the platform holds %+v, and the agent last reported sequence %d %s", manifest, name, held, last.Sequence, last.Condition)
			}
		}
		if kept.Alone.Admitted != len(scenario.Reports) || kept.Replayed.Admitted != 2*len(scenario.Reports) {
			t.Errorf("%s admitted %d then %d reports of %d", manifest, kept.Alone.Admitted, kept.Replayed.Admitted, len(scenario.Reports))
		}
	}
}

func statusTold(t *testing.T) (statusScenario, [][]byte) {
	t.Helper()
	var scenario statusScenario
	content, err := os.ReadFile(filepath.Join("testdata", "status", "scenario.json"))
	if err == nil {
		decoder := json.NewDecoder(bytes.NewReader(content))
		decoder.DisallowUnknownFields()
		err = decoder.Decode(&scenario)
	}
	if err != nil || len(scenario.Reports) == 0 || scenario.Reports[len(scenario.Reports)-1].Condition != agentv1.Status_CONDITION_STOPPED.String() {
		t.Fatalf("read what the installed agent reported, ending as it stopped: %v", err)
	}
	batches := make([][]byte, 0, len(scenario.Reports))
	for _, report := range scenario.Reports {
		batch, err := os.ReadFile(filepath.Join("testdata", "status", report.Batch))
		if err != nil {
			t.Fatal(err)
		}
		batches = append(batches, batch)
	}
	return scenario, batches
}

func updatesTold(t *testing.T) (updatesScenario, [][]byte) {
	t.Helper()
	var scenario updatesScenario
	content, err := os.ReadFile(filepath.Join("testdata", "update-status", "scenario.json"))
	if err == nil {
		decoder := json.NewDecoder(bytes.NewReader(content))
		decoder.DisallowUnknownFields()
		err = decoder.Decode(&scenario)
	}
	if err != nil || len(scenario.Reports) == 0 {
		t.Fatalf("read what the installed agent reported of its updates: %v", err)
	}
	batches := make([][]byte, 0, len(scenario.Reports))
	for _, report := range scenario.Reports {
		batch, err := os.ReadFile(filepath.Join("testdata", "update-status", report.Batch))
		if err != nil {
			t.Fatal(err)
		}
		batches = append(batches, batch)
	}
	return scenario, batches
}

func statusRecordings(t *testing.T, named string) []statusRecording {
	t.Helper()
	manifests, err := filepath.Glob(filepath.Join("testdata", "*", named))
	if err != nil || len(manifests) == 0 {
		t.Fatalf("no platform was recorded answering what the agent reported in %s: %v", named, err)
	}
	var found []statusRecording
	for _, manifest := range manifests {
		content, err := os.ReadFile(manifest)
		if err != nil {
			t.Fatal(err)
		}
		decoder := json.NewDecoder(bytes.NewReader(content))
		decoder.DisallowUnknownFields()
		recorded := statusRecording{directory: filepath.Dir(manifest)}
		if err := decoder.Decode(&recorded); err != nil || recorded.Platform.Commit == "" || recorded.RecordedAt.IsZero() {
			t.Fatalf("decode %s: %v", manifest, err)
		}
		found = append(found, recorded)
	}
	return found
}

func (r statusRecording) read(t *testing.T, name string) []byte {
	t.Helper()
	held, err := os.ReadFile(filepath.Join(r.directory, name))
	if err != nil {
		t.Fatal(err)
	}
	return held
}
