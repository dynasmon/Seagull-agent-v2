package compatibility_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-agent-v2/internal/link"
	"github.com/dynasmon/Seagull-agent-v2/internal/policy"
	"github.com/dynasmon/Seagull-agent-v2/internal/protocol"
	"github.com/dynasmon/Seagull-agent-v2/internal/transport"
	assessmentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/assessment/v1"
	policyv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/policy/v1"
)

// What the installed agent assessed in the native gate: the policies the gate
// signed for it, and every batch the platform took, byte for byte.
type assessmentScenario struct {
	RecordedAt     time.Time `json:"recorded_at"`
	InstallationID string    `json:"installation_id"`
	AgentID        string    `json:"agent_id"`
	Policies       []string  `json:"policies"`
	Assessments    []struct {
		Batch      string            `json:"batch"`
		ID         string            `json:"assessment_id"`
		Revision   uint64            `json:"policy_revision"`
		AssessedAt time.Time         `json:"assessed_at"`
		Outcomes   map[string]string `json:"outcomes"`
	} `json:"assessments"`
}

type assessmentRecording struct {
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

var assessedBatch = regexp.MustCompile(`^assessment-[0-9]{3}$`)

var assessmentAnswers = map[string]protocol.Outcome{
	"assessment-invalid":              protocol.RecordRefused,
	"assessment-unknown-outcome":      protocol.RecordRefused,
	"assessment-schema-2":             protocol.Incompatible,
	"assessment-protocol-2":           protocol.Incompatible,
	"assessment-too-old":              protocol.RecordRefused,
	"assessment-ahead":                protocol.Disputed,
	"assessment-too-many":             protocol.BatchTooLarge,
	"assessment-agent-not-registered": protocol.AgentRefused,
	"assessment-agent-not-admitted":   protocol.AgentRefused,
	"assessment-unusable-identity":    protocol.AgentRefused,
	"assessment-malformed":            protocol.BatchUndecodable,
}

// Every assessment the installed agent made answers each check of the policy it
// ran on, in the policy's order, as the platform's contract has it, and the
// gate made it answer each outcome the contract has at least once.
func TestEveryAssessmentTheInstalledAgentMadeAnswersEveryCheckOfThePolicyItRanOn(t *testing.T) {
	scenario, order, batches := assessmentsTold(t)
	ran := map[uint64]*policyv1.Policy{}
	for _, name := range scenario.Policies {
		applied := gatePolicy(t, name)
		ran[applied.GetRevision()] = applied
	}
	outcomes, ids := map[assessmentv1.Outcome]bool{}, map[string]bool{}
	index := 0
	for _, name := range order {
		var held assessmentv1.AssessmentBatch
		if err := proto.Unmarshal(batches[name], &held); err != nil || held.GetProtocolVersion() != protocol.Version || len(held.GetAssessments()) == 0 {
			t.Fatalf("%s is not a batch of protocol %d carrying assessments: %v", name, protocol.Version, err)
		}
		for _, assessed := range held.GetAssessments() {
			told := scenario.Assessments[index]
			index++
			if err := protocol.CheckAssessment(assessed); err != nil {
				t.Errorf("assessment %s is one the platform refuses: %v", assessed.GetAssessmentId(), err)
			}
			if assessed.GetAssessmentId() != told.ID || ids[told.ID] || assessed.GetPolicyRevision() != told.Revision || !assessed.GetAssessedAt().AsTime().Equal(told.AssessedAt) {
				t.Errorf("%s carries %s of revision %d at %v, and the gate recorded %+v", name, assessed.GetAssessmentId(), assessed.GetPolicyRevision(),
					assessed.GetAssessedAt().AsTime(), told)
			}
			ids[told.ID] = true
			applied, known := ran[assessed.GetPolicyRevision()]
			if !known || assessed.GetPolicyId() != applied.GetPolicyId() {
				t.Fatalf("assessment %s answers revision %d of %s, which the gate never signed", told.ID, assessed.GetPolicyRevision(), assessed.GetPolicyId())
			}
			checks, results := applied.GetSettings().GetAssessment().GetChecks(), assessed.GetResults()
			if len(results) != len(checks) {
				t.Fatalf("assessment %s answers %d of the %d checks it ran on", told.ID, len(results), len(checks))
			}
			for position, result := range results {
				if result.GetCheckId() != checks[position].GetCheckId() || result.GetOutcome().String() != told.Outcomes[result.GetCheckId()] {
					t.Errorf("assessment %s answers %s %s where %s was asked and the gate recorded %s", told.ID, result.GetCheckId(), result.GetOutcome(),
						checks[position].GetCheckId(), told.Outcomes[checks[position].GetCheckId()])
				}
				outcomes[result.GetOutcome()] = true
			}
		}
	}
	if index != len(scenario.Assessments) {
		t.Errorf("the batches carry %d assessments, and the gate recorded %d", index, len(scenario.Assessments))
	}
	for value := range assessmentv1.Outcome_name {
		if outcome := assessmentv1.Outcome(value); outcome != assessmentv1.Outcome_OUTCOME_UNSPECIFIED && !outcomes[outcome] {
			t.Errorf("the installed agent answered no check %s", outcome)
		}
	}
}

func TestWhatARecordedPlatformAnswersTheAssessmentsOfAnInstalledAgentIsWhatTheAgentReads(t *testing.T) {
	_, order, batches := assessmentsTold(t)
	for _, recorded := range assessmentRecordings(t) {
		t.Run(filepath.Base(recorded.directory), func(t *testing.T) {
			accepted, refusals := 0, map[string]bool{}
			for _, sent := range recorded.Exchanges {
				request, reply := recorded.read(t, sent.Name+".request.pb"), recorded.read(t, sent.Name+".reply.pb")
				var held []protocol.Sent
				for _, record := range protocol.Assessments.Records(request) {
					admitted := recorded.RecordedAt
					var assessed assessmentv1.Assessment
					if proto.Unmarshal(record, &assessed) == nil && assessed.GetAssessedAt().IsValid() {
						admitted = assessed.GetAssessedAt().AsTime()
					}
					held = append(held, protocol.Sent{Record: record, Admitted: admitted})
				}
				want, refusing := assessmentAnswers[sent.Name]
				if !refusing {
					want = protocol.Durable
					index := 0
					if _, err := fmt.Sscanf(sent.Name, "assessment-%03d", &index); err != nil || !assessedBatch.MatchString(sent.Name) || index >= len(order) {
						t.Fatalf("nothing says what the agent does after %s", sent.Name)
					}
					if !bytes.Equal(request, batches[order[index]]) {
						t.Errorf("%s is not what the installed agent sent", sent.Name)
					}
					accepted++
				}
				refusals[sent.Name] = refusing
				verdict := protocol.Assessments.Judge(held, protocol.Answer{Status: sent.Status, ContentType: protocol.ContentType, Body: reply, Date: recorded.RecordedAt})
				if verdict.Outcome != want {
					t.Errorf("%s, answered %d, reads as %s: %v, and %s was expected", sent.Name, sent.Status, verdict.Outcome, verdict.Reason, want)
				}
			}
			if accepted != len(order) {
				t.Errorf("%d of the %d batches the agent sent were recorded", accepted, len(order))
			}
			for name := range assessmentAnswers {
				if !refusals[name] {
					t.Errorf("no %s was recorded", name)
				}
			}
		})
	}
}

func TestARecordedRefusalOfAnOutcomeTheAgentDeclaresIsAnIncompatibility(t *testing.T) {
	for _, recorded := range assessmentRecordings(t) {
		t.Run(filepath.Base(recorded.directory), func(t *testing.T) {
			var batch assessmentv1.AssessmentBatch
			if err := proto.Unmarshal(recorded.read(t, "assessment-unknown-outcome.request.pb"), &batch); err != nil {
				t.Fatal(err)
			}
			batch.GetAssessments()[0].GetResults()[0].Outcome = assessmentv1.Outcome_OUTCOME_NOT_APPLICABLE
			declared, err := proto.Marshal(&batch)
			if err != nil {
				t.Fatal(err)
			}
			records := protocol.Assessments.Records(declared)
			verdict := protocol.Assessments.Judge([]protocol.Sent{{Record: records[0], Admitted: batch.GetAssessments()[0].GetAssessedAt().AsTime()}},
				protocol.Answer{Status: http.StatusUnprocessableEntity, ContentType: protocol.ContentType, Body: recorded.read(t, "assessment-unknown-outcome.reply.pb"),
					Date: recorded.RecordedAt})
			found, incompatible := verdict.Reason.(*protocol.Incompatibility)
			if verdict.Outcome != protocol.Incompatible || !incompatible || found.Field != "results[0].outcome" || found.Value != "OUTCOME_NOT_APPLICABLE" {
				t.Fatalf("the refusal of a declared outcome reads as %s: %v", verdict.Outcome, verdict.Reason)
			}
		})
	}
}

// The posture of the agent a recorded platform keeps is the newest assessment
// it made, as it made it, and every assessment admitted again changes nothing.
func TestARecordedPlatformKeepsTheNewestAssessmentOfTheAgentAsItsPosture(t *testing.T) {
	scenario, _, batches := assessmentsTold(t)
	newest := scenario.Assessments[0]
	for _, told := range scenario.Assessments {
		if told.AssessedAt.After(newest.AssessedAt) {
			newest = told
		}
	}
	var made *assessmentv1.Assessment
	var held assessmentv1.AssessmentBatch
	if err := proto.Unmarshal(batches[newest.Batch], &held); err != nil {
		t.Fatal(err)
	}
	for _, assessed := range held.GetAssessments() {
		if assessed.GetAssessmentId() == newest.ID {
			made = assessed
		}
	}
	type counted struct {
		Checks        int `json:"checks"`
		Passed        int `json:"passed"`
		Failed        int `json:"failed"`
		Errors        int `json:"errors"`
		Unsupported   int `json:"unsupported"`
		NotApplicable int `json:"not_applicable"`
	}
	want := counted{Checks: len(made.GetResults())}
	for _, result := range made.GetResults() {
		switch result.GetOutcome() {
		case assessmentv1.Outcome_OUTCOME_PASS:
			want.Passed++
		case assessmentv1.Outcome_OUTCOME_FAIL:
			want.Failed++
		case assessmentv1.Outcome_OUTCOME_ERROR:
			want.Errors++
		case assessmentv1.Outcome_OUTCOME_UNSUPPORTED:
			want.Unsupported++
		case assessmentv1.Outcome_OUTCOME_NOT_APPLICABLE:
			want.NotApplicable++
		}
	}
	manifests, err := filepath.Glob(filepath.Join("testdata", "*", "assessment-store.json"))
	if err != nil || len(manifests) == 0 {
		t.Fatalf("no platform was recorded keeping what the agent assessed: %v", err)
	}
	for _, manifest := range manifests {
		type kept struct {
			Admitted    int     `json:"admitted"`
			Kept        uint64  `json:"kept_rows"`
			Posture     string  `json:"posture"`
			PostureFile string  `json:"posture_file"`
			Counts      counted `json:"posture_counts"`
		}
		var recorded struct {
			Platform struct {
				Repository string `json:"repository"`
				Commit     string `json:"commit"`
				Contracts  string `json:"contracts"`
				Broker     string `json:"broker"`
				Store      string `json:"store"`
			} `json:"platform"`
			RecordedAt time.Time `json:"recorded_at"`
			Tenant     string    `json:"tenant_id"`
			Alone      kept      `json:"alone"`
			Replayed   kept      `json:"replayed"`
		}
		content, err := os.ReadFile(manifest)
		if err == nil {
			decoder := json.NewDecoder(bytes.NewReader(content))
			decoder.DisallowUnknownFields()
			err = decoder.Decode(&recorded)
		}
		if err != nil || recorded.Platform.Commit == "" || recorded.Tenant == "" {
			t.Fatalf("decode %s: %v", manifest, err)
		}
		for name, held := range map[string]kept{"alone": recorded.Alone, "replayed": recorded.Replayed} {
			if held.Kept != uint64(len(scenario.Assessments)) || held.Posture != newest.ID || held.Counts != want {
				t.Errorf("%s: %s, the platform keeps %d assessments and the posture %s counted %+v, and the agent made %d, the newest %s counted %+v",
					manifest, name, held.Kept, held.Posture, held.Counts, len(scenario.Assessments), newest.ID, want)
			}
			content, err := os.ReadFile(filepath.Join(filepath.Dir(manifest), held.PostureFile))
			if err != nil {
				t.Fatal(err)
			}
			var posture assessmentv1.Assessment
			if err := proto.Unmarshal(content, &posture); err != nil {
				t.Fatalf("%s: %s, the posture does not decode: %v", manifest, name, err)
			}
			if posture.GetOrigin().GetTenantId() != recorded.Tenant || posture.GetOrigin().GetAgentId() != "web-01" || posture.GetReception().GetGateway() == "" {
				t.Errorf("%s: %s, the posture speaks for %v as received %v", manifest, name, posture.GetOrigin(), posture.GetReception())
			}
			posture.Origin.TenantId, posture.Origin.AgentId, posture.Reception = "", "", nil
			if !proto.Equal(&posture, made) {
				t.Errorf("%s: %s, the posture the control plane reads is not the assessment the agent made", manifest, name)
			}
		}
		if recorded.Alone.Admitted != len(scenario.Assessments) || recorded.Replayed.Admitted != 2*len(scenario.Assessments) {
			t.Errorf("%s admitted %d then %d assessments of %d", manifest, recorded.Alone.Admitted, recorded.Replayed.Admitted, len(scenario.Assessments))
		}
	}
}

// What a recorded platform publishes of the checks the installed agent ran in
// the gate and hands the agent: the checks its contracts describe, signed by a
// key the agent verifies, in a policy the agent applies. A check it does not
// describe, as a newer contract would write it, never reaches an agent.
func TestARecordedPlatformHandsTheAgentTheChecksItRanInTheGate(t *testing.T) {
	scenario, _, _ := assessmentsTold(t)
	manifests, err := filepath.Glob(filepath.Join("testdata", "*", "checklist.json"))
	if err != nil || len(manifests) == 0 {
		t.Fatalf("no platform was recorded handing the agent its checks: %v", err)
	}
	for _, manifest := range manifests {
		t.Run(filepath.Base(filepath.Dir(manifest)), func(t *testing.T) {
			var recorded struct {
				Platform struct {
					Repository string `json:"repository"`
					Commit     string `json:"commit"`
					Contracts  string `json:"contracts"`
				} `json:"platform"`
				RecordedAt   time.Time `json:"recorded_at"`
				Source       string    `json:"source"`
				Signers      string    `json:"signers"`
				Publications []struct {
					Name   string `json:"name"`
					Checks int    `json:"checks"`
					Status int    `json:"status"`
					Code   string `json:"code"`
					Detail string `json:"detail"`
				} `json:"publications"`
				Exchanges []policyExchange `json:"exchanges"`
			}
			content, err := os.ReadFile(manifest)
			if err == nil {
				decoder := json.NewDecoder(bytes.NewReader(content))
				decoder.DisallowUnknownFields()
				err = decoder.Decode(&recorded)
			}
			if err != nil || recorded.Platform.Commit == "" || len(recorded.Exchanges) != 1 || len(recorded.Publications) != 2 {
				t.Fatalf("decode %s: %v", manifest, err)
			}
			gate := gatePolicy(t, recorded.Source).GetSettings().GetAssessment().GetChecks()
			var described []*assessmentv1.Check
			newer := -1
			for index, check := range gate {
				if check.GetTest() == nil {
					newer = index
					continue
				}
				described = append(described, check)
			}
			published, refused := recorded.Publications[0], recorded.Publications[1]
			if published.Name != "checklist-published" || published.Status != http.StatusCreated || published.Checks != len(described) {
				t.Errorf("the platform published %+v of the %d checks its contracts describe", published, len(described))
			}
			if refused.Name != "checklist-newer-test" || refused.Status != http.StatusUnprocessableEntity || refused.Code != "malformed_policy" ||
				refused.Checks != len(gate) || newer < 0 {
				t.Errorf("the platform answered %+v to a checklist whose check %d it does not describe", refused, newer)
			}

			sent := recorded.Exchanges[0]
			var offered [][]byte
			follower, err := policy.New(policy.Options{
				Client:  &replaying{reply: transport.Reply{Status: sent.Status, ContentType: sent.ContentType, Body: recordedFile(t, manifest, sent.Name+".reply.pb"), Tag: sent.Tag}},
				URL:     "https://control.example:8446",
				Tag:     func() string { return "" },
				Offered: func(_ context.Context, served []byte) error { offered = append(offered, served); return nil },
				Every:   func() time.Duration { return time.Hour },
				Policy:  link.Policy{},
				Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
			})
			if err != nil {
				t.Fatal(err)
			}
			follower.Ask(t.Context())
			if got := follower.State().Answer; sent.Name != "checklist-served" || got != policy.Served || len(offered) != 1 {
				t.Fatalf("%s was read as %s", sent.Name, got)
			}
			verified, err := policyRecording{directory: filepath.Dir(manifest), Signers: recorded.Signers}.verifier(t).Verify(offered[0])
			if err != nil {
				t.Fatalf("the agent cannot verify the checks it was handed: %v", err)
			}
			if err := policy.Judge(verified, sent.AgentID, policy.Holding{}, recorded.RecordedAt); err != nil {
				t.Fatalf("the agent refuses the checks it was handed: %v", err)
			}
			made, _, err := policy.Overlay(ownConfiguration(t), verified.Policy.GetSettings())
			if err != nil || !made.Modules["assessment"].Enabled {
				t.Fatalf("the agent does not assess on the policy it was handed: %v", err)
			}
			served := verified.Policy.GetSettings().GetAssessment().GetChecks()
			if len(served) != len(described) {
				t.Fatalf("the agent was handed %d checks of the %d published", len(served), len(described))
			}
			for index, check := range served {
				if !proto.Equal(check, described[index]) {
					t.Errorf("the agent was handed %v where the gate ran %v", check, described[index])
				}
				if _, ran := scenario.Assessments[len(scenario.Assessments)-1].Outcomes[check.GetCheckId()]; !ran {
					t.Errorf("the installed agent never answered %s", check.GetCheckId())
				}
			}
		})
	}
}

func assessmentsTold(t *testing.T) (assessmentScenario, []string, map[string][]byte) {
	t.Helper()
	var scenario assessmentScenario
	content, err := os.ReadFile(filepath.Join("testdata", "assessment", "scenario.json"))
	if err == nil {
		decoder := json.NewDecoder(bytes.NewReader(content))
		decoder.DisallowUnknownFields()
		err = decoder.Decode(&scenario)
	}
	if err != nil || len(scenario.Assessments) == 0 || len(scenario.Policies) == 0 {
		t.Fatalf("read what the installed agent assessed: %v", err)
	}
	var order []string
	batches := map[string][]byte{}
	for _, told := range scenario.Assessments {
		if _, read := batches[told.Batch]; read {
			continue
		}
		batch, err := os.ReadFile(filepath.Join("testdata", "assessment", told.Batch))
		if err != nil {
			t.Fatal(err)
		}
		order, batches[told.Batch] = append(order, told.Batch), batch
	}
	return scenario, order, batches
}

func gatePolicy(t *testing.T, name string) *policyv1.Policy {
	t.Helper()
	signed := recordedFile(t, filepath.Join("testdata", "assessment", "scenario.json"), name)
	verified, err := policyRecording{directory: filepath.Join("testdata", "assessment"), Signers: "policy-signers.pem"}.verifier(t).Verify(signed)
	if err != nil {
		t.Fatalf("the gate's %s does not verify: %v", name, err)
	}
	return verified.Policy
}

func assessmentRecordings(t *testing.T) []assessmentRecording {
	t.Helper()
	manifests, err := filepath.Glob(filepath.Join("testdata", "*", "assessment.json"))
	if err != nil || len(manifests) == 0 {
		t.Fatalf("no platform was recorded answering what the agent assessed: %v", err)
	}
	var found []assessmentRecording
	for _, manifest := range manifests {
		content, err := os.ReadFile(manifest)
		if err != nil {
			t.Fatal(err)
		}
		decoder := json.NewDecoder(bytes.NewReader(content))
		decoder.DisallowUnknownFields()
		recorded := assessmentRecording{directory: filepath.Dir(manifest)}
		if err := decoder.Decode(&recorded); err != nil || recorded.Platform.Commit == "" || recorded.RecordedAt.IsZero() {
			t.Fatalf("decode %s: %v", manifest, err)
		}
		found = append(found, recorded)
	}
	return found
}

func (r assessmentRecording) read(t *testing.T, name string) []byte {
	t.Helper()
	return recordedFile(t, filepath.Join(r.directory, "assessment.json"), name)
}

func recordedFile(t *testing.T, manifest, name string) []byte {
	t.Helper()
	held, err := os.ReadFile(filepath.Join(filepath.Dir(manifest), name))
	if err != nil {
		t.Fatal(err)
	}
	return held
}
