package protocol_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-agent-v2/internal/protocol"
	assessmentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/assessment/v1"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	ingestv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/ingest/v1"
)

var assessedAt = time.Date(2026, time.October, 15, 12, 0, 0, 0, time.UTC)

func assessed() *assessmentv1.Assessment {
	return &assessmentv1.Assessment{
		AssessmentId:   "4c1d9a2e-7b3f-8e5a-9c0d-1e2f3a4b5c6d",
		SchemaVersion:  protocol.AssessmentSchemaVersion,
		PolicyId:       "linux-baseline",
		PolicyRevision: 3,
		AssessedAt:     timestamppb.New(assessedAt),
		Origin:         &eventv1.Origin{Host: &eventv1.Host{Hostname: "web-01", Os: "linux", Architecture: "amd64"}},
		Collection:     &eventv1.Collection{Collector: "assessment"},
		Results: []*assessmentv1.Result{
			{CheckId: "ssh.root-login", Outcome: assessmentv1.Outcome_OUTCOME_FAIL, Evidence: "PermitRootLogin is yes"},
			{CheckId: "cramfs", Outcome: assessmentv1.Outcome_OUTCOME_PASS},
		},
	}
}

func TestAnAssessmentThePlatformAdmitsIsCheckedAndOneItRefusesIsNamed(t *testing.T) {
	if err := protocol.CheckAssessment(assessed()); err != nil {
		t.Fatalf("an admissible assessment was refused: %v", err)
	}
	empty := assessed()
	empty.Results = nil
	if err := protocol.CheckAssessment(empty); err != nil {
		t.Fatalf("an assessment answering no check was refused: %v", err)
	}
	many := assessed()
	many.Results = nil
	for index := range protocol.MaxAssessmentResults {
		many.Results = append(many.Results, &assessmentv1.Result{CheckId: fmt.Sprintf("check-%d", index), Outcome: assessmentv1.Outcome_OUTCOME_PASS,
			Evidence: strings.Repeat("e", protocol.MaxAssessmentEvidence)})
	}
	if err := protocol.CheckAssessment(many); err != nil {
		t.Fatalf("an assessment at every bound was refused: %v", err)
	}

	for name, one := range map[string]struct {
		change func(*assessmentv1.Assessment)
		field  string
	}{
		"short identifier":    {func(a *assessmentv1.Assessment) { a.AssessmentId = "4c1d9a2" }, "assessment_id"},
		"spaced identifier":   {func(a *assessmentv1.Assessment) { a.AssessmentId = "4c1d 9a2e" }, "assessment_id"},
		"schema":              {func(a *assessmentv1.Assessment) { a.SchemaVersion = 2 }, "schema_version"},
		"no policy":           {func(a *assessmentv1.Assessment) { a.PolicyId = "" }, "policy_id"},
		"policy with a colon": {func(a *assessmentv1.Assessment) { a.PolicyId = "linux:web" }, "policy_id"},
		"no revision":         {func(a *assessmentv1.Assessment) { a.PolicyRevision = 0 }, "policy_revision"},
		"no moment":           {func(a *assessmentv1.Assessment) { a.AssessedAt = nil }, "assessed_at"},
		"no collector":        {func(a *assessmentv1.Assessment) { a.Collection = nil }, "collection.collector"},
		"long hostname":       {func(a *assessmentv1.Assessment) { a.Origin.Host.Hostname = strings.Repeat("h", 256) }, "origin.host.hostname"},
		"malformed check":     {func(a *assessmentv1.Assessment) { a.Results[1].CheckId = "cram fs" }, "results[1].check_id"},
		"check twice":         {func(a *assessmentv1.Assessment) { a.Results[1].CheckId = "ssh.root-login" }, "results[1].check_id"},
		"no outcome":          {func(a *assessmentv1.Assessment) { a.Results[0].Outcome = assessmentv1.Outcome_OUTCOME_UNSPECIFIED }, "results[0].outcome"},
		"undeclared outcome":  {func(a *assessmentv1.Assessment) { a.Results[0].Outcome = assessmentv1.Outcome(9) }, "results[0].outcome"},
		"long evidence": {func(a *assessmentv1.Assessment) {
			a.Results[0].Evidence = strings.Repeat("e", protocol.MaxAssessmentEvidence+1)
		}, "results[0].evidence"},
		"too many results": {func(a *assessmentv1.Assessment) {
			a.Results = append(append([]*assessmentv1.Result{}, many.Results...), many.Results[0])
		}, "results"},
	} {
		t.Run(name, func(t *testing.T) {
			changed := proto.Clone(assessed()).(*assessmentv1.Assessment)
			one.change(changed)
			var refused *protocol.Inadmissible
			if err := protocol.CheckAssessment(changed); !errors.As(err, &refused) || refused.Field != one.field {
				t.Fatalf("the assessment was answered %v, and the platform refuses %s", err, one.field)
			}
		})
	}
}

func TestAnAssessmentBatchCarriesTheAssessmentAsItWasEncoded(t *testing.T) {
	encoded, err := proto.Marshal(assessed())
	if err != nil {
		t.Fatalf("encode an assessment: %v", err)
	}
	if protocol.Assessments.Path() != "/v1/assessments" || protocol.Assessments.String() != "assessments" {
		t.Fatalf("the assessments route is %s at %s", protocol.Assessments, protocol.Assessments.Path())
	}
	var batch assessmentv1.AssessmentBatch
	if err := proto.Unmarshal(protocol.Assessments.Batch("assessment-7", [][]byte{encoded}), &batch); err != nil {
		t.Fatalf("decode the batch: %v", err)
	}
	if batch.GetBatchId() != "assessment-7" || batch.GetProtocolVersion() != protocol.Version || len(batch.GetAssessments()) != 1 ||
		!proto.Equal(batch.GetAssessments()[0], assessed()) {
		t.Fatalf("the batch carries %+v", &batch)
	}
	identity, err := protocol.Assessments.Identify(encoded)
	if err != nil || identity.ID != assessed().GetAssessmentId() || identity.Items != 0 {
		t.Fatalf("the assessment is identified as %+v: %v", identity, err)
	}
}

func TestWhatThePlatformAnswersAnAssessmentIsJudgedAsForAnyBatch(t *testing.T) {
	encoded, err := proto.Marshal(assessed())
	if err != nil {
		t.Fatalf("encode an assessment: %v", err)
	}
	sent := []protocol.Sent{{Record: encoded, Admitted: assessedAt}}
	answered := func(status int, message proto.Message) protocol.Answer {
		body, err := proto.Marshal(message)
		if err != nil {
			t.Fatalf("encode an answer: %v", err)
		}
		return protocol.Answer{Status: status, ContentType: protocol.ContentType, Body: body, Date: assessedAt.Add(time.Minute)}
	}
	for name, one := range map[string]struct {
		answer protocol.Answer
		want   protocol.Outcome
	}{
		"acknowledged":      {answered(200, &ingestv1.BatchAck{Accepted: true, Durable: true, Received: 1}), protocol.Durable},
		"counted short":     {answered(200, &ingestv1.BatchAck{Accepted: true, Durable: true}), protocol.Unconfirmed},
		"refused":           {answered(422, &ingestv1.Rejection{Code: "invalid_assessment", Field: "results[0].evidence", EventIndex: 0}), protocol.RecordRefused},
		"refused as a kind": {answered(422, &ingestv1.Rejection{Code: "invalid_report", Field: "results", EventIndex: 0}), protocol.Unexpected},
		"not admitted":      {answered(403, &ingestv1.Rejection{Code: "agent_not_admitted", EventIndex: -1}), protocol.AgentRefused},
		"unavailable":       {answered(503, &ingestv1.Rejection{Code: "backbone_unavailable", EventIndex: -1}), protocol.Unconfirmed},
		"rate limited":      {answered(429, &ingestv1.Rejection{Code: "rate_limited", EventIndex: -1}), protocol.Busy},
		"protocol":          {answered(426, &ingestv1.Rejection{Code: "unsupported_protocol_version", EventIndex: -1}), protocol.Incompatible},
		"schema":            {answered(422, &ingestv1.Rejection{Code: "invalid_assessment", Field: "schema_version", EventIndex: 0}), protocol.Incompatible},
		"not served":        {protocol.Answer{Status: 404, ContentType: "text/plain", Body: []byte("404 page not found"), Date: assessedAt}, protocol.Unexpected},
		"from the future":   {answered(422, &ingestv1.Rejection{Code: "invalid_assessment", Field: "assessed_at", EventIndex: 0}), protocol.RecordRefused},
	} {
		t.Run(name, func(t *testing.T) {
			if got := protocol.Assessments.Judge(sent, one.answer); got.Outcome != one.want {
				t.Fatalf("judged %s: %v", got.Outcome, got.Reason)
			}
		})
	}
}
