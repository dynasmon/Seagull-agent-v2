package protocol_test

import (
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-agent-v2/internal/protocol"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	ingestv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/ingest/v1"
)

var written = time.Date(2026, time.October, 11, 12, 0, 0, 0, time.UTC)

func report() *agentv1.Status {
	return &agentv1.Status{
		SchemaVersion:  protocol.StatusSchemaVersion,
		InstallationId: "2f1d6c1e-6b0a-4f4e-9b8e-6d1c2a3b4c5d",
		Sequence:       3,
		ReportedAt:     timestamppb.New(written),
		Interval:       durationpb.New(time.Minute),
		Origin:         &eventv1.Origin{Host: &eventv1.Host{Hostname: "web-01", Os: "linux", Architecture: "amd64"}},
		Run:            &agentv1.Status_Run{BootId: "5f0c4a59-0c1a-4a8e-8f53-1b2c3d4e5f60", StartedAt: timestamppb.New(written.Add(-time.Hour)), PreviousEnding: agentv1.Status_ENDING_NONE},
		Build:          &agentv1.Status_Build{Version: "(devel)", Toolchain: "go1.26.9", Os: "linux", Architecture: "amd64"},
		Condition:      agentv1.Status_CONDITION_RUNNING,
		Components:     []*agentv1.Status_Component{{Name: "delivery", Condition: agentv1.Status_CONDITION_RUNNING}},
		Modules:        []*agentv1.Status_Module{{Name: "files", Condition: agentv1.Status_CONDITION_DISABLED}},
		Spool:          &agentv1.Status_Spool{MaxBytes: 1 << 29, Streams: []*agentv1.Status_Stream{{Name: "events"}}},
		Configuration:  &agentv1.Status_Configuration{DigestSha256: strings.Repeat("0a", 32)},
		Privileges:     &agentv1.Status_Privileges{User: "997", Groups: []string{"997"}, Seccomp: "filter"},
	}
}

func TestCutKeepsTextWithinItsBoundOnACharacterAndSaysSo(t *testing.T) {
	if got := protocol.Cut("the platform does not answer", 64); got != "the platform does not answer" {
		t.Errorf("text within its bound became %q", got)
	}
	long := strings.Repeat("é", protocol.MaxStatusText)
	cut := protocol.Cut(long, protocol.MaxStatusText)
	if len(cut) > protocol.MaxStatusText || !utf8.ValidString(cut) || !strings.HasSuffix(cut, "...") {
		t.Errorf("a long reason was cut to %d bytes, valid %t: %q", len(cut), utf8.ValidString(cut), cut[len(cut)-8:])
	}
	if got := protocol.Cut("abcdef", 2); got != ".." {
		t.Errorf("a bound narrower than the mark kept %q", got)
	}
}

func TestAReportThePlatformAdmitsIsCheckedAndOneItRefusesIsNamed(t *testing.T) {
	if err := protocol.CheckStatus(report()); err != nil {
		t.Fatalf("a well formed report was refused: %v", err)
	}
	for name, one := range map[string]struct {
		change func(*agentv1.Status)
		field  string
	}{
		"schema":            {func(r *agentv1.Status) { r.SchemaVersion = 2 }, "schema_version"},
		"installation":      {func(r *agentv1.Status) { r.InstallationId = "not one" }, "installation_id"},
		"sequence":          {func(r *agentv1.Status) { r.Sequence = 0 }, "sequence"},
		"interval":          {func(r *agentv1.Status) { r.Interval = durationpb.New(time.Second) }, "interval"},
		"start":             {func(r *agentv1.Status) { r.Run.StartedAt = nil }, "run.started_at"},
		"digest":            {func(r *agentv1.Status) { r.Configuration.DigestSha256 = strings.Repeat("0A", 32) }, "configuration.digest_sha256"},
		"condition":         {func(r *agentv1.Status) { r.Condition = agentv1.Status_CONDITION_UNSPECIFIED }, "condition"},
		"component reason":  {func(r *agentv1.Status) { r.Components[0].Reason = strings.Repeat("r", protocol.MaxStatusText+1) }, "components[0].reason"},
		"module name":       {func(r *agentv1.Status) { r.Modules[0].Name = strings.Repeat("m", protocol.MaxStatusName+1) }, "modules[0].name"},
		"too many groups":   {func(r *agentv1.Status) { r.Privileges.Groups = make([]string, protocol.MaxStatusGroups+1) }, "privileges.groups"},
		"empty capability":  {func(r *agentv1.Status) { r.Privileges.Capabilities = []string{""} }, "privileges.capabilities[0]"},
		"undeclared ending": {func(r *agentv1.Status) { r.Run.PreviousEnding = agentv1.Status_Ending(9) }, "run.previous_ending"},
	} {
		t.Run(name, func(t *testing.T) {
			changed := report()
			one.change(changed)
			var refused *protocol.Inadmissible
			if err := protocol.CheckStatus(changed); !errors.As(err, &refused) || refused.Field != one.field {
				t.Fatalf("refused with %v, and the fault is in %s", err, one.field)
			}
		})
	}
}

func TestAStatusBatchCarriesTheReportAsItWasEncoded(t *testing.T) {
	encoded, err := proto.Marshal(report())
	if err != nil {
		t.Fatalf("encode a report: %v", err)
	}
	if protocol.Status.Path() != "/v1/status" || protocol.Status.String() != "status" {
		t.Fatalf("the status route is %s at %s", protocol.Status, protocol.Status.Path())
	}
	var batch agentv1.StatusBatch
	if err := proto.Unmarshal(protocol.Status.Batch("status-7", [][]byte{encoded}), &batch); err != nil {
		t.Fatalf("decode the batch: %v", err)
	}
	if batch.GetBatchId() != "status-7" || batch.GetProtocolVersion() != protocol.Version || len(batch.GetReports()) != 1 || !proto.Equal(batch.GetReports()[0], report()) {
		t.Fatalf("the batch carries %+v", &batch)
	}
}

func TestWhatThePlatformAnswersAReportIsJudgedAsForAnyBatch(t *testing.T) {
	encoded, err := proto.Marshal(report())
	if err != nil {
		t.Fatalf("encode a report: %v", err)
	}
	sent := []protocol.Sent{{Record: encoded, Admitted: written}}
	answered := func(status int, message proto.Message) protocol.Answer {
		body, err := proto.Marshal(message)
		if err != nil {
			t.Fatalf("encode an answer: %v", err)
		}
		return protocol.Answer{Status: status, ContentType: protocol.ContentType, Body: body, Date: written}
	}
	for name, one := range map[string]struct {
		answer protocol.Answer
		want   protocol.Outcome
	}{
		"acknowledged":    {answered(200, &ingestv1.BatchAck{Accepted: true, Durable: true, Received: 1}), protocol.Durable},
		"counted short":   {answered(200, &ingestv1.BatchAck{Accepted: true, Durable: true}), protocol.Unconfirmed},
		"refused":         {answered(422, &ingestv1.Rejection{Code: "invalid_report", Field: "interval", EventIndex: 0}), protocol.RecordRefused},
		"not admitted":    {answered(403, &ingestv1.Rejection{Code: "agent_not_admitted", EventIndex: -1}), protocol.AgentRefused},
		"unavailable":     {answered(503, &ingestv1.Rejection{Code: "backbone_unavailable", EventIndex: -1}), protocol.Unconfirmed},
		"rate limited":    {answered(429, &ingestv1.Rejection{Code: "rate_limited", EventIndex: -1}), protocol.Busy},
		"protocol":        {answered(426, &ingestv1.Rejection{Code: "unsupported_protocol_version", EventIndex: -1}), protocol.Incompatible},
		"not served":      {protocol.Answer{Status: 404, ContentType: "text/plain", Body: []byte("404 page not found"), Date: written}, protocol.Unexpected},
		"from the future": {answered(422, &ingestv1.Rejection{Code: "invalid_report", Field: "reported_at", EventIndex: 0}), protocol.RecordRefused},
	} {
		t.Run(name, func(t *testing.T) {
			if got := protocol.Status.Judge(sent, one.answer); got.Outcome != one.want {
				t.Fatalf("judged %s: %v", got.Outcome, got.Reason)
			}
		})
	}
}
