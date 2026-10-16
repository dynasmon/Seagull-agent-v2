package assessment

import (
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-agent-v2/internal/protocol"
	assessmentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/assessment/v1"
)

const installation = "6f1c2d3e-4a5b-4c6d-8e7f-0a1b2c3d4e5f"

var (
	madeAt    = time.Date(2026, time.October, 15, 12, 0, 0, 0, time.UTC)
	uuidShape = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-8[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
)

func results() []*assessmentv1.Result {
	return []*assessmentv1.Result{
		{CheckId: "ssh.root-login", Outcome: fail, Evidence: `PermitRootLogin is "yes" at /etc/ssh/sshd_config line 33`},
		{CheckId: "forwarding", Outcome: pass, Evidence: `net.ipv4.ip_forward is "0"`},
		{CheckId: "cramfs", Outcome: inapplicable},
	}
}

func TestAnAssessmentIsWhatThePlatformAdmitsAndSaysTheSameWheneverItIsMade(t *testing.T) {
	asked := Asked{PolicyID: "linux-baseline", Revision: 7}
	made, err := Make(installation, asked, results(), madeAt, "web-01")
	if err != nil {
		t.Fatalf("make the assessment: %v", err)
	}
	record := made.Record
	if !uuidShape.MatchString(record.GetAssessmentId()) || record.GetPolicyId() != "linux-baseline" || record.GetPolicyRevision() != 7 ||
		!record.GetAssessedAt().AsTime().Equal(madeAt) || record.GetSchemaVersion() != protocol.AssessmentSchemaVersion ||
		record.GetCollection().GetCollector() != Name || record.GetOrigin().GetHost().GetHostname() != "web-01" || len(record.GetResults()) != 3 {
		t.Fatalf("the assessment reads %v", record)
	}
	var decoded assessmentv1.Assessment
	if err := proto.Unmarshal(made.Encoded, &decoded); err != nil || !proto.Equal(&decoded, record) {
		t.Fatalf("the assessment is admitted as other bytes than it is: %v", err)
	}
	if made.Counts != (Counts{Passed: 1, Failed: 1, NotApplicable: 1}) {
		t.Fatalf("the outcomes are counted as %+v", made.Counts)
	}

	later, err := Make(installation, asked, results(), madeAt.Add(time.Hour), "web-01-renamed")
	if err != nil || later.Digest != made.Digest || later.Record.GetAssessmentId() == record.GetAssessmentId() {
		t.Fatalf("the same findings an hour later read as digest %s and identifier %s: %v", later.Digest, later.Record.GetAssessmentId(), err)
	}
	again, _ := Make(installation, asked, results(), madeAt, "web-01")
	if again.Record.GetAssessmentId() != record.GetAssessmentId() {
		t.Fatal("the same assessment made at the same moment is named twice")
	}
	other := results()
	other[1].Outcome = fail
	if changed, _ := Make(installation, asked, other, madeAt, "web-01"); changed.Digest == made.Digest {
		t.Fatal("findings that changed say the same as before")
	}
	if revised, _ := Make(installation, Asked{PolicyID: "linux-baseline", Revision: 8}, results(), madeAt, "web-01"); revised.Digest == made.Digest {
		t.Fatal("the same findings under another revision say the same as before")
	}
}

func TestAnAssessmentThePlatformWouldRefuseIsNotMade(t *testing.T) {
	twice := results()
	twice[2].CheckId = "forwarding"
	if _, err := Make(installation, Asked{PolicyID: "linux-baseline", Revision: 7}, twice, madeAt, "web-01"); !refusedAt(err, "results[2].check_id") {
		t.Fatalf("an assessment answering one check twice was answered %v", err)
	}
	long := results()
	long[0].Evidence = strings.Repeat("e", protocol.MaxAssessmentEvidence+1)
	if _, err := Make(installation, Asked{PolicyID: "linux-baseline", Revision: 7}, long, madeAt, "web-01"); !refusedAt(err, "results[0].evidence") {
		t.Fatalf("an assessment with evidence beyond its bound was answered %v", err)
	}
}

func refusedAt(err error, field string) bool {
	var refused *protocol.Inadmissible
	return errors.As(err, &refused) && refused.Field == field
}
