package assessment

import (
	"os"
	"path/filepath"
	"testing"
	"unicode/utf8"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-agent-v2/internal/protocol"
	assessmentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/assessment/v1"
	policyv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/policy/v1"
)

// Whatever a check a policy carries asks, the agent answers it with one of the
// outcomes the contract names, under its own identifier, with evidence a
// result can carry, and the same way each time it is asked.
func FuzzAnswer(f *testing.F) {
	policies, err := filepath.Glob("../../../tests/compatibility/testdata/assessment/policy-*.pb")
	if err != nil || len(policies) == 0 {
		f.Fatalf("find the policies the native gate signed: %v", err)
	}
	for _, named := range policies {
		served, err := os.ReadFile(named)
		if err != nil {
			f.Fatal(err)
		}
		var envelope policyv1.SignedPolicy
		var held policyv1.Policy
		if err := proto.Unmarshal(served, &envelope); err != nil {
			f.Fatal(err)
		}
		if err := proto.Unmarshal(envelope.GetPayload(), &held); err != nil {
			f.Fatal(err)
		}
		for _, check := range held.GetSettings().GetAssessment().GetChecks() {
			content, err := proto.Marshal(check)
			if err != nil {
				f.Fatal(err)
			}
			f.Add(content)
		}
	}
	f.Fuzz(func(t *testing.T, content []byte) {
		var check assessmentv1.Check
		if proto.Unmarshal(content, &check) != nil {
			return
		}
		answered := newRound(t.Context(), newHost(), []*assessmentv1.Check{&check}).answer(&check)
		again := newRound(t.Context(), newHost(), []*assessmentv1.Check{&check}).answer(&check)
		switch {
		case answered.GetOutcome() == assessmentv1.Outcome_OUTCOME_UNSPECIFIED || assessmentv1.Outcome_name[int32(answered.GetOutcome())] == "":
			t.Fatalf("check %q was answered %v", check.GetCheckId(), answered.GetOutcome())
		case answered.GetCheckId() != check.GetCheckId():
			t.Fatalf("check %q was answered as %q", check.GetCheckId(), answered.GetCheckId())
		case len(answered.GetEvidence()) > protocol.MaxAssessmentEvidence || !utf8.ValidString(answered.GetEvidence()):
			t.Fatalf("check %q was answered with %d bytes of evidence", check.GetCheckId(), len(answered.GetEvidence()))
		case unread(&check) != nil && answered.GetOutcome() != assessmentv1.Outcome_OUTCOME_UNSUPPORTED:
			t.Fatalf("check %q, which the agent does not read, was answered %v", check.GetCheckId(), answered.GetOutcome())
		case !proto.Equal(answered, again):
			t.Fatalf("check %q was answered %v and then %v", check.GetCheckId(), answered, again)
		}
	})
}
