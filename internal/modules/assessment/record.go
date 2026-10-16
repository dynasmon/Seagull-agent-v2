package assessment

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"runtime"
	"strconv"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-agent-v2/internal/protocol"
	assessmentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/assessment/v1"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

const Name = "assessment"

// Asked is what the policy in force asks the agent to assess: its identity
// and the checks it carries, none when it carries no checklist. An empty
// PolicyID is no policy in force.
type Asked struct {
	PolicyID string
	Revision uint64
	Checks   []*assessmentv1.Check
}

type Counts struct {
	Passed        int
	Failed        int
	Errors        int
	Unsupported   int
	NotApplicable int
}

func counted(results []*assessmentv1.Result) Counts {
	var held Counts
	for _, result := range results {
		switch result.GetOutcome() {
		case assessmentv1.Outcome_OUTCOME_PASS:
			held.Passed++
		case assessmentv1.Outcome_OUTCOME_FAIL:
			held.Failed++
		case assessmentv1.Outcome_OUTCOME_ERROR:
			held.Errors++
		case assessmentv1.Outcome_OUTCOME_UNSUPPORTED:
			held.Unsupported++
		case assessmentv1.Outcome_OUTCOME_NOT_APPLICABLE:
			held.NotApplicable++
		}
	}
	return held
}

// An Assessment as the agent admits it: the record, the bytes it is admitted
// as, and the digest of what it says, which leaves out when it was made and
// under which identifier.
type Assessment struct {
	Record  *assessmentv1.Assessment
	Encoded []byte
	Digest  string
	Counts  Counts
}

// Make writes the results of one round as an assessment the platform would
// admit, or says why it would not.
func Make(installation string, asked Asked, results []*assessmentv1.Result, at time.Time, hostname string) (Assessment, error) {
	record := &assessmentv1.Assessment{
		AssessmentId:   identify(installation, asked, at),
		SchemaVersion:  protocol.AssessmentSchemaVersion,
		PolicyId:       asked.PolicyID,
		PolicyRevision: asked.Revision,
		AssessedAt:     timestamppb.New(at),
		Origin:         &eventv1.Origin{Host: &eventv1.Host{Hostname: hostname, Os: runtime.GOOS, Architecture: runtime.GOARCH}},
		Collection:     &eventv1.Collection{Collector: Name},
		Results:        results,
	}
	if err := protocol.CheckAssessment(record); err != nil {
		return Assessment{}, err
	}
	deterministic := proto.MarshalOptions{Deterministic: true}
	encoded, err := deterministic.Marshal(record)
	if err != nil {
		return Assessment{}, fmt.Errorf("encode the assessment: %w", err)
	}
	stated, err := deterministic.Marshal(&assessmentv1.Assessment{PolicyId: asked.PolicyID, PolicyRevision: asked.Revision, Results: results})
	if err != nil {
		return Assessment{}, fmt.Errorf("encode the assessment: %w", err)
	}
	digest := sha256.Sum256(stated)
	return Assessment{Record: record, Encoded: encoded, Digest: hex.EncodeToString(digest[:]), Counts: counted(results)}, nil
}

func identify(installation string, asked Asked, at time.Time) string {
	sum := sha256.Sum256(bytes.Join([][]byte{
		[]byte("seagull-agent/" + Name), []byte(installation), []byte(asked.PolicyID),
		[]byte(strconv.FormatUint(asked.Revision, 10)), []byte(at.UTC().Format(time.RFC3339Nano)),
	}, []byte{0}))
	sum[6] = sum[6]&0x0f | 0x80
	sum[8] = sum[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", sum[0:4], sum[4:6], sum[6:8], sum[8:10], sum[10:16])
}
