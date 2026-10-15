package protocol

import (
	"fmt"
	"math"
	"strings"
	"unicode/utf8"

	assessmentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/assessment/v1"
)

// What the platform admits of an assessment beyond the shape of its contract:
// a batch of at most MaxAssessmentsPerBatch of them, each answering at most
// MaxAssessmentResults checks with evidence of at most MaxAssessmentEvidence
// bytes.
const (
	MaxAssessmentsPerBatch = 16
	MaxAssessmentResults   = 512
	MaxAssessmentEvidence  = 512
	minAssessmentID        = 8
)

// CheckAssessment refuses what the platform would refuse of an assessment
// whatever moment it reached it, naming the field as the platform names it.
func CheckAssessment(assessment *assessmentv1.Assessment) error {
	id, results := assessment.GetAssessmentId(), assessment.GetResults()
	switch {
	case len(id) < minAssessmentID || len(id) > maxIdentifier || !identifier.MatchString(id):
		return &Inadmissible{Field: "assessment_id", Reason: "is missing or malformed"}
	case assessment.GetSchemaVersion() != AssessmentSchemaVersion:
		return &Inadmissible{Field: "schema_version", Reason: fmt.Sprintf("is not %d", AssessmentSchemaVersion)}
	case !identifier.MatchString(assessment.GetPolicyId()) || strings.Contains(assessment.GetPolicyId(), ":"):
		return &Inadmissible{Field: "policy_id", Reason: "is missing or malformed"}
	case assessment.GetPolicyRevision() == 0 || assessment.GetPolicyRevision() > math.MaxInt64:
		return &Inadmissible{Field: "policy_revision", Reason: "is not a revision"}
	case !assessment.GetAssessedAt().IsValid():
		return &Inadmissible{Field: "assessed_at", Reason: "is not a moment"}
	case len(results) > MaxAssessmentResults:
		return &Inadmissible{Field: "results", Reason: fmt.Sprintf("carries %d results and the platform takes %d", len(results), MaxAssessmentResults)}
	}
	host := assessment.GetOrigin().GetHost()
	if err := firstOf(
		text("origin.host.hostname", host.GetHostname(), maxHostname, false),
		text("origin.host.os", host.GetOs(), maxOperatingSystem, false),
		text("origin.host.architecture", host.GetArchitecture(), maxArchitecture, false),
		hostAddress(host),
		text("collection.collector", assessment.GetCollection().GetCollector(), maxCollector, true),
		text("collection.source", assessment.GetCollection().GetSource(), maxCollection, false),
	); err != nil {
		return err
	}
	answered := make(map[string]bool, len(results))
	for index, result := range results {
		field := fmt.Sprintf("results[%d]", index)
		check, outcome, evidence := result.GetCheckId(), result.GetOutcome(), result.GetEvidence()
		switch {
		case !identifier.MatchString(check) || strings.Contains(check, ":"):
			return &Inadmissible{Field: field + ".check_id", Reason: "is missing or malformed"}
		case answered[check]:
			return &Inadmissible{Field: field + ".check_id", Reason: "answers a check another result already answers"}
		case outcome == assessmentv1.Outcome_OUTCOME_UNSPECIFIED || assessmentv1.Outcome_name[int32(outcome)] == "":
			return &Inadmissible{Field: field + ".outcome", Reason: "is not an outcome the contract declares"}
		case len(evidence) > MaxAssessmentEvidence || !utf8.ValidString(evidence) || strings.ContainsRune(evidence, 0):
			return &Inadmissible{Field: field + ".evidence", Reason: fmt.Sprintf("is not text of at most %d bytes", MaxAssessmentEvidence)}
		}
		answered[check] = true
	}
	return nil
}
