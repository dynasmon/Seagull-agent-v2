package assessment

import (
	"errors"
	"fmt"
	"strings"

	"github.com/dynasmon/Seagull-agent-v2/internal/platform/metadata"
	assessmentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/assessment/v1"
)

var kinds = map[assessmentv1.FileTest_Kind]metadata.Kind{
	assessmentv1.FileTest_KIND_REGULAR:   metadata.Regular,
	assessmentv1.FileTest_KIND_DIRECTORY: metadata.Directory,
	assessmentv1.FileTest_KIND_SYMLINK:   metadata.Symlink,
}

func (r *round) file(test *assessmentv1.FileTest) (assessmentv1.Outcome, string) {
	path, presence := test.GetPath(), test.GetPresence()
	node, err := r.host.Describe(path)
	switch {
	case errors.Is(err, metadata.ErrAbsent):
		return absent(presence, path+" is not there")
	case errors.Is(err, metadata.ErrHidden):
		return assessmentv1.Outcome_OUTCOME_ERROR, fmt.Sprintf("the agent's service hides %s from it: a drop-in for seagull-agent.service that sets ProtectHome=read-only lets the agent see it", path)
	case errors.Is(err, metadata.ErrDenied):
		return assessmentv1.Outcome_OUTCOME_ERROR, fmt.Sprintf("the agent's account cannot reach %s, as %s: a drop-in for seagull-agent.service that grants CAP_DAC_READ_SEARCH lets it",
			path, strings.TrimPrefix(told(err), metadata.ErrDenied.Error()+": "))
	case errors.Is(err, errors.ErrUnsupported):
		return assessmentv1.Outcome_OUTCOME_UNSUPPORTED, "the agent does not describe a path on this platform"
	case err != nil:
		return assessmentv1.Outcome_OUTCOME_ERROR, told(err)
	}
	seen := fmt.Sprintf("%s is a %s owned by %d:%d with permissions %04o", path, node.Kind, node.User, node.Group, node.Permissions)
	if presence == assessmentv1.Presence_PRESENCE_FORBIDDEN {
		return assessmentv1.Outcome_OUTCOME_FAIL, seen
	}
	var wrong []string
	if kind := test.GetKind(); kind != assessmentv1.FileTest_KIND_UNSPECIFIED && kinds[kind] != node.Kind {
		wrong = append(wrong, "it is not a "+kinds[kind].String())
	}
	if test.UserId != nil && node.User != test.GetUserId() {
		wrong = append(wrong, fmt.Sprintf("its owner is not %d", test.GetUserId()))
	}
	if test.GroupId != nil && node.Group != test.GetGroupId() {
		wrong = append(wrong, fmt.Sprintf("its group is not %d", test.GetGroupId()))
	}
	if test.Permissions != nil && node.Permissions&^test.GetPermissions() != 0 {
		wrong = append(wrong, fmt.Sprintf("its permissions go beyond %04o", test.GetPermissions()))
	}
	if len(wrong) > 0 {
		return assessmentv1.Outcome_OUTCOME_FAIL, seen + ": " + strings.Join(wrong, ", ")
	}
	return assessmentv1.Outcome_OUTCOME_PASS, seen
}

// absent is what a check makes of something the host does not have, by what
// the check says its absence means.
func absent(presence assessmentv1.Presence, seen string) (assessmentv1.Outcome, string) {
	switch presence {
	case assessmentv1.Presence_PRESENCE_REQUIRED:
		return assessmentv1.Outcome_OUTCOME_FAIL, seen
	case assessmentv1.Presence_PRESENCE_FORBIDDEN:
		return assessmentv1.Outcome_OUTCOME_PASS, seen
	}
	return assessmentv1.Outcome_OUTCOME_NOT_APPLICABLE, seen
}
