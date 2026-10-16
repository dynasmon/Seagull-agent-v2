package assessment

import (
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	assessmentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/assessment/v1"
)

func TestAPathIsJudgedFromWhatTheKernelShowsOfIt(t *testing.T) {
	host := newHost()
	regular, directory, link := assessmentv1.FileTest_KIND_REGULAR, assessmentv1.FileTest_KIND_DIRECTORY, assessmentv1.FileTest_KIND_SYMLINK
	expect(t, host, map[string]struct {
		test any
		want answered
	}{
		"shadow as it should be": {&assessmentv1.FileTest{Path: "/etc/shadow", Presence: required, Kind: regular, UserId: proto.Uint32(0), GroupId: proto.Uint32(42), Permissions: proto.Uint32(0o640)},
			answered{pass, "/etc/shadow is a regular file owned by 0:42 with permissions 0640"}},
		"passwd too open": {&assessmentv1.FileTest{Path: "/etc/passwd", Permissions: proto.Uint32(0o600)},
			answered{fail, "its permissions go beyond 0600"}},
		"crontab of another group": {&assessmentv1.FileTest{Path: "/etc/crontab", GroupId: proto.Uint32(42), UserId: proto.Uint32(1)},
			answered{fail, "its owner is not 1, its group is not 42"}},
		"setuid beyond": {&assessmentv1.FileTest{Path: "/usr/bin/sudo", Permissions: proto.Uint32(0o755)},
			answered{fail, "permissions 4755"}},
		"setuid allowed": {&assessmentv1.FileTest{Path: "/usr/bin/sudo", Permissions: proto.Uint32(0o4755)},
			answered{pass, "permissions 4755"}},
		"a link judged as a link": {&assessmentv1.FileTest{Path: "/etc/mtab", Kind: regular},
			answered{fail, "it is not a regular file"}},
		"a link that should be one": {&assessmentv1.FileTest{Path: "/etc/mtab", Kind: link},
			answered{pass, "symbolic link"}},
		"a directory": {&assessmentv1.FileTest{Path: "/etc", Kind: directory},
			answered{pass, "/etc is a directory"}},
		"absent and required": {&assessmentv1.FileTest{Path: "/etc/issue.net", Presence: required},
			answered{fail, "/etc/issue.net is not there"}},
		"absent and forbidden": {&assessmentv1.FileTest{Path: "/etc/hosts.equiv", Presence: forbidden},
			answered{pass, "/etc/hosts.equiv is not there"}},
		"present and forbidden": {&assessmentv1.FileTest{Path: "/etc/crontab", Presence: forbidden},
			answered{fail, "/etc/crontab is a regular file"}},
		"absent and judged only where present": {&assessmentv1.FileTest{Path: "/etc/cron.allow", Permissions: proto.Uint32(0o640)},
			answered{inapplicable, "/etc/cron.allow is not there"}},
		"hidden by the service": {&assessmentv1.FileTest{Path: "/root", Permissions: proto.Uint32(0o700)},
			answered{erred, "the agent's service hides /root from it: a drop-in for seagull-agent.service that sets ProtectHome=read-only"}},
		"below a directory it cannot search": {&assessmentv1.FileTest{Path: "/etc/ssl/private/server.key", Permissions: proto.Uint32(0o600)},
			answered{erred, "/etc/ssl/private cannot be searched: a drop-in for seagull-agent.service that grants CAP_DAC_READ_SEARCH"}},
		"a path made up by the kernel": {&assessmentv1.FileTest{Path: "/proc/1/status", Presence: required},
			answered{unsupported, "its path is within /proc"}},
		"a path to resolve": {&assessmentv1.FileTest{Path: "/etc/../etc/shadow", Presence: required},
			answered{unsupported, "its path is not an absolute path with nothing to resolve"}},
	})
}

func TestAPathTheHostCannotDescribeIsAnError(t *testing.T) {
	host := newHost()
	host.failing["describe"] = errors.New("input/output error")
	expect(t, host, map[string]struct {
		test any
		want answered
	}{
		"broken disk": {&assessmentv1.FileTest{Path: "/etc/shadow", Presence: required}, answered{erred, "input/output error"}},
	})
}
