package assessment

import (
	"fmt"
	"testing"

	"github.com/dynasmon/Seagull-agent-v2/internal/platform/dpkg"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/services"
	assessmentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/assessment/v1"
)

func TestAPackageIsJudgedByWhatDpkgHoldsInstalled(t *testing.T) {
	expect(t, newHost(), map[string]struct {
		test any
		want answered
	}{
		"ssh server required": {&assessmentv1.PackageTest{Name: "openssh-server", Presence: required}, answered{pass, "openssh-server 1:9.6p1-3ubuntu13 amd64 is installed"}},
		"telnetd forbidden":   {&assessmentv1.PackageTest{Name: "telnetd", Presence: forbidden}, answered{pass, "telnetd is not installed"}},
		"libc6 forbidden":     {&assessmentv1.PackageTest{Name: "libc6", Presence: forbidden}, answered{fail, "libc6 2.39 amd64, 2.39 i386 is installed"}},
		"aide required":       {&assessmentv1.PackageTest{Name: "aide", Presence: required}, answered{fail, "aide is not installed"}},
		"either way":          {&assessmentv1.PackageTest{Name: "aide"}, answered{unsupported, "it says neither"}},
	})
	host := newHost()
	host.failing["packages"] = fmt.Errorf("%w: /usr/bin/dpkg-query", dpkg.ErrAbsent)
	expect(t, host, map[string]struct {
		test any
		want answered
	}{
		"telnetd forbidden": {&assessmentv1.PackageTest{Name: "telnetd", Presence: forbidden}, answered{unsupported, "this host has no dpkg"}},
	})
}

func TestAUnitIsJudgedByWhatSystemdSaysOfItUnderTheNameItWasAskedBy(t *testing.T) {
	enabled, disabled, masked := assessmentv1.ServiceTest_STARTUP_ENABLED, assessmentv1.ServiceTest_STARTUP_DISABLED, assessmentv1.ServiceTest_STARTUP_MASKED
	active, inactive := assessmentv1.ServiceTest_ACTIVITY_ACTIVE, assessmentv1.ServiceTest_ACTIVITY_INACTIVE
	host := newHost()
	expect(t, host, map[string]struct {
		test any
		want answered
	}{
		"ssh runs":              {&assessmentv1.ServiceTest{Unit: "ssh.service", Startup: enabled, Activity: active}, answered{pass, "ssh.service is enabled and active"}},
		"an alias":              {&assessmentv1.ServiceTest{Unit: "sshd.service", Activity: inactive}, answered{fail, "sshd.service, which is ssh.service, is enabled and active"}},
		"rsync stopped":         {&assessmentv1.ServiceTest{Unit: "rsync.service", Startup: disabled, Activity: inactive}, answered{pass, "rsync.service is disabled and inactive"}},
		"rsync not masked":      {&assessmentv1.ServiceTest{Unit: "rsync.service", Startup: masked}, answered{fail, "rsync.service is disabled"}},
		"telnet masked":         {&assessmentv1.ServiceTest{Unit: "telnet.socket", Startup: masked}, answered{pass, "telnet.socket is masked"}},
		"an absent unit":        {&assessmentv1.ServiceTest{Unit: "rpcbind.socket", Startup: disabled, Activity: inactive}, answered{pass, "the host has no unit rpcbind.socket"}},
		"an absent unit wanted": {&assessmentv1.ServiceTest{Unit: "auditd.service", Startup: enabled}, answered{fail, "the host has no unit auditd.service"}},
		"a static unit":         {&assessmentv1.ServiceTest{Unit: "systemd-journald.service", Startup: disabled}, answered{fail, "is static and active"}},
		"a template":            {&assessmentv1.ServiceTest{Unit: "getty@.service", Startup: disabled}, answered{unsupported, "its unit is a template"}},
	})
	if host.reads["units"] != 1 {
		t.Fatalf("one round asked systemd %d times", host.reads["units"])
	}
	absent := newHost()
	absent.failing["units"] = fmt.Errorf("%w: /run/systemd/system is not there", services.ErrAbsent)
	expect(t, absent, map[string]struct {
		test any
		want answered
	}{
		"ssh runs": {&assessmentv1.ServiceTest{Unit: "ssh.service", Activity: active}, answered{unsupported, "systemd does not manage this host"}},
	})
}
