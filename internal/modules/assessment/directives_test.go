package assessment

import (
	"fmt"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-agent-v2/internal/platform/logindefs"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/sshd"
	assessmentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/assessment/v1"
)

func server(name string, allowed ...string) *assessmentv1.DirectiveTest {
	return &assessmentv1.DirectiveTest{Source: assessmentv1.DirectiveTest_SOURCE_SSHD, Name: name, Allowed: allowed}
}

func defined(name string, allowed ...string) *assessmentv1.DirectiveTest {
	return &assessmentv1.DirectiveTest{Source: assessmentv1.DirectiveTest_SOURCE_LOGIN_DEFS, Name: name, Allowed: allowed}
}

func TestADirectiveIsJudgedAsTheProgramThatReadsItAppliesIt(t *testing.T) {
	assumed := server("PermitEmptyPasswords", "no")
	assumed.Assumed = "no"
	unset := server("PermitEmptyPasswords", "no")
	tries := server("MaxAuthTries")
	tries.AtMost = proto.Int64(4)
	days := defined("PASS_MAX_DAYS")
	days.AtMost = proto.Int64(365)
	umask := defined("UMASK")
	umask.AtLeast = proto.Int64(0o27)
	expect(t, newHost(), map[string]struct {
		test any
		want answered
	}{
		"the first value wins": {server("PermitRootLogin", "no", "prohibit-password"),
			answered{pass, `PermitRootLogin is "no" at /etc/ssh/sshd_config.d/10-hardening.conf line 1`}},
		"case is no matter": {server("permitrootlogin", "NO"),
			answered{pass, `permitrootlogin is "no"`}},
		"a match block weakens it": {server("PasswordAuthentication", "no"),
			answered{fail, `PasswordAuthentication is "yes" in a Match block for Address 10.0.0.0/8 at /etc/ssh/sshd_config line 120, which is none of no`}},
		"a bound kept": {tries, answered{pass, `MaxAuthTries is "4" at /etc/ssh/sshd_config line 40`}},
		"a default assumed": {assumed,
			answered{pass, `PermitEmptyPasswords is "no" as the default the check assumes, since no line sets it`}},
		"no default assumed": {unset, answered{fail, "PermitEmptyPasswords is not set, and the check assumes no default for it"}},
		"forwarding on":      {server("X11Forwarding", "no"), answered{fail, `X11Forwarding is "yes" at /etc/ssh/sshd_config line 90, which is none of no`}},
		"a gathered keyword": {server("AllowUsers", "admin"),
			answered{unsupported, "sshd gathers AllowUsers from every line that names it"}},
		"passwords last a lifetime": {days, answered{fail, `PASS_MAX_DAYS is "99999" at /etc/login.defs line 160, above 365`}},
		"an octal umask":            {umask, answered{pass, `UMASK is "027"`}},
		"login.defs minds case":     {defined("encrypt_method", "SHA512"), answered{fail, "encrypt_method is not set"}},
		"the method":                {defined("ENCRYPT_METHOD", "sha512", "yescrypt"), answered{pass, `ENCRYPT_METHOD is "SHA512"`}},
	})

	absent := newHost()
	absent.failing["sshd"] = fmt.Errorf("%w: /etc/ssh/sshd_config is not there", sshd.ErrAbsent)
	absent.failing["logins"] = fmt.Errorf("%w: /etc/login.defs is not there", logindefs.ErrAbsent)
	expect(t, absent, map[string]struct {
		test any
		want answered
	}{
		"no sshd":       {server("PermitRootLogin", "no"), answered{inapplicable, "the host has no /etc/ssh/sshd_config"}},
		"no login.defs": {defined("PASS_MAX_DAYS", "90"), answered{inapplicable, "the host has no /etc/login.defs"}},
	})

	unread := newHost()
	unread.failing["sshd"] = fmt.Errorf("%w: /etc/ssh/sshd_config.d/50-cloud-init.conf", sshd.ErrUnreadable)
	expect(t, unread, map[string]struct {
		test any
		want answered
	}{
		"a private include": {server("PasswordAuthentication", "no"),
			answered{erred, "50-cloud-init.conf: a drop-in for seagull-agent.service that grants CAP_DAC_READ_SEARCH lets the agent read it"}},
	})
}
