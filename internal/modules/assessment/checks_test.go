package assessment

import (
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	assessmentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/assessment/v1"
)

// A check the agent cannot read whole is answered as unsupported and never
// as anything the host is, while the rest of the checklist is answered as
// usual.
func TestACheckNewerThanTheAgentIsAnsweredUnsupportedAndTheRestAreRun(t *testing.T) {
	known := checked("forwarding", &assessmentv1.KernelParameterTest{Name: "net.ipv4.ip_forward", Allowed: []string{"0"}})
	newerTest := &assessmentv1.Check{CheckId: "from-tomorrow"}
	newerTest.ProtoReflect().SetUnknown(protowire.AppendBytes(protowire.AppendTag(nil, 99, protowire.BytesType), []byte{0x08, 0x01}))
	newerField := cloned(known)
	newerField.GetKernelParameter().ProtoReflect().SetUnknown(protowire.AppendVarint(protowire.AppendTag(nil, 9, protowire.VarintType), 1))
	newerValue := checked("newer-presence", &assessmentv1.KernelParameterTest{Name: "net.ipv4.ip_forward", Presence: assessmentv1.Presence(3)})
	newerValue.CheckId = "newer-presence"
	newerField.CheckId = "newer-field"
	noTest := &assessmentv1.Check{CheckId: "no-test"}

	round := newRound(t.Context(), newHost(), []*assessmentv1.Check{known, newerTest, newerField, newerValue, noTest})
	for check, want := range map[*assessmentv1.Check]answered{
		known:      {pass, `net.ipv4.ip_forward is "0"`},
		newerTest:  {unsupported, "it carries a test, or a value in one, newer than this agent reads"},
		newerField: {unsupported, "newer than this agent reads"},
		newerValue: {unsupported, "newer than this agent reads"},
		noTest:     {unsupported, "it carries no test"},
	} {
		got := round.answer(check)
		if got.GetOutcome() != want.outcome || !strings.Contains(got.GetEvidence(), want.evidence) {
			t.Errorf("%s was answered %s %q", check.GetCheckId(), got.GetOutcome(), got.GetEvidence())
		}
	}
}

func TestEveryCheckTheContractAdmitsIsReadAndOneItRefusesIsNot(t *testing.T) {
	for name, one := range map[string]struct {
		test    any
		problem string
	}{
		"a file":                {&assessmentv1.FileTest{Path: "/etc/shadow", Permissions: proto.Uint32(0o640)}, ""},
		"a forbidden file":      {&assessmentv1.FileTest{Path: "/etc/hosts.equiv", Presence: forbidden}, ""},
		"the root":              {&assessmentv1.FileTest{Path: "/", Presence: required}, "its path is not an absolute path"},
		"tmp":                   {&assessmentv1.FileTest{Path: "/var/tmp/x", Presence: required}, "within /var/tmp"},
		"runtime":               {&assessmentv1.FileTest{Path: "/run", Presence: required}, "within /run"},
		"permissions beyond":    {&assessmentv1.FileTest{Path: "/etc/shadow", Permissions: proto.Uint32(0o17777)}, "beyond 07777"},
		"forbidden and judged":  {&assessmentv1.FileTest{Path: "/etc/shadow", Presence: forbidden, UserId: proto.Uint32(0)}, "must not be there"},
		"nothing judged":        {&assessmentv1.FileTest{Path: "/etc/shadow"}, "judges nothing"},
		"a parameter":           {&assessmentv1.KernelParameterTest{Name: "net.ipv4.conf.eth0/100.rp_filter", AtLeast: proto.Int64(1)}, ""},
		"values and bounds":     {&assessmentv1.KernelParameterTest{Name: "net.ipv4.ip_forward", Allowed: []string{"0"}, AtMost: proto.Int64(0)}, "both values and bounds"},
		"crossed bounds":        {&assessmentv1.KernelParameterTest{Name: "net.ipv4.ip_forward", AtLeast: proto.Int64(2), AtMost: proto.Int64(1)}, "no value lies between"},
		"a spaced value":        {&assessmentv1.KernelParameterTest{Name: "net.ipv4.ip_forward", Allowed: []string{"0 "}}, "not one it could compare"},
		"a module":              {&assessmentv1.KernelModuleTest{Name: "usb-storage", Disabled: true}, ""},
		"a module path":         {&assessmentv1.KernelModuleTest{Name: "../cramfs", Disabled: true}, "not named as the kernel"},
		"a package":             {&assessmentv1.PackageTest{Name: "libc6", Presence: required}, ""},
		"a package like option": {&assessmentv1.PackageTest{Name: "--admindir", Presence: required}, ""},
		"a package path":        {&assessmentv1.PackageTest{Name: "lib/c6", Presence: required}, "not named as a package manager"},
		"an instance":           {&assessmentv1.ServiceTest{Unit: "getty@tty1.service", Activity: assessmentv1.ServiceTest_ACTIVITY_ACTIVE}, ""},
		"an option for a unit":  {&assessmentv1.ServiceTest{Unit: "--root=/tmp", Activity: assessmentv1.ServiceTest_ACTIVITY_ACTIVE}, "not the full name of a unit"},
		"a directive":           {&assessmentv1.DirectiveTest{Source: assessmentv1.DirectiveTest_SOURCE_SSHD, Name: "PermitRootLogin", Allowed: []string{"no"}, Assumed: "prohibit-password"}, ""},
		"an unnamed file":       {&assessmentv1.DirectiveTest{Name: "PermitRootLogin", Allowed: []string{"no"}}, "it names no file"},
		"a bounded word":        {&assessmentv1.DirectiveTest{Source: assessmentv1.DirectiveTest_SOURCE_SSHD, Name: "MaxAuthTries", AtMost: proto.Int64(4), Assumed: "six"}, "not one it could compare"},
		"too many values": {&assessmentv1.DirectiveTest{Source: assessmentv1.DirectiveTest_SOURCE_SSHD, Name: "Ciphers",
			Allowed: slices.Repeat([]string{"aes256-gcm@openssh.com"}, maxValues+1)}, "at most 16"},
	} {
		got := unread(checked("check", one.test))
		switch {
		case one.problem == "" && got != nil:
			t.Errorf("%s was not read: %v", name, got)
		case one.problem != "" && (got == nil || !strings.Contains(got.Error(), one.problem)):
			t.Errorf("%s was read as %v, want a refusal saying %q", name, got, one.problem)
		}
	}
}

func TestAValueIsReadAsTheProgramItBelongsToReadsANumber(t *testing.T) {
	sshd, defs := assessmentv1.DirectiveTest_SOURCE_SSHD, assessmentv1.DirectiveTest_SOURCE_LOGIN_DEFS
	for _, one := range []struct {
		source assessmentv1.DirectiveTest_Source
		value  string
		held   int64
		read   bool
	}{
		{sshd, "6", 6, true}, {sshd, "027", 27, true}, {sshd, "0x10", 0, false},
		{defs, "027", 0o27, true}, {defs, "0x1F", 31, true}, {defs, "-1", -1, true}, {defs, "0", 0, true},
		{defs, "08", 0, false}, {defs, "1_000", 0, false}, {defs, "", 0, false},
	} {
		if held, read := number(one.source, one.value); held != one.held || read != one.read {
			t.Errorf("%s %q reads as %d (%t)", one.source, one.value, held, read)
		}
	}
}
