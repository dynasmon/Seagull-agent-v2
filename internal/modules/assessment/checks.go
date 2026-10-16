package assessment

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"

	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/dynasmon/Seagull-agent-v2/internal/platform/kmod"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/sysctl"
	assessmentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/assessment/v1"
)

const (
	maxPath           = 4096
	maxGroup          = 64
	maxValues         = 16
	maxParameterValue = 128
	maxDirectiveValue = 256
	maxPackage        = 255
	maxUnit           = 255
	maxDirective      = 64
	maxPermissions    = 0o7777
)

var (
	unexamined = []string{"/proc", "/sys", "/dev", "/run", "/tmp", "/var/tmp"}
	packaged   = regexp.MustCompile(`^[A-Za-z0-9+._-]+$`)
	unitName   = regexp.MustCompile(`^[A-Za-z0-9:_.\\@-]+\.(service|socket|timer|path|mount|automount|swap|target|slice|scope|device)$`)
	directive  = regexp.MustCompile(`^[A-Za-z0-9_]+$`)
)

var errUnread = errors.New("the agent does not read the check")

// unread says why the agent cannot run a check as it was written, which it then
// answers as unsupported: a test, or a value in one, newer than this build, or
// one outside what the contract it was built with lets a check ask.
func unread(check *assessmentv1.Check) error {
	if newer(check.ProtoReflect()) {
		return fmt.Errorf("%w: it carries a test, or a value in one, newer than this agent reads", errUnread)
	}
	var problem string
	switch test := check.GetTest().(type) {
	case *assessmentv1.Check_File:
		problem = fileProblem(test.File)
	case *assessmentv1.Check_Account:
		problem = accountProblem(test.Account)
	case *assessmentv1.Check_KernelParameter:
		problem = parameterProblem(test.KernelParameter)
	case *assessmentv1.Check_KernelModule:
		problem = moduleProblem(test.KernelModule)
	case *assessmentv1.Check_Package:
		problem = packageProblem(test.Package)
	case *assessmentv1.Check_Service:
		problem = serviceProblem(test.Service)
	case *assessmentv1.Check_Directive:
		problem = directiveProblem(test.Directive)
	default:
		problem = "it carries no test"
	}
	if problem != "" {
		return fmt.Errorf("%w: %s", errUnread, problem)
	}
	return nil
}

func newer(message protoreflect.Message) bool {
	if len(message.GetUnknown()) > 0 {
		return true
	}
	found := false
	message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		switch {
		case field.Enum() != nil && !field.IsList():
			found = field.Enum().Values().ByNumber(value.Enum()) == nil
		case field.Message() != nil && field.IsList():
			for index := range value.List().Len() {
				found = found || newer(value.List().Get(index).Message())
			}
		case field.Message() != nil:
			found = newer(value.Message())
		}
		return !found
	})
	return found
}

func fileProblem(test *assessmentv1.FileTest) string {
	written := test.GetPath()
	switch {
	case written == "" || len(written) > maxPath || !strings.HasPrefix(written, "/") || path.Clean(written) != written || written == "/" || strings.ContainsRune(written, 0):
		return "its path is not an absolute path with nothing to resolve"
	case test.Permissions != nil && test.GetPermissions() > maxPermissions:
		return "its permissions lie beyond 07777"
	}
	for _, held := range unexamined {
		if written == held || strings.HasPrefix(written, held+"/") {
			return "its path is within " + held
		}
	}
	judged := test.GetKind() != assessmentv1.FileTest_KIND_UNSPECIFIED || test.UserId != nil || test.GroupId != nil || test.Permissions != nil
	switch test.GetPresence() {
	case assessmentv1.Presence_PRESENCE_FORBIDDEN:
		if judged {
			return "it judges what a path that must not be there is"
		}
	case assessmentv1.Presence_PRESENCE_UNSPECIFIED:
		if !judged {
			return "it judges nothing of the path"
		}
	}
	return ""
}

func accountProblem(test *assessmentv1.AccountTest) string {
	group := test.GetGroup()
	switch {
	case test.GetRule() == assessmentv1.AccountTest_RULE_UNSPECIFIED:
		return "it names no rule"
	case test.GetRule() != assessmentv1.AccountTest_RULE_GROUP_HAS_NO_MEMBERS:
		if group != "" {
			return "it names a group for a rule about no group"
		}
	case group == "" || len(group) > maxGroup || strings.IndexFunc(group, func(r rune) bool { return r <= ' ' || r > '~' || r == ':' }) >= 0:
		return "its group is not a name of a group"
	}
	return ""
}

func parameterProblem(test *assessmentv1.KernelParameterTest) string {
	if _, err := sysctl.Path(test.GetName()); err != nil {
		return "its parameter is not named as sysctl names one"
	}
	if problem := valuesProblem(test.GetAllowed(), maxParameterValue); problem != "" {
		return problem
	}
	bounded := test.AtLeast != nil || test.AtMost != nil
	carried := len(test.GetAllowed()) > 0 || bounded
	switch {
	case test.AtLeast != nil && test.AtMost != nil && test.GetAtLeast() > test.GetAtMost():
		return "no value lies between its bounds"
	case test.GetPresence() == assessmentv1.Presence_PRESENCE_FORBIDDEN && carried:
		return "it judges the value of a parameter that must not be there"
	case len(test.GetAllowed()) > 0 && bounded:
		return "it carries both values and bounds"
	case !carried && test.GetPresence() == assessmentv1.Presence_PRESENCE_UNSPECIFIED:
		return "it judges nothing of the parameter"
	}
	return ""
}

func moduleProblem(test *assessmentv1.KernelModuleTest) string {
	if _, err := kmod.Name(test.GetName()); err != nil {
		return "its module is not named as the kernel names one"
	}
	if test.GetLoaded() == assessmentv1.Presence_PRESENCE_UNSPECIFIED && !test.GetDisabled() {
		return "it judges nothing of the module"
	}
	return ""
}

func packageProblem(test *assessmentv1.PackageTest) string {
	switch {
	case len(test.GetName()) > maxPackage || !packaged.MatchString(test.GetName()):
		return "its package is not named as a package manager names one"
	case test.GetPresence() == assessmentv1.Presence_PRESENCE_UNSPECIFIED:
		return "it says neither that the package must be installed nor that it must not"
	}
	return ""
}

func serviceProblem(test *assessmentv1.ServiceTest) string {
	unit := test.GetUnit()
	switch {
	case len(unit) > maxUnit || !unitName.MatchString(unit):
		return "its unit is not the full name of a unit"
	case strings.HasSuffix(unit[:strings.LastIndexByte(unit, '.')], "@"):
		return "its unit is a template"
	case test.GetStartup() == assessmentv1.ServiceTest_STARTUP_UNSPECIFIED && test.GetActivity() == assessmentv1.ServiceTest_ACTIVITY_UNSPECIFIED:
		return "it judges nothing of the unit"
	}
	return ""
}

func directiveProblem(test *assessmentv1.DirectiveTest) string {
	bounded := test.AtLeast != nil || test.AtMost != nil
	switch {
	case test.GetSource() == assessmentv1.DirectiveTest_SOURCE_UNSPECIFIED:
		return "it names no file"
	case len(test.GetName()) > maxDirective || !directive.MatchString(test.GetName()):
		return "its directive is not named as a directive is"
	case len(test.GetAllowed()) > 0 && bounded:
		return "it carries both values and bounds"
	case len(test.GetAllowed()) == 0 && !bounded:
		return "it judges nothing of the directive"
	case test.AtLeast != nil && test.AtMost != nil && test.GetAtLeast() > test.GetAtMost():
		return "no value lies between its bounds"
	}
	if problem := valuesProblem(test.GetAllowed(), maxDirectiveValue); problem != "" {
		return problem
	}
	if assumed := test.GetAssumed(); assumed != "" {
		if _, integer := number(test.GetSource(), assumed); !normalized(assumed, maxDirectiveValue) || (bounded && !integer) {
			return "the value it assumes is not one it could compare"
		}
	}
	return ""
}

func valuesProblem(values []string, most int) string {
	if len(values) > maxValues {
		return fmt.Sprintf("it names %d values, and a check names at most %d", len(values), maxValues)
	}
	for _, value := range values {
		if !normalized(value, most) {
			return "a value it allows is not one it could compare"
		}
	}
	return ""
}

// normalized is a value as a check compares it: printable, with no white space
// but single spaces between words, which is what a value read from a host is
// made before it is compared.
func normalized(value string, most int) bool {
	if value == "" || len(value) > most || strings.TrimSpace(value) != value || strings.Contains(value, "  ") {
		return false
	}
	return strings.IndexFunc(value, func(r rune) bool { return r < ' ' || r > '~' }) < 0
}

func spaced(value string) string { return strings.Join(strings.Fields(value), " ") }

// number reads a value the way the program it belongs to reads a number: sshd
// and the kernel in decimal, login.defs as C's strtol does with base 0.
func number(source assessmentv1.DirectiveTest_Source, value string) (int64, bool) {
	if source != assessmentv1.DirectiveTest_SOURCE_LOGIN_DEFS {
		parsed, err := strconv.ParseInt(value, 10, 64)
		return parsed, err == nil
	}
	sign, digits := "", value
	if strings.HasPrefix(digits, "-") || strings.HasPrefix(digits, "+") {
		sign, digits = digits[:1], digits[1:]
	}
	base := 10
	switch {
	case len(digits) > 2 && (digits[:2] == "0x" || digits[:2] == "0X"):
		base, digits = 16, digits[2:]
	case len(digits) > 1 && digits[0] == '0':
		base, digits = 8, digits[1:]
	}
	if digits == "" || strings.ContainsAny(digits, "_+-") {
		return 0, false
	}
	parsed, err := strconv.ParseInt(sign+digits, base, 64)
	return parsed, err == nil
}
