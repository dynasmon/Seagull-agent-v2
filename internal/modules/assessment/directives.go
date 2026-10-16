package assessment

import (
	"errors"
	"fmt"
	"strings"

	"github.com/dynasmon/Seagull-agent-v2/internal/platform/logindefs"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/sshd"
	"github.com/dynasmon/Seagull-agent-v2/internal/secrets"
	assessmentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/assessment/v1"
)

// The keywords sshd gathers from every line that names them, rather than take
// from the first: a check of one is answered unsupported, as the value it
// would judge is not one line's.
var gathered = map[string]bool{
	"acceptenv": true, "allowgroups": true, "allowusers": true, "channeltimeout": true, "denygroups": true, "denyusers": true,
	"hostcertificate": true, "hostkey": true, "include": true, "listenaddress": true, "logverbose": true, "match": true,
	"permitlisten": true, "permitopen": true, "port": true, "setenv": true, "subsystem": true,
}

type judged struct {
	value string
	where string
	unset bool
}

func (r *round) directive(test *assessmentv1.DirectiveTest) (assessmentv1.Outcome, string) {
	name := test.GetName()
	var held []judged
	switch test.GetSource() {
	case assessmentv1.DirectiveTest_SOURCE_SSHD:
		if gathered[strings.ToLower(name)] {
			return assessmentv1.Outcome_OUTCOME_UNSUPPORTED, fmt.Sprintf("sshd gathers %s from every line that names it, and the agent judges a directive sshd takes from one", name)
		}
		directives, err := r.sshd.get(r.host.SSHD)
		switch {
		case errors.Is(err, sshd.ErrAbsent):
			return assessmentv1.Outcome_OUTCOME_NOT_APPLICABLE, "the host has no /etc/ssh/sshd_config"
		case errors.Is(err, sshd.ErrUnreadable):
			return assessmentv1.Outcome_OUTCOME_ERROR, told(err) + ": a drop-in for seagull-agent.service that grants CAP_DAC_READ_SEARCH lets the agent read it"
		case err != nil:
			return assessmentv1.Outcome_OUTCOME_ERROR, told(err)
		}
		global := false
		for _, setting := range directives.Settings(name) {
			switch {
			case setting.Match != "":
				held = append(held, judged{value: setting.Value, where: fmt.Sprintf("in a Match block for %s at %s line %d", secrets.Bounded(setting.Match), secrets.Bounded(setting.File), setting.Line)})
			case !global:
				global = true
				held = append([]judged{{value: setting.Value, where: fmt.Sprintf("at %s line %d", secrets.Bounded(setting.File), setting.Line)}}, held...)
			}
		}
		if !global {
			held = append([]judged{{unset: true}}, held...)
		}
	case assessmentv1.DirectiveTest_SOURCE_LOGIN_DEFS:
		defined, err := r.loginDefs.get(r.host.LoginDefs)
		switch {
		case errors.Is(err, logindefs.ErrAbsent):
			return assessmentv1.Outcome_OUTCOME_NOT_APPLICABLE, "the host has no /etc/login.defs"
		case err != nil:
			return assessmentv1.Outcome_OUTCOME_ERROR, told(err)
		}
		setting, found := defined[name]
		if !found {
			held = append(held, judged{unset: true})
		} else {
			held = append(held, judged{value: setting.Value, where: fmt.Sprintf("at %s line %d", secrets.Bounded(setting.File), setting.Line)})
		}
	default:
		return assessmentv1.Outcome_OUTCOME_UNSUPPORTED, "the agent does not read the file the check names"
	}

	if held[0].unset {
		if test.GetAssumed() == "" {
			return assessmentv1.Outcome_OUTCOME_FAIL, name + " is not set, and the check assumes no default for it"
		}
		held[0].value, held[0].where = test.GetAssumed(), "as the default the check assumes, since no line sets it"
	}
	for _, setting := range held {
		if wrong := disallows(test, setting.value); wrong != "" {
			return assessmentv1.Outcome_OUTCOME_FAIL, fmt.Sprintf("%s is %s %s, %s", name, secrets.Shown(spaced(setting.value)), setting.where, wrong)
		}
	}
	seen := fmt.Sprintf("%s is %s %s", name, secrets.Shown(spaced(held[0].value)), held[0].where)
	if len(held) > 1 {
		seen += fmt.Sprintf(", and the %d Match blocks that set it allow what they set", len(held)-1)
	}
	return assessmentv1.Outcome_OUTCOME_PASS, seen
}

func disallows(test *assessmentv1.DirectiveTest, value string) string {
	value = spaced(value)
	if allowed := test.GetAllowed(); len(allowed) > 0 {
		for _, one := range allowed {
			if strings.EqualFold(one, value) {
				return ""
			}
		}
		return "which is none of " + strings.Join(allowed, ", ")
	}
	held, integer := number(test.GetSource(), value)
	return beyond(held, integer, test.AtLeast, test.AtMost)
}
