package assessment

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/dynasmon/Seagull-agent-v2/internal/platform/kmod"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/sysctl"
	"github.com/dynasmon/Seagull-agent-v2/internal/secrets"
	assessmentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/assessment/v1"
)

func (r *round) parameter(test *assessmentv1.KernelParameterTest) (assessmentv1.Outcome, string) {
	name := test.GetName()
	value, err := r.host.Parameter(name)
	switch {
	case errors.Is(err, sysctl.ErrAbsent):
		return absent(test.GetPresence(), "the kernel has no parameter "+name)
	case errors.Is(err, sysctl.ErrDenied):
		return assessmentv1.Outcome_OUTCOME_ERROR, "the agent's account may not read " + name
	case err != nil:
		return assessmentv1.Outcome_OUTCOME_ERROR, told(err)
	}
	value = spaced(value)
	seen := fmt.Sprintf("%s is %s", name, secrets.Shown(value))
	switch allowed := test.GetAllowed(); {
	case test.GetPresence() == assessmentv1.Presence_PRESENCE_FORBIDDEN:
		return assessmentv1.Outcome_OUTCOME_FAIL, seen
	case len(allowed) > 0 && !slices.Contains(allowed, value):
		return assessmentv1.Outcome_OUTCOME_FAIL, seen + ", which is none of " + strings.Join(allowed, ", ")
	case test.AtLeast != nil || test.AtMost != nil:
		held, integer := number(assessmentv1.DirectiveTest_SOURCE_UNSPECIFIED, value)
		if wrong := beyond(held, integer, test.AtLeast, test.AtMost); wrong != "" {
			return assessmentv1.Outcome_OUTCOME_FAIL, seen + ", " + wrong
		}
	}
	return assessmentv1.Outcome_OUTCOME_PASS, seen
}

// beyond says how a value misses the bounds a check sets, or nothing when it
// lies within them.
func beyond(held int64, integer bool, least, most *int64) string {
	switch {
	case !integer:
		return "which is not one integer"
	case least != nil && held < *least:
		return fmt.Sprintf("below %d", *least)
	case most != nil && held > *most:
		return fmt.Sprintf("above %d", *most)
	}
	return ""
}

func (r *round) module(test *assessmentv1.KernelModuleTest) (assessmentv1.Outcome, string) {
	name := test.GetName()
	var seen []string
	failed := false
	if loaded := test.GetLoaded(); loaded != assessmentv1.Presence_PRESENCE_UNSPECIFIED {
		modules, err := r.modules.get(r.host.Modules)
		var state kmod.State
		if err == nil {
			state, err = modules.State(name)
		}
		if err != nil {
			return assessmentv1.Outcome_OUTCOME_ERROR, "what the kernel holds cannot be read: " + told(err)
		}
		seen = append(seen, fmt.Sprintf("%s is %s", name, state))
		failed = loaded == assessmentv1.Presence_PRESENCE_FORBIDDEN && state != kmod.Absent ||
			loaded == assessmentv1.Presence_PRESENCE_REQUIRED && state == kmod.Absent
	}
	if test.GetDisabled() {
		rules, err := r.modprobe.get(r.host.Modprobe)
		if err != nil {
			return assessmentv1.Outcome_OUTCOME_ERROR, "the modprobe configuration cannot be read: " + told(err)
		}
		rule, found := rules.Install(name)
		switch {
		case !found:
			failed = true
			seen = append(seen, "no install line of the modprobe configuration keeps "+name+" out")
		case kmod.Refuses(rule.Command):
			seen = append(seen, fmt.Sprintf("%s line %d has modprobe run %s for it", secrets.Bounded(rule.File), rule.Line, secrets.Shown(rule.Command)))
		default:
			failed = true
			seen = append(seen, fmt.Sprintf("%s line %d has modprobe run %s for it, which does not keep it out", secrets.Bounded(rule.File), rule.Line, secrets.Shown(rule.Command)))
		}
		if blacklisted, found := rules.Blacklisted(name); found {
			seen = append(seen, fmt.Sprintf("%s line %d blacklists it", secrets.Bounded(blacklisted.File), blacklisted.Line))
		}
	}
	if failed {
		return assessmentv1.Outcome_OUTCOME_FAIL, strings.Join(seen, "; ")
	}
	return assessmentv1.Outcome_OUTCOME_PASS, strings.Join(seen, "; ")
}
