package assessment

import (
	"errors"
	"fmt"
	"slices"

	"github.com/dynasmon/Seagull-agent-v2/internal/platform/dpkg"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/services"
	"github.com/dynasmon/Seagull-agent-v2/internal/secrets"
	assessmentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/assessment/v1"
)

var (
	enabled  = []string{"enabled", "enabled-runtime"}
	masked   = []string{"masked", "masked-runtime"}
	disabled = append([]string{"disabled"}, masked...)
	running  = []string{"active", "reloading"}
	stopped  = []string{"inactive", "failed"}
)

func (r *round) installed(test *assessmentv1.PackageTest) (assessmentv1.Outcome, string) {
	name := test.GetName()
	packages, err := r.packages.get(func() ([]dpkg.Package, error) { return r.host.Packages(r.ctx) })
	switch {
	case errors.Is(err, dpkg.ErrAbsent):
		return assessmentv1.Outcome_OUTCOME_UNSUPPORTED, "this host has no dpkg, the package manager the agent reads"
	case err != nil:
		return assessmentv1.Outcome_OUTCOME_ERROR, "what dpkg holds cannot be read: " + told(err)
	}
	var held []string
	for _, installed := range packages {
		if installed.Name == name {
			held = append(held, secrets.Bounded(installed.Version)+" "+secrets.Bounded(installed.Architecture))
		}
	}
	required := test.GetPresence() == assessmentv1.Presence_PRESENCE_REQUIRED
	switch {
	case len(held) == 0 && required:
		return assessmentv1.Outcome_OUTCOME_FAIL, name + " is not installed"
	case len(held) == 0:
		return assessmentv1.Outcome_OUTCOME_PASS, name + " is not installed"
	case required:
		return assessmentv1.Outcome_OUTCOME_PASS, fmt.Sprintf("%s %s is installed", name, named(held))
	}
	return assessmentv1.Outcome_OUTCOME_FAIL, fmt.Sprintf("%s %s is installed", name, named(held))
}

func (r *round) service(test *assessmentv1.ServiceTest) (assessmentv1.Outcome, string) {
	asked := test.GetUnit()
	unit, err := r.unit(asked)
	switch {
	case errors.Is(err, services.ErrAbsent):
		return assessmentv1.Outcome_OUTCOME_UNSUPPORTED, "systemd does not manage this host"
	case errors.Is(err, services.ErrDenied):
		return assessmentv1.Outcome_OUTCOME_ERROR, "systemctl cannot reach systemd from where the agent runs"
	case err != nil:
		return assessmentv1.Outcome_OUTCOME_ERROR, "what systemd holds of the unit cannot be read: " + told(err)
	}
	gone := unit.Load == "not-found"
	seen := "the host has no unit " + asked
	if !gone {
		name := asked
		if unit.ID != asked {
			name = fmt.Sprintf("%s, which is %s,", asked, secrets.Bounded(unit.ID))
		}
		file := secrets.Bounded(unit.File)
		if unit.File == "" {
			file = "without a unit file"
		}
		seen = fmt.Sprintf("%s is %s and %s", name, file, secrets.Bounded(unit.Active))
	}
	passes := true
	switch test.GetStartup() {
	case assessmentv1.ServiceTest_STARTUP_ENABLED:
		passes = !gone && slices.Contains(enabled, unit.File)
	case assessmentv1.ServiceTest_STARTUP_DISABLED:
		passes = gone || unit.Load == "masked" || slices.Contains(disabled, unit.File)
	case assessmentv1.ServiceTest_STARTUP_MASKED:
		passes = gone || unit.Load == "masked" || slices.Contains(masked, unit.File)
	}
	switch test.GetActivity() {
	case assessmentv1.ServiceTest_ACTIVITY_ACTIVE:
		passes = passes && slices.Contains(running, unit.Active)
	case assessmentv1.ServiceTest_ACTIVITY_INACTIVE:
		passes = passes && (gone || slices.Contains(stopped, unit.Active))
	}
	if passes {
		return assessmentv1.Outcome_OUTCOME_PASS, seen
	}
	return assessmentv1.Outcome_OUTCOME_FAIL, seen
}
