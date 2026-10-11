package status_test

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/status"
)

func TestHowTheRunBeforeEndedIsReadFromTheStatusItLeft(t *testing.T) {
	seen := time.Date(2026, time.October, 11, 12, 0, 0, 0, time.UTC)
	left := func(state status.State, boot string) status.Snapshot {
		held := snapshot()
		held.State, held.WrittenAt, held.Reason, held.Agent.Boot = state, seen, "the agent was asked to stop", status.Text(boot)
		return held
	}
	for name, one := range map[string]struct {
		left   status.Snapshot
		unread error
		want   status.Previous
	}{
		"never ran":      {status.Snapshot{}, fmt.Errorf("%w in /state/status", status.ErrUnwritten), status.Previous{Ending: status.EndingNone}},
		"unreadable":     {status.Snapshot{}, fmt.Errorf("%w: /state/status/status.json", status.ErrDamaged), status.Previous{Ending: status.EndingUnknown}},
		"stopped":        {left(status.Stopped, "boot-1"), nil, status.Previous{Ending: status.EndingStopped, SeenAt: seen, Reason: "the agent was asked to stop"}},
		"killed":         {left(status.Running, "boot-1"), nil, status.Previous{Ending: status.EndingInterrupted, SeenAt: seen}},
		"lost power":     {left(status.Degraded, "boot-0"), nil, status.Previous{Ending: status.EndingInterrupted, SeenAt: seen, Rebooted: true}},
		"no boot before": {left(status.Running, ""), nil, status.Previous{Ending: status.EndingInterrupted, SeenAt: seen}},
	} {
		t.Run(name, func(t *testing.T) {
			if got := status.Before(one.left, one.unread, "boot-1"); got != one.want {
				t.Errorf("the run before reads as %+v, want %+v", got, one.want)
			}
		})
	}
}

func TestWhatChangedSinceTheRunBeforeIsNamedAndWhatWeakensTheAgentIsSaid(t *testing.T) {
	before := snapshot()
	before.Agent.Build, before.Agent.Configuration, before.Agent.PolicyRevision = "seagull-agent v0.1.0", "aaaa", 7
	before.Agent.Privileges = &status.Privileges{User: 997, Group: 997, Groups: []int{997, 999}, Capabilities: []status.Text{}, NoNewPrivs: true, Seccomp: "filter"}
	before.Modules = []status.Module{{Name: "authentication", State: status.Running}, {Name: "files", State: status.Disabled}, {Name: "inventory", State: status.Running}}

	if changes := status.Changed(before, before); len(changes) != 0 {
		t.Fatalf("an agent that changed nothing reports %+v", changes)
	}

	after := before
	after.Agent.Build, after.Agent.Configuration, after.Agent.PolicyRevision = "seagull-agent v0.2.0", "bbbb", 0
	after.Agent.Privileges = &status.Privileges{User: 997, Group: 997, Groups: []int{997, 999}, Capabilities: []status.Text{"CAP_SYS_ADMIN"}, NoNewPrivs: true, Seccomp: "filter"}
	after.Modules = []status.Module{{Name: "authentication", State: status.Running}, {Name: "files", State: status.Running}, {Name: "inventory", State: status.Disabled}}

	found := map[string]status.Change{}
	for _, change := range status.Changed(before, after) {
		found[change.What] = change
	}
	for what, weakens := range map[string]bool{"build": false, "configuration": false, "policy": true, "modules": true, "privileges": true} {
		change, named := found[what]
		if !named || change.Weakens != weakens {
			t.Errorf("%s changed as %+v, weakening %t was expected", what, change, weakens)
		}
	}
	if found["modules"].Before != "authentication, inventory" || found["modules"].After != "authentication, files" || found["policy"].After != "none" {
		t.Errorf("the changes read %+v", found)
	}

	confined := before
	confined.Agent.Privileges = &status.Privileges{User: 997, Group: 997, Groups: []int{997}, Capabilities: []status.Text{}, NoNewPrivs: true, Seccomp: "filter"}
	if changes := status.Changed(before, confined); len(changes) != 1 || changes[0].Weakens {
		t.Errorf("leaving a group reports %+v", changes)
	}
}

func TestTheStatusSaysHowTheRunBeforeEnded(t *testing.T) {
	now := time.Date(2026, time.October, 11, 12, 0, 0, 0, time.UTC)
	for previous, want := range map[status.Previous]string{
		{Ending: status.EndingStopped, SeenAt: now.Add(-time.Hour), Reason: "the agent was asked to stop"}: "the run before stopped 2026-10-11T11:00:00Z: the agent was asked to stop\n",
		{Ending: status.EndingInterrupted, SeenAt: now.Add(-time.Hour), Rebooted: true}:                    "the run before ended without saying so: it last wrote its status 2026-10-11T11:00:00Z; the host started again since\n",
		{Ending: status.EndingUnknown}: "how the run before ended is not known",
	} {
		held := snapshot()
		held.WrittenAt, held.EverySeconds, held.Agent.Previous = now, 30, &previous
		var printed bytes.Buffer
		if err := held.Print(&printed, now); err != nil {
			t.Fatalf("print the status: %v", err)
		}
		if !strings.Contains(printed.String(), want) {
			t.Errorf("the status does not say %q:\n%s", want, printed.String())
		}
	}
	never := snapshot()
	never.Agent.Previous = &status.Previous{Ending: status.EndingNone}
	var printed bytes.Buffer
	if err := never.Print(&printed, now); err != nil || strings.Contains(printed.String(), "run before") {
		t.Errorf("an installation that never ran before printed %q: %v", printed.String(), err)
	}
}
