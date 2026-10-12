package status

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// A Change is one thing the agent finds different from what the run before it
// said of itself. It weakens the agent when a collector stopped, a privilege
// was gained or a confinement lost, or the policy in force went away. None of
// it says who made the change.
type Change struct {
	What    string
	Before  string
	After   string
	Weakens bool
}

func Changed(before, after Snapshot) []Change {
	var changes []Change
	if before.Agent.Build != after.Agent.Build {
		changes = append(changes, Change{What: "build", Before: string(before.Agent.Build), After: string(after.Agent.Build)})
	}
	if before.Agent.Configuration != "" && before.Agent.Configuration != after.Agent.Configuration {
		changes = append(changes, Change{What: "configuration", Before: string(before.Agent.Configuration), After: string(after.Agent.Configuration)})
	}
	if before.Agent.PolicyRevision != after.Agent.PolicyRevision {
		changes = append(changes, Change{What: "policy", Before: revision(before.Agent.PolicyRevision), After: revision(after.Agent.PolicyRevision),
			Weakens: after.Agent.PolicyRevision == 0})
	}
	if was, is := collecting(before.Modules), collecting(after.Modules); !slices.Equal(was, is) {
		changes = append(changes, Change{What: "modules", Before: strings.Join(was, ", "), After: strings.Join(is, ", "),
			Weakens: slices.ContainsFunc(was, func(name string) bool { return !slices.Contains(is, name) })})
	}
	if was, is := before.Agent.Privileges, after.Agent.Privileges; was != nil && is != nil && described(was) != described(is) {
		changes = append(changes, Change{What: "privileges", Before: described(was), After: described(is), Weakens: gained(was, is)})
	}
	return changes
}

func revision(held uint64) string {
	if held == 0 {
		return "none"
	}
	return strconv.FormatUint(held, 10)
}

func collecting(modules []Module) []string {
	var named []string
	for _, module := range modules {
		if module.State != Disabled {
			named = append(named, string(module.Name))
		}
	}
	slices.Sort(named)
	return named
}

func described(held *Privileges) string {
	capabilities := make([]string, 0, len(held.Capabilities))
	for _, capability := range held.Capabilities {
		capabilities = append(capabilities, string(capability))
	}
	return fmt.Sprintf("uid %d gid %d groups %v capabilities [%s] no_new_privs %t seccomp %s",
		held.User, held.Group, held.Groups, strings.Join(capabilities, " "), held.NoNewPrivs, held.Seccomp)
}

func gained(was, is *Privileges) bool {
	for _, capability := range is.Capabilities {
		if !slices.Contains(was.Capabilities, capability) {
			return true
		}
	}
	return (is.User == 0 && was.User != 0) || (was.NoNewPrivs && !is.NoNewPrivs) || (was.Seccomp == "filter" && is.Seccomp != "filter")
}
