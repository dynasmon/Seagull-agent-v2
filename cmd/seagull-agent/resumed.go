package main

import (
	"log/slog"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/status"
)

// What the agent finds as it starts about the run before it: how that run
// ended and how long the agent was not running, then what differs from what
// that run said of itself. Nothing here says who stopped the agent or changed
// it; the journal of the host does, beside these lines.
func resumed(logger *slog.Logger, previous status.Previous, left status.Snapshot, read bool, now status.Snapshot, at time.Time) {
	reported := []any{slog.String("ending", string(previous.Ending))}
	if !previous.SeenAt.IsZero() {
		reported = append(reported, slog.Time("seen_at", previous.SeenAt), slog.Duration("down_for", at.Sub(previous.SeenAt).Round(time.Second)),
			slog.Bool("rebooted", previous.Rebooted))
	}
	if previous.Reason != "" {
		reported = append(reported, slog.String("reason", string(previous.Reason)))
	}
	switch previous.Ending {
	case status.EndingInterrupted:
		logger.Warn("agent_previous_run", append(reported, slog.String("recovery",
			"nothing for the agent: the run before was killed, crashed or lost its host's power, and the host's journal says which"))...)
	case status.EndingUnknown:
		logger.Warn("agent_previous_run", append(reported, slog.String("recovery",
			"nothing: the run before left no status this agent reads, so how it ended is not known"))...)
	default:
		logger.Info("agent_previous_run", reported...)
	}
	if !read {
		return
	}
	changes := status.Changed(left, now)
	if len(changes) == 0 {
		return
	}
	weakened, described := false, make([]any, 0, len(changes))
	for _, change := range changes {
		weakened = weakened || change.Weakens
		described = append(described, slog.Group(change.What, slog.String("before", change.Before), slog.String("after", change.After), slog.Bool("weakens", change.Weakens)))
	}
	if weakened {
		logger.Warn("agent_changed", append(described, slog.String("recovery",
			"check who changed the agent while it was not running: a collector stopped, a privilege was gained or the policy in force is gone"))...)
		return
	}
	logger.Info("agent_changed", described...)
}
