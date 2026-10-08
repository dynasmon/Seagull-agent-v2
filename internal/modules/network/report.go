package network

import (
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/platform/sockets"
)

const (
	loggedPerMinute = 1000
	maxListed       = 8
)

const (
	shown      = "have the service show the agent every process, and the namespaces they run in: a drop-in for seagull-agent.service that sets ProtectProc=default"
	associated = "have it read which process holds each socket as well: a drop-in that sets ProtectProc=default, ReadOnlyPaths=/proc, CapabilityBoundingSet=CAP_SYS_PTRACE CAP_DAC_READ_SEARCH, AmbientCapabilities=CAP_SYS_PTRACE CAP_DAC_READ_SEARCH and SystemCallFilter=~process_vm_readv process_vm_writev"
	restarted  = ", then systemctl daemon-reload and systemctl restart seagull-agent"
)

func Recovery(failed error) string {
	switch {
	case errors.Is(failed, sockets.ErrTooMany):
		return "none: the host holds more sockets than the module reads, and it reads them again at its next round"
	case errors.Is(failed, errors.ErrUnsupported):
		return "none: the module watches the network of linux hosts"
	}
	return "none: the module reads the sockets again at its next round"
}

// report writes down one change the module found. A minute writes down at
// most a thousand, so a host that opens connections by the thousand cannot
// crowd the rest of the agent out of the journal, and what it holds back is
// counted and said once the round ends.
func (c *Collector) report(found change, origin string, names map[uint32]string) {
	now := time.Now()
	c.mu.Lock()
	c.changes++
	c.changed = now
	if now.Sub(c.window) >= time.Minute {
		c.window, c.logged = now, 0
	}
	allowed := c.logged < loggedPerMinute
	if allowed {
		c.logged++
	} else {
		c.unlogged++
		c.withheld[found.message]++
	}
	c.mu.Unlock()
	if !allowed {
		return
	}
	attributes := []any{namespaced(found.space), slog.String("origin", origin)}
	switch found.message {
	case listenerOpened, listenerClosed, listenerChanged:
		attributes = append(attributes, slog.String("protocol", found.listening.protocol.String()), slog.String("address", found.listening.address.String()),
			slog.Int("port", int(found.listening.port)))
		attributes = append(attributes, listened(found.listener, names)...)
		if found.message == listenerChanged {
			attributes = append(attributes, slog.Any("changes", found.changed), slog.Group("before", listened(found.before, names)...))
		}
	case flowStarted, flowEnded:
		attributes = append(attributes, slog.String("direction", found.talk.direction.String()), slog.String("protocol", found.talk.protocol.String()),
			slog.String("remote", found.talk.remote.String()), slog.Int("port", int(found.talk.port)), slog.String("association", found.flow.association.String()))
		if found.talk.owned {
			attributes = append(attributes, slog.String("account", accounted(found.talk.account, names)))
		}
		if found.flow.association != byNobody {
			attributes = append(attributes, slog.Any("processes", processed(found.flow.processes)))
		}
		connections := found.flow.connections
		if found.message == flowEnded {
			connections = found.flow.most
		}
		attributes = append(attributes, slog.Int("connections", connections), slog.Any("states", found.flow.states), slog.Time("first", found.flow.first.UTC()))
		if found.message == flowEnded {
			attributes = append(attributes, slog.Time("last", found.flow.last.UTC()))
		}
	case namespaceSeen, namespaceGone:
		attributes = append(attributes, slog.Int("listeners", len(found.space.listeners)), slog.Int("flows", len(found.space.flows)), slog.Int("processes", found.space.processes))
	}
	c.logger.Info(found.message, attributes...)
}

func (c *Collector) withholding() {
	c.mu.Lock()
	withheld := maps.Clone(c.withheld)
	clear(c.withheld)
	c.mu.Unlock()
	if len(withheld) == 0 {
		return
	}
	counted := make([]any, 0, len(withheld))
	for _, message := range slices.Sorted(maps.Keys(withheld)) {
		counted = append(counted, slog.Int(message, withheld[message]))
	}
	c.logger.Warn("network_changes_not_logged", slog.Group("withheld", counted...),
		slog.String("reason", fmt.Sprintf("the module writes down at most %d changes a minute, and found more", loggedPerMinute)),
		slog.String("recovery", "none: the status counts every change the module found"))
}

func namespaced(seen *space) slog.Attr {
	attributes := []any{slog.Bool("own", seen.own)}
	if seen.host {
		attributes = append(attributes, slog.Bool("host", true))
	}
	if seen.id != "" {
		attributes = append(attributes, slog.String("id", seen.id))
	}
	if !seen.own {
		attributes = append(attributes, slog.Int("process", int(seen.through.PID)), slog.String("name", seen.through.Name), slog.Time("started", seen.through.Started))
	}
	return slog.Group("namespace", attributes...)
}

func listened(held listener, names map[uint32]string) []any {
	accounts := make([]string, 0, len(held.accounts))
	for _, account := range held.accounts {
		accounts = append(accounts, accounted(account, names))
	}
	return []any{slog.Any("accounts", accounts), slog.Int("sockets", held.sockets), slog.String("association", held.association.String()), slog.Any("processes", processed(held.processes))}
}

func processed(held []holder) []string {
	said := []string{}
	for i, member := range held {
		if i == maxListed {
			said = append(said, fmt.Sprintf("and %d more", len(held)-maxListed))
			break
		}
		said = append(said, fmt.Sprintf("%s (pid %d)", member.Name, member.PID))
	}
	return said
}

func accounted(account uint32, names map[uint32]string) string {
	if name, found := names[account]; found {
		return told(name)
	}
	return strconv.FormatUint(uint64(account), 10)
}

type Stats struct {
	Namespaces  int
	Listeners   int
	Flows       int
	Connections int
	Changes     uint64
	Unlogged    uint64
	Changed     time.Time
	Observed    time.Time
	Hidden      bool
	Unvisited   error
	Refused     int
	Skipped     int
	Unread      int
	Untracked   int
	Unreadable  []string
	Failure     error
}

func (c *Collector) Stats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	held := c.stats
	held.Unreadable = slices.Clone(held.Unreadable)
	held.Changes, held.Unlogged, held.Changed = c.changes, c.unlogged, c.changed
	return held
}

func (s Stats) Coverage() string {
	var said []string
	switch {
	case s.Unvisited != nil:
		said = append(said, fmt.Sprintf("the network namespaces other than the agent's own, and which processes hold its sockets, as the module could not look at the processes: %v", s.Unvisited))
	case s.Hidden:
		said = append(said, "the network namespaces other than the agent's own, and which processes of other accounts hold its sockets, as procfs hides the processes of other accounts")
	case s.Unread > 0:
		said = append(said, fmt.Sprintf("which processes hold the sockets, as the agent may not read the descriptors of %d processes", s.Unread))
	}
	if s.Refused > 0 {
		said = append(said, fmt.Sprintf("the namespaces of %d processes procfs lists and does not show", s.Refused))
	}
	if s.Skipped > 0 {
		said = append(said, fmt.Sprintf("%d network namespaces past the %d it reads", s.Skipped, maxNamespaces))
	}
	if s.Untracked > 0 {
		said = append(said, fmt.Sprintf("%d flows past the %d it keeps", s.Untracked, maxFlows))
	}
	if len(s.Unreadable) > 0 {
		said = append(said, "the sockets of "+strings.Join(s.Unreadable, ", "))
	}
	if s.Failure != nil {
		said = append(said, s.Failure.Error())
	}
	return strings.Join(said, "; ")
}

func (s Stats) recovery() string {
	switch {
	case s.Failure != nil:
		return Recovery(s.Failure)
	case s.Hidden, s.Unvisited != nil && !errors.Is(s.Unvisited, sockets.ErrTooMany):
		return "to watch the other namespaces, " + shown + restarted + "; to " + associated + restarted
	case s.Unread > 0:
		return "to " + associated + restarted
	}
	return "none: the module reads what it can again at its next round"
}

// survey counts what the module holds and what it cannot see, as of the
// round that ended, and says so whenever what it cannot see changes.
func (c *Collector) survey(reading sockets.Reading, untracked int, now time.Time) {
	held := Stats{Observed: now, Hidden: reading.Hidden, Unvisited: reading.Unvisited, Refused: reading.Refused, Skipped: reading.Skipped, Unread: reading.Unread, Untracked: untracked}
	for _, kept := range c.held.spaces {
		if kept.pending {
			continue
		}
		held.Namespaces++
		held.Listeners += len(kept.listeners)
		held.Flows += len(kept.flows)
		for _, talking := range kept.flows {
			held.Connections += talking.connections
		}
	}
	for _, read := range reading.Namespaces {
		switch {
		case read.Failure == nil:
		case read.Own:
			held.Failure = fmt.Errorf("the agent's own network namespace: %w", read.Failure)
		default:
			held.Unreadable = append(held.Unreadable, fmt.Sprintf("the namespace of %s (pid %d): %v", told(read.Through.Name), read.Through.PID, read.Failure))
		}
	}
	c.mu.Lock()
	c.stats = held
	c.mu.Unlock()
	said := held.Coverage()
	if said == c.covered {
		return
	}
	c.covered = said
	if said == "" {
		c.logger.Info("network_covered", slog.Int("namespaces", held.Namespaces))
		return
	}
	c.logger.Warn("network_not_covered", slog.String("reason", "the module does not see "+said), slog.String("recovery", held.recovery()))
}
