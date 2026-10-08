package network

import (
	"cmp"
	"maps"
	"slices"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/platform/sockets"
)

const (
	listenerOpened  = "listener_opened"
	listenerClosed  = "listener_closed"
	listenerChanged = "listener_changed"
	flowStarted     = "flow_started"
	flowEnded       = "flow_ended"
	namespaceSeen   = "network_namespace_seen"
	namespaceGone   = "network_namespace_gone"
	linger          = 3
)

var maxFlows = 16384

type change struct {
	message   string
	space     *space
	listening listening
	listener  listener
	before    listener
	changed   []string
	talk      conversation
	flow      flow
}

// The state is what the module last saw of every namespace it reads, the
// agent's own first, and the boot it saw it in.
type state struct {
	boot   string
	spaces []*space
}

func (s *state) match(read sockets.Namespace) *space {
	if s == nil {
		return nil
	}
	for _, kept := range s.spaces {
		switch {
		case kept.own || read.Own:
			if kept.own && read.Own {
				return kept
			}
		case kept.key == read.Key && slices.ContainsFunc(read.Earliest, func(member sockets.Process) bool { return slices.ContainsFunc(kept.earliest, holding(member).same) }):
			return kept
		}
	}
	return nil
}

type comparison struct {
	now       time.Time
	adopting  bool
	quiet     bool
	ending    bool
	complete  bool
	left      int
	untracked int
	changes   []change
}

// compare makes the state of a round from the last one and what the reading
// saw, and says what changed in between. A namespace the reading could not
// read stays as it was; one it did not find is gone only when the reading
// found every namespace, and is forgotten without a word when procfs hides
// the namespaces of other accounts. What is new is the baseline while the
// module adopts, and the flows of a quiet comparison are.
func (c *comparison) compare(previous *state, reading sockets.Reading) *state {
	next := &state{boot: reading.Boot}
	matched := map[*space]bool{}
	c.left = maxFlows
	for _, read := range reading.Namespaces {
		kept := previous.match(read)
		matched[kept] = kept != nil
		var before map[connected]conversation
		if kept != nil {
			before = kept.connected
		}
		switch {
		case read.Failure != nil && kept != nil:
			c.left -= len(kept.flows)
			next.spaces = append(next.spaces, kept)
		case read.Failure != nil:
			awaited := viewed(sockets.Namespace{Key: read.Key, Own: read.Own, ID: read.ID, Host: read.Host, Through: read.Through, Earliest: read.Earliest, Processes: read.Processes}, nil, c.complete, nil, c.now)
			awaited.pending = true
			next.spaces = append(next.spaces, awaited)
		case kept == nil || kept.pending:
			seen := viewed(read, reading.Holders, c.complete, nil, c.now)
			c.arrive(seen, c.adopting || kept != nil)
			next.spaces = append(next.spaces, seen)
		default:
			next.spaces = append(next.spaces, c.merge(kept, viewed(read, reading.Holders, c.complete, before, c.now)))
		}
	}
	whole := reading.Unvisited == nil && !reading.Hidden && reading.Refused == 0 && reading.Skipped == 0
	for _, kept := range previous.held() {
		switch {
		case matched[kept]:
		case whole && !kept.pending:
			c.changes = append(c.changes, change{message: namespaceGone, space: kept})
		case whole, reading.Hidden && !kept.own:
		default:
			c.left -= len(kept.flows)
			next.spaces = append(next.spaces, kept)
		}
	}
	return next
}

func (s *state) held() []*space {
	if s == nil {
		return nil
	}
	return s.spaces
}

func (c *comparison) arrive(seen *space, adopting bool) {
	if !adopting {
		c.changes = append(c.changes, change{message: namespaceSeen, space: seen})
		for _, at := range ordered(seen.listeners, byListening) {
			c.changes = append(c.changes, change{message: listenerOpened, space: seen, listening: at, listener: seen.listeners[at]})
		}
	}
	for _, talk := range ordered(seen.flows, byConversation) {
		if !c.track() {
			delete(seen.flows, talk)
			continue
		}
		if !adopting {
			c.changes = append(c.changes, change{message: flowStarted, space: seen, talk: talk, flow: *seen.flows[talk]})
		}
	}
}

func (c *comparison) track() bool {
	if c.left <= 0 {
		c.untracked++
		return false
	}
	c.left--
	return true
}

func (c *comparison) merge(kept, seen *space) *space {
	for _, at := range ordered(seen.listeners, byListening) {
		now := seen.listeners[at]
		was, existed := kept.listeners[at]
		if !existed {
			c.changes = append(c.changes, change{message: listenerOpened, space: seen, listening: at, listener: now})
		} else if changed := differences(was, now); len(changed) > 0 {
			c.changes = append(c.changes, change{message: listenerChanged, space: seen, listening: at, listener: now, before: was, changed: changed})
		}
	}
	for _, at := range ordered(kept.listeners, byListening) {
		if _, still := seen.listeners[at]; !still {
			c.changes = append(c.changes, change{message: listenerClosed, space: seen, listening: at, listener: kept.listeners[at]})
		}
	}
	flows := map[conversation]*flow{}
	for _, talk := range ordered(seen.flows, byConversation) {
		now := seen.flows[talk]
		if was := kept.flows[talk]; was != nil {
			now.first, now.most = was.first, max(was.most, now.most)
			now.processes = joined(was.processes, now.processes)
			c.left--
			flows[talk] = now
			continue
		}
		if !c.track() {
			continue
		}
		flows[talk] = now
		if !c.quiet {
			c.changes = append(c.changes, change{message: flowStarted, space: seen, talk: talk, flow: *now})
		}
	}
	for _, talk := range ordered(kept.flows, byConversation) {
		if _, still := seen.flows[talk]; still {
			continue
		}
		was := *kept.flows[talk]
		was.missed++
		was.connections = 0
		if was.missed >= linger || c.ending {
			if !c.quiet {
				c.changes = append(c.changes, change{message: flowEnded, space: seen, talk: talk, flow: was})
			}
			continue
		}
		c.left--
		flows[talk] = &was
	}
	seen.flows = flows
	return seen
}

// differences names what changed of a listener that stayed: the accounts its
// sockets belong to, and the names of the processes holding it when the
// module read them both times, so a service started again is no change.
func differences(was, now listener) []string {
	var changed []string
	if !slices.Equal(was.accounts, now.accounts) {
		changed = append(changed, "accounts")
	}
	if was.association == byProcess && now.association == byProcess && !slices.Equal(named(was.processes), named(now.processes)) {
		changed = append(changed, "processes")
	}
	return changed
}

func named(held []holder) []string {
	var names []string
	for _, member := range held {
		names = added(names, member.Name)
	}
	return names
}

func byListening(a, b listening) int {
	return cmp.Or(cmp.Compare(a.protocol, b.protocol), a.address.Compare(b.address), cmp.Compare(a.port, b.port))
}

func byConversation(a, b conversation) int {
	return cmp.Or(cmp.Compare(a.direction, b.direction), cmp.Compare(a.protocol, b.protocol), a.remote.Compare(b.remote), cmp.Compare(a.port, b.port),
		compareOwned(a, b), cmp.Compare(a.account, b.account))
}

func compareOwned(a, b conversation) int {
	switch {
	case a.owned == b.owned:
		return 0
	case a.owned:
		return 1
	}
	return -1
}

func ordered[K comparable, V any](held map[K]V, by func(K, K) int) []K {
	return slices.SortedFunc(maps.Keys(held), by)
}
