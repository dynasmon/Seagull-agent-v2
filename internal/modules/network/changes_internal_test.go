package network

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/platform/sockets"
)

const boot = "6c1e4c49-0f6e-4a39-9d4e-3c1f2b7a9e10"

func own(held ...sockets.Socket) sockets.Namespace {
	return sockets.Namespace{Own: true, Key: 1, ID: "net:[4026531833]", Host: true, Sockets: held}
}

func other(key uint64, pid uint32, started time.Time, held ...sockets.Socket) sockets.Namespace {
	through := sockets.Process{PID: pid, Name: "box", StartedAt: started}
	return sockets.Namespace{Key: key, Through: through, Earliest: []sockets.Process{through}, Processes: 1, Sockets: held}
}

func reading(namespaces ...sockets.Namespace) sockets.Reading {
	return sockets.Reading{Boot: boot, Namespaces: namespaces}
}

// rounds compares each reading with the state the one before it left, the
// first of them the baseline, and says what each round changed.
func rounds(t *testing.T, held *state, adjust func(*comparison), readings ...sockets.Reading) (*state, [][]string) {
	t.Helper()
	var said [][]string
	for i, read := range readings {
		compared := &comparison{now: seenAt.Add(time.Duration(i) * time.Minute), adopting: held == nil}
		if adjust != nil {
			adjust(compared)
		}
		held = compared.compare(held, read)
		var round []string
		for _, found := range compared.changes {
			round = append(round, described(found))
		}
		said = append(said, round)
	}
	return held, said
}

func described(found change) string {
	switch found.message {
	case listenerOpened, listenerClosed:
		return fmt.Sprintf("%s %s %s:%d", found.message, found.listening.protocol, found.listening.address, found.listening.port)
	case listenerChanged:
		return fmt.Sprintf("%s %s %s:%d %s", found.message, found.listening.protocol, found.listening.address, found.listening.port, strings.Join(found.changed, ","))
	case flowStarted, flowEnded:
		return fmt.Sprintf("%s %s %s %s:%d %d", found.message, found.talk.direction, found.talk.protocol, found.talk.remote, found.talk.port, found.talk.account)
	}
	return fmt.Sprintf("%s %d", found.message, found.space.key)
}

func TestTheFirstRoundIsTheBaselineAndTheNextOnesSayWhatOpensAndCloses(t *testing.T) {
	ssh := listens(sockets.TCP, "0.0.0.0:22", 0, 1)
	web := listens(sockets.TCP, "0.0.0.0:80", 33, 2)
	webAsRoot := listens(sockets.TCP, "0.0.0.0:80", 0, 3)
	dns := listens(sockets.UDP, "127.0.0.53:53", 991, 4)
	session := talks(sockets.TCP, "10.0.0.5:22", "203.0.113.7:51514", sockets.Established, 0, 5)
	_, said := rounds(t, nil, nil,
		reading(own(ssh, web, session)),
		reading(own(ssh, webAsRoot, dns, session)),
		reading(own(ssh, webAsRoot, dns, session)),
		reading(own(webAsRoot, dns)),
	)
	want := [][]string{
		nil,
		{"listener_changed tcp 0.0.0.0:80 accounts", "listener_opened udp 127.0.0.53:53"},
		nil,
		{"listener_closed tcp 0.0.0.0:22"},
	}
	if !slices.EqualFunc(said, want, slices.Equal) {
		t.Errorf("the rounds said\n%q\nwant\n%q", said, want)
	}
}

func TestAListenerHeldByOtherProgramsChangesAndOneStartedAgainDoesNot(t *testing.T) {
	ssh := listens(sockets.TCP, "0.0.0.0:22", 0, 1)
	held := func(inode uint64, name string, pid uint32) sockets.Reading {
		read := reading(own(ssh))
		read.Holders = map[uint64][]sockets.Process{inode: {{PID: pid, Name: name, StartedAt: seenAt.Add(time.Duration(pid))}}}
		return read
	}
	_, said := rounds(t, nil, func(c *comparison) { c.complete = true },
		held(1, "sshd", 900),
		held(1, "sshd", 901),
		held(1, "nc", 902),
	)
	if want := [][]string{nil, nil, {"listener_changed tcp 0.0.0.0:22 processes"}}; !slices.EqualFunc(said, want, slices.Equal) {
		t.Errorf("the rounds said %q, want %q", said, want)
	}
	_, said = rounds(t, nil, nil, held(1, "sshd", 900), held(1, "nc", 902))
	if want := [][]string{nil, nil}; !slices.EqualFunc(said, want, slices.Equal) {
		t.Errorf("without reading every descriptor, the rounds said %q, want %q", said, want)
	}
}

func TestAFlowEndsOnceRoundsInARowDidNotSeeIt(t *testing.T) {
	first := talks(sockets.TCP, "10.0.0.5:41000", "198.51.100.1:443", sockets.Established, 1000, 10)
	second := talks(sockets.TCP, "10.0.0.5:41001", "198.51.100.1:443", sockets.Established, 1000, 11)
	other := talks(sockets.UDP, "10.0.0.5:39000", "192.0.2.53:53", sockets.Established, 1000, 12)
	held, said := rounds(t, nil, nil,
		reading(own()),
		reading(own(first)),
		reading(own()),
		reading(own(first, second)),
		reading(own(other)),
		reading(own()),
		reading(own()),
	)
	want := [][]string{
		nil,
		{"flow_started outbound tcp 198.51.100.1:443 1000"},
		nil,
		nil,
		{"flow_started outbound udp 192.0.2.53:53 1000"},
		nil,
		{"flow_ended outbound tcp 198.51.100.1:443 1000"},
	}
	if !slices.EqualFunc(said, want, slices.Equal) {
		t.Errorf("the rounds said\n%q\nwant\n%q", said, want)
	}
	kept := held.spaces[0].flows[flowing(outbound, sockets.UDP, "192.0.2.53", 53, 1000, true)]
	if kept == nil || kept.missed != 2 || kept.connections != 0 || !kept.first.Equal(seenAt.Add(4*time.Minute)) {
		t.Errorf("a flow two rounds missed is kept as %+v", kept)
	}

	_, said = rounds(t, nil, nil, reading(own(first, second)), reading(own()))
	_, ended := rounds(t, held, func(c *comparison) { c.ending = true }, reading(own()))
	if len(said[1]) != 0 || !slices.Equal(ended[0], []string{"flow_ended outbound udp 192.0.2.53:53 1000"}) {
		t.Errorf("a flow missed once said %q, and missed as the module starts said %q", said[1], ended[0])
	}
}

func TestAFlowKeepsWhenItBeganAndTheMostConnectionsItHad(t *testing.T) {
	var many []sockets.Socket
	for port := range 3 {
		many = append(many, talks(sockets.TCP, fmt.Sprintf("10.0.0.5:%d", 41000+port), "198.51.100.1:443", sockets.Established, 1000, uint64(10+port)))
	}
	held, _ := rounds(t, nil, nil, reading(own()), reading(own(many...)), reading(own(many[0])), reading(own()), reading(own()))
	final := &comparison{now: seenAt.Add(time.Hour)}
	final.compare(held, reading(own()))
	if len(final.changes) != 1 || final.changes[0].message != flowEnded {
		t.Fatalf("a flow three rounds missed said %+v", final.changes)
	}
	if ended := final.changes[0].flow; ended.most != 3 || !ended.first.Equal(seenAt.Add(time.Minute)) || !ended.last.Equal(seenAt.Add(2*time.Minute)) {
		t.Errorf("a flow of three connections, then one, ended as %+v", ended)
	}
}

func TestNamespacesAreToldApartByTheProcessesInThem(t *testing.T) {
	started := seenAt.Add(-time.Hour)
	web := listens(sockets.TCP, "0.0.0.0:80", 0, 20)
	api := listens(sockets.TCP, "0.0.0.0:8080", 0, 21)
	whole, said := rounds(t, nil, nil,
		reading(own(), other(9, 500, started, web)),
		reading(own(), other(9, 500, started, web, api)),
		reading(own(), other(9, 700, seenAt, web)),
		reading(own()),
	)
	want := [][]string{
		nil,
		{"listener_opened tcp 0.0.0.0:8080"},
		{"network_namespace_seen 9", "listener_opened tcp 0.0.0.0:80", "network_namespace_gone 9"},
		{"network_namespace_gone 9"},
	}
	if !slices.EqualFunc(said, want, slices.Equal) || len(whole.spaces) != 1 {
		t.Errorf("the rounds said\n%q\nwant\n%q", said, want)
	}

	partial := reading(own())
	partial.Skipped = 1
	hidden := reading(own())
	hidden.Hidden = true
	held, said := rounds(t, nil, nil, reading(own(), other(9, 500, started, web)), partial)
	if len(said[1]) != 0 || len(held.spaces) != 2 {
		t.Errorf("a namespace a reading skipped said %q and is kept as %d namespaces", said[1], len(held.spaces))
	}
	held, said = rounds(t, held, nil, hidden)
	if len(said[0]) != 0 || len(held.spaces) != 1 {
		t.Errorf("a namespace procfs hides said %q and is kept as %d namespaces", said[0], len(held.spaces))
	}
	_, said = rounds(t, held, func(c *comparison) { c.adopting = true }, reading(own(), other(9, 500, started, web)))
	if len(said[0]) != 0 {
		t.Errorf("a namespace the module adopts said %q", said[0])
	}
}

func TestANamespaceTheReadingCouldNotReadStaysAsItWas(t *testing.T) {
	started := seenAt.Add(-time.Hour)
	web := listens(sockets.TCP, "0.0.0.0:80", 0, 20)
	flow := talks(sockets.TCP, "172.17.0.2:80", "172.17.0.1:40000", sockets.Established, 0, 21)
	failed := other(9, 500, started)
	failed.Failure = sockets.ErrTooMany
	ownFailed := own()
	ownFailed.Failure = sockets.ErrUnreadable
	held, said := rounds(t, nil, nil,
		reading(own(), other(9, 500, started, web, flow)),
		reading(own(), failed),
		reading(ownFailed, failed),
		reading(own(), other(9, 500, started, web, flow)),
	)
	if !slices.EqualFunc(said, [][]string{nil, nil, nil, nil}, slices.Equal) || len(held.spaces[1].listeners) != 1 || len(held.spaces[1].flows) != 1 {
		t.Errorf("namespaces the readings could not read said %q", said)
	}

	held, said = rounds(t, nil, nil, reading(own(), failed), reading(own(), other(9, 500, started, web)), reading(own(), other(9, 500, started)))
	if want := [][]string{nil, nil, {"listener_closed tcp 0.0.0.0:80"}}; !slices.EqualFunc(said, want, slices.Equal) || held.spaces[1].pending {
		t.Errorf("a namespace first met unread said %q, want %q", said, want)
	}
	if !errors.Is(failed.Failure, sockets.ErrTooMany) {
		t.Fatal(failed.Failure)
	}
}

func TestFlowsPastWhatTheModuleKeepsAreCounted(t *testing.T) {
	kept := maxFlows
	maxFlows = 2
	t.Cleanup(func() { maxFlows = kept })
	var many []sockets.Socket
	for port := range 4 {
		many = append(many, talks(sockets.TCP, fmt.Sprintf("10.0.0.5:%d", 41000+port), fmt.Sprintf("198.51.100.%d:443", port+1), sockets.Established, 1000, uint64(10+port)))
	}
	compared := &comparison{now: seenAt, adopting: true}
	held := compared.compare(nil, reading(own(many[:1]...)))
	compared = &comparison{now: seenAt.Add(time.Minute)}
	held = compared.compare(held, reading(own(many...)))
	if len(held.spaces[0].flows) != 2 || compared.untracked != 2 || len(compared.changes) != 1 {
		t.Errorf("four flows where two are kept leave %d flows, %d untracked, %d changes", len(held.spaces[0].flows), compared.untracked, len(compared.changes))
	}
}

func TestAQuietComparisonTakesTheFlowsAndComparesTheListeners(t *testing.T) {
	ssh := listens(sockets.TCP, "0.0.0.0:22", 0, 1)
	session := talks(sockets.TCP, "10.0.0.5:22", "203.0.113.7:51514", sockets.Established, 0, 5)
	held, _ := rounds(t, nil, nil, reading(own(ssh, session)))
	held = rebooted(held)
	compared := &comparison{now: seenAt.Add(time.Hour), adopting: true, ending: true, quiet: true}
	compared.compare(held, reading(own(listens(sockets.TCP, "0.0.0.0:8022", 0, 9), talks(sockets.TCP, "10.0.0.5:8022", "203.0.113.9:1000", sockets.Established, 0, 10))))
	var said []string
	for _, found := range compared.changes {
		said = append(said, described(found))
	}
	if want := []string{"listener_opened tcp 0.0.0.0:8022", "listener_closed tcp 0.0.0.0:22"}; !slices.Equal(said, want) {
		t.Errorf("after the host booted again the module said %q, want %q", said, want)
	}
}
