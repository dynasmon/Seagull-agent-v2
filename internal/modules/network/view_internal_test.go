package network

import (
	"maps"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/platform/sockets"
)

var seenAt = time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)

func listens(protocol sockets.Protocol, local string, user uint32, inode uint64) sockets.Socket {
	at := netip.MustParseAddrPort(local)
	remote := netip.AddrPortFrom(netip.IPv4Unspecified(), 0)
	if at.Addr().Is6() {
		remote = netip.AddrPortFrom(netip.IPv6Unspecified(), 0)
	}
	state := sockets.Listen
	if protocol == sockets.UDP {
		state = sockets.Closed
	}
	return sockets.Socket{Protocol: protocol, Local: at, Remote: remote, State: state, User: user, Owned: true, Inode: inode}
}

func talks(protocol sockets.Protocol, local, remote string, state sockets.State, user uint32, inode uint64) sockets.Socket {
	owned := !(protocol == sockets.TCP && state == sockets.TimeWait)
	if !owned {
		user = 0
	}
	return sockets.Socket{Protocol: protocol, Local: netip.MustParseAddrPort(local), Remote: netip.MustParseAddrPort(remote), State: state, User: user, Owned: owned, Inode: inode}
}

func flowing(way direction, protocol sockets.Protocol, remote string, port uint16, account uint32, owned bool) conversation {
	return conversation{direction: way, protocol: protocol, remote: netip.MustParseAddr(remote), port: port, account: account, owned: owned}
}

func TestASocketTableIsSeenAsTheListenersAndTheFlowsItHolds(t *testing.T) {
	read := sockets.Namespace{Own: true, Key: 7, ID: "net:[4026531833]", Host: true, Sockets: []sockets.Socket{
		listens(sockets.TCP, "0.0.0.0:22", 0, 1),
		listens(sockets.TCP, "[::]:22", 0, 2),
		listens(sockets.UDP, "127.0.0.53:53", 991, 3),
		listens(sockets.TCP, "0.0.0.0:80", 33, 4),
		listens(sockets.TCP, "0.0.0.0:80", 0, 5),
		listens(sockets.TCP, "127.0.0.1:631", 0, 6),
		listens(sockets.TCP, "0.0.0.0:8080", 1000, 7),
		talks(sockets.TCP, "10.0.0.5:22", "203.0.113.7:51514", sockets.Established, 0, 10),
		talks(sockets.TCP, "10.0.0.5:22", "203.0.113.7:51515", sockets.Established, 0, 11),
		talks(sockets.TCP, "[::ffff:10.0.0.5]:22", "[::ffff:203.0.113.8]:40000", sockets.Established, 0, 12),
		talks(sockets.TCP, "10.0.0.5:41000", "198.51.100.1:443", sockets.Established, 1000, 13),
		talks(sockets.TCP, "10.0.0.5:41001", "198.51.100.1:443", sockets.TimeWait, 0, 0),
		talks(sockets.TCP, "10.0.0.5:80", "198.51.100.9:60000", sockets.SynReceived, 33, 0),
		talks(sockets.UDP, "10.0.0.5:39000", "192.0.2.53:53", sockets.Established, 1000, 14),
		talks(sockets.TCP, "10.0.0.5:631", "198.51.100.2:9999", sockets.Established, 1000, 15),
		talks(sockets.TCP, "[2001:db8::5]:8080", "[2001:db8::9]:5000", sockets.SynSent, 1000, 16),
	}}
	holders := map[uint64][]sockets.Process{
		1:  {{PID: 900, Name: "sshd", StartedAt: seenAt.Add(-time.Hour)}},
		4:  {{PID: 1200, Name: "nginx", StartedAt: seenAt.Add(-time.Minute)}, {PID: 1201, Name: "nginx", StartedAt: seenAt.Add(-time.Minute)}},
		5:  {{PID: 1200, Name: "nginx", StartedAt: seenAt.Add(-time.Minute)}},
		13: {{PID: 4000, Name: "curl", StartedAt: seenAt.Add(-time.Second)}},
	}
	seen := viewed(read, holders, false, nil, seenAt)
	if !seen.own || seen.key != 7 || seen.id != "net:[4026531833]" || !seen.host {
		t.Errorf("the namespace is seen as %+v", seen)
	}
	wantListeners := map[listening]listener{
		{sockets.TCP, netip.MustParseAddr("0.0.0.0"), 22}:    {accounts: []uint32{0}, sockets: 1, processes: []holder{{PID: 900, Name: "sshd", Started: seenAt.Add(-time.Hour)}}, association: byAccount},
		{sockets.TCP, netip.MustParseAddr("::"), 22}:         {accounts: []uint32{0}, sockets: 1, association: byAccount},
		{sockets.UDP, netip.MustParseAddr("127.0.0.53"), 53}: {accounts: []uint32{991}, sockets: 1, association: byAccount},
		{sockets.TCP, netip.MustParseAddr("0.0.0.0"), 80}:    {accounts: []uint32{0, 33}, sockets: 2, processes: []holder{{PID: 1200, Name: "nginx", Started: seenAt.Add(-time.Minute)}, {PID: 1201, Name: "nginx", Started: seenAt.Add(-time.Minute)}}, association: byAccount},
		{sockets.TCP, netip.MustParseAddr("127.0.0.1"), 631}: {accounts: []uint32{0}, sockets: 1, association: byAccount},
		{sockets.TCP, netip.MustParseAddr("0.0.0.0"), 8080}:  {accounts: []uint32{1000}, sockets: 1, association: byAccount},
	}
	if !maps.EqualFunc(seen.listeners, wantListeners, func(a, b listener) bool {
		return slices.Equal(a.accounts, b.accounts) && a.sockets == b.sockets && slices.EqualFunc(a.processes, b.processes, holder.same) && a.association == b.association
	}) {
		t.Errorf("the listeners are\n%+v\nwant\n%+v", seen.listeners, wantListeners)
	}
	wantFlows := map[conversation]struct {
		connections int
		states      []string
		association association
		processes   int
	}{
		flowing(inbound, sockets.TCP, "203.0.113.7", 22, 0, true):        {2, []string{"established"}, byAccount, 0},
		flowing(inbound, sockets.TCP, "203.0.113.8", 22, 0, true):        {1, []string{"established"}, byAccount, 0},
		flowing(outbound, sockets.TCP, "198.51.100.1", 443, 1000, true):  {1, []string{"established"}, byAccount, 1},
		flowing(outbound, sockets.TCP, "198.51.100.1", 443, 0, false):    {1, []string{"time-wait"}, byNobody, 0},
		flowing(inbound, sockets.TCP, "198.51.100.9", 80, 33, true):      {1, []string{"syn-recv"}, byAccount, 0},
		flowing(outbound, sockets.UDP, "192.0.2.53", 53, 1000, true):     {1, []string{"connected"}, byAccount, 0},
		flowing(outbound, sockets.TCP, "198.51.100.2", 9999, 1000, true): {1, []string{"established"}, byAccount, 0},
		flowing(outbound, sockets.TCP, "2001:db8::9", 5000, 1000, true):  {1, []string{"syn-sent"}, byAccount, 0},
	}
	if len(seen.flows) != len(wantFlows) {
		t.Errorf("the namespace holds %d flows, want %d: %+v", len(seen.flows), len(wantFlows), slices.Collect(maps.Keys(seen.flows)))
	}
	for talk, want := range wantFlows {
		found := seen.flows[talk]
		if found == nil || found.connections != want.connections || !slices.Equal(found.states, want.states) || found.association != want.association ||
			len(found.processes) != want.processes || !found.first.Equal(seenAt) || !found.last.Equal(seenAt) {
			t.Errorf("the flow %+v is %+v, want %+v", talk, found, want)
		}
	}
	if len(seen.connected) != 9 {
		t.Errorf("the namespace remembers %d connections, want 9", len(seen.connected))
	}
}

func TestAConnectionStaysInTheFlowItWasSeenIn(t *testing.T) {
	before := map[connected]conversation{
		{sockets.TCP, netip.MustParseAddrPort("10.0.0.5:41001"), netip.MustParseAddrPort("198.51.100.1:443")}: flowing(outbound, sockets.TCP, "198.51.100.1", 443, 1000, true),
		{sockets.TCP, netip.MustParseAddrPort("10.0.0.5:8080"), netip.MustParseAddrPort("198.51.100.3:7000")}: flowing(inbound, sockets.TCP, "198.51.100.3", 8080, 1000, true),
		{sockets.TCP, netip.MustParseAddrPort("10.0.0.5:41002"), netip.MustParseAddrPort("198.51.100.1:443")}: flowing(outbound, sockets.TCP, "198.51.100.1", 443, 1000, true),
	}
	read := sockets.Namespace{Own: true, Sockets: []sockets.Socket{
		talks(sockets.TCP, "10.0.0.5:41001", "198.51.100.1:443", sockets.TimeWait, 0, 0),
		talks(sockets.TCP, "10.0.0.5:8080", "198.51.100.3:7000", sockets.FinWait1, 1000, 30),
		talks(sockets.TCP, "10.0.0.5:41002", "198.51.100.1:443", sockets.Established, 1001, 31),
	}}
	seen := viewed(read, nil, false, before, seenAt)
	if kept := seen.flows[flowing(outbound, sockets.TCP, "198.51.100.1", 443, 1000, true)]; kept == nil || kept.connections != 1 || !slices.Equal(kept.states, []string{"time-wait"}) {
		t.Errorf("a connection finishing in TIME_WAIT left the flow it was seen in: %+v", seen.flows)
	}
	if kept := seen.flows[flowing(inbound, sockets.TCP, "198.51.100.3", 8080, 1000, true)]; kept == nil {
		t.Errorf("a connection whose listener closed changed its direction: %+v", slices.Collect(maps.Keys(seen.flows)))
	}
	if kept := seen.flows[flowing(outbound, sockets.TCP, "198.51.100.1", 443, 1001, true)]; kept == nil {
		t.Errorf("a connection the kernel now keeps for another account stays in the flow of the first: %+v", slices.Collect(maps.Keys(seen.flows)))
	}
}

func TestOnceEveryDescriptorWasReadTheHoldersFoundAreAllThereAre(t *testing.T) {
	read := sockets.Namespace{Own: true, Sockets: []sockets.Socket{
		listens(sockets.TCP, "0.0.0.0:2049", 0, 40),
		talks(sockets.TCP, "10.0.0.5:41000", "198.51.100.1:443", sockets.Established, 1000, 41),
		talks(sockets.TCP, "10.0.0.5:41001", "198.51.100.1:443", sockets.TimeWait, 0, 0),
	}}
	var many []sockets.Process
	for pid := range uint32(20) {
		many = append(many, sockets.Process{PID: 100 + pid, Name: "worker", StartedAt: seenAt})
	}
	seen := viewed(read, map[uint64][]sockets.Process{41: many}, true, nil, seenAt)
	nfs := seen.listeners[listening{sockets.TCP, netip.MustParseAddr("0.0.0.0"), 2049}]
	if nfs.association != byProcess || len(nfs.processes) != 0 {
		t.Errorf("a listener the kernel holds, every descriptor read, is %+v", nfs)
	}
	shared := seen.flows[flowing(outbound, sockets.TCP, "198.51.100.1", 443, 1000, true)]
	if shared.association != byProcess || len(shared.processes) != maxHolders || shared.processes[0].PID != 100 {
		t.Errorf("a connection twenty processes share is held by %d of them as %v", len(shared.processes), shared.association)
	}
	if nobody := seen.flows[flowing(outbound, sockets.TCP, "198.51.100.1", 443, 0, false)]; nobody.association != byNobody {
		t.Errorf("a connection the kernel keeps for nobody is associated as %v", nobody.association)
	}
}
