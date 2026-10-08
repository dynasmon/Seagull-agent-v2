//go:build linux

package sockets

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/platform/processes"
)

const (
	bootedAt = 1759752000
	boot     = "6c1e4c49-0f6e-4a39-9d4e-3c1f2b7a9e10"
)

// A procfs tree the test writes: when the host booted, which process the agent
// is, and each process with its stat, its status, the tables of the namespace
// it runs in, linked so every process of a namespace shows the same inode, as
// procfs does, its descriptors and what its namespace link reads.
type tree struct {
	t    *testing.T
	root string
}

type running struct {
	pid         uint32
	name        string
	started     uint64
	namespace   string
	descriptors []string
}

func plant(t *testing.T, self uint32, namespaces map[string][]Socket, processes ...running) tree {
	t.Helper()
	held := tree{t: t, root: t.TempDir()}
	held.write("stat", fmt.Sprintf("cpu  1 2 3 4\nbtime %d\nprocesses 4242\n", bootedAt))
	held.write("sys/kernel/random/boot_id", boot+"\n")
	for name, sockets := range namespaces {
		for _, kept := range tables {
			rows := []string{header(kept.size)}
			for _, socket := range sockets {
				if socket.Protocol == kept.protocol && socket.Local.Addr().BitLen() == 8*kept.size {
					timer := 0
					if !socket.Owned && socket.Protocol == TCP {
						timer = timeWaiting
					}
					rows = append(rows, written(socket, timer))
				}
			}
			held.write(filepath.Join("namespaces", name, kept.name), strings.Join(rows, "\n")+"\n")
		}
	}
	for _, process := range processes {
		held.add(process)
	}
	if err := os.Symlink(strconv.FormatUint(uint64(self), 10), filepath.Join(held.root, "self")); err != nil {
		t.Fatal(err)
	}
	return held
}

func (h tree) write(name, content string) {
	h.t.Helper()
	path := filepath.Join(h.root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		h.t.Fatal(err)
	}
}

func (h tree) add(process running) {
	h.t.Helper()
	pid := strconv.FormatUint(uint64(process.pid), 10)
	h.write(pid+"/stat", fmt.Sprintf("%s (%s) S 1 %s 1 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 %d 24301568 3685 18446744073709551615 1 1 0 0 0 0 0 4096 1260 0 0 0 17 3 0 0 0 0 0\n",
		pid, process.name, pid, process.started))
	h.write(pid+"/status", fmt.Sprintf("Name:\t%s\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n", process.name))
	if err := os.MkdirAll(filepath.Join(h.root, pid, "net"), 0o755); err != nil {
		h.t.Fatal(err)
	}
	for _, kept := range tables {
		if err := os.Link(filepath.Join(h.root, "namespaces", process.namespace, kept.name), filepath.Join(h.root, pid, "net", kept.name)); err != nil {
			h.t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(h.root, pid, "ns"), 0o755); err != nil {
		h.t.Fatal(err)
	}
	if err := os.Symlink(identity(process.namespace), filepath.Join(h.root, pid, "ns", "net")); err != nil {
		h.t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(h.root, pid, "fd"), 0o755); err != nil {
		h.t.Fatal(err)
	}
	for i, target := range process.descriptors {
		if err := os.Symlink(target, filepath.Join(h.root, pid, "fd", strconv.Itoa(i))); err != nil {
			h.t.Fatal(err)
		}
	}
}

func identity(namespace string) string {
	number := uint64(4026531840)
	for _, letter := range namespace {
		number += uint64(letter)
	}
	return fmt.Sprintf("net:[%d]", number)
}

func at(ticks uint64) time.Time {
	return time.Unix(bootedAt, 0).UTC().Add(time.Duration(ticks) * 10 * time.Millisecond)
}

func listener(protocol Protocol, local string, user uint32, inode uint64) Socket {
	remote := netip.AddrPortFrom(netip.IPv4Unspecified(), 0)
	state := Listen
	if netip.MustParseAddrPort(local).Addr().Is6() {
		remote = netip.AddrPortFrom(netip.IPv6Unspecified(), 0)
	}
	if protocol == UDP {
		state = Closed
	}
	return Socket{Protocol: protocol, Local: netip.MustParseAddrPort(local), Remote: remote, State: state, User: user, Owned: true, Inode: inode}
}

func connection(local, remote string, state State, user uint32, inode uint64) Socket {
	return Socket{Protocol: TCP, Local: netip.MustParseAddrPort(local), Remote: netip.MustParseAddrPort(remote), State: state, User: user, Owned: state != TimeWait, Inode: inode}
}

var limits = Limits{Processes: 100, Namespaces: 8, Sockets: 100, Descriptors: 100}

func ordered(held []Socket) []Socket {
	return slices.SortedFunc(slices.Values(held), func(a, b Socket) int { return int(a.Inode) - int(b.Inode) })
}

func TestTheAgentReadsTheSocketsOfItsOwnNamespaceWhenProcfsHidesTheRest(t *testing.T) {
	host := []Socket{
		listener(TCP, "0.0.0.0:22", 0, 100),
		listener(TCP, "[::]:22", 0, 101),
		listener(UDP, "127.0.0.53:53", 991, 102),
		connection("10.0.0.5:22", "203.0.113.7:51514", Established, 0, 103),
		connection("10.0.0.5:41000", "198.51.100.1:443", TimeWait, 0, 0),
		connection("10.0.0.5:52000", "192.0.2.10:8443", Established, 997, 300),
	}
	planted := plant(t, 77, map[string][]Socket{"host": host},
		running{pid: 77, name: "seagull-agent", started: 900, namespace: "host", descriptors: []string{"/dev/null", "socket:[300]", "pipe:[4]", "socket:[]", "anon_inode:[eventpoll]"}})
	reading, err := read(t.Context(), planted.root, limits)
	if err != nil {
		t.Fatal(err)
	}
	if len(reading.Namespaces) != 1 || !reading.Hidden || reading.Boot != boot || reading.Unvisited != nil || reading.Skipped != 0 || reading.Unread != 0 {
		t.Fatalf("with procfs showing the agent alone, the reading is %+v", reading)
	}
	own := reading.Namespaces[0]
	if !own.Own || own.Host || own.ID != identity("host") || own.Processes != 1 || own.Failure != nil || own.Through.PID != 0 {
		t.Errorf("the agent's own namespace reads as %+v", own)
	}
	if !slices.Equal(ordered(own.Sockets), ordered(host)) {
		t.Errorf("the agent's own namespace holds\n%+v\nwant\n%+v", own.Sockets, host)
	}
	agent := Process{PID: 77, Name: "seagull-agent", StartedAt: at(900)}
	if len(reading.Holders) != 1 || !slices.Equal(reading.Holders[300], []Process{agent}) {
		t.Errorf("the agent holds %v", reading.Holders)
	}
	if reading.Bytes <= 0 {
		t.Errorf("reading %d sockets cost %d bytes", len(own.Sockets), reading.Bytes)
	}
}

func TestTheNamespaceOfAProcessThatMayNotBeDumpedIsNamed(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("the superuser reads every directory")
	}
	planted := plant(t, 77, map[string][]Socket{"host": {}}, running{pid: 77, name: "seagull-agent", started: 900, namespace: "host"})
	closed := filepath.Join(planted.root, "77", "ns")
	if err := os.Chmod(closed, 0o111); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(closed, 0o755) })
	reading, err := read(t.Context(), planted.root, limits)
	if err != nil || reading.Namespaces[0].ID != identity("host") {
		t.Errorf("with the links of its namespaces closed to all but a path through them, the agent's namespace reads as %q, %v", reading.Namespaces[0].ID, err)
	}
}

func TestEveryOtherNamespaceIsReadThroughAProcessInIt(t *testing.T) {
	host := []Socket{listener(TCP, "0.0.0.0:22", 0, 100)}
	box := []Socket{listener(TCP, "0.0.0.0:80", 0, 200), connection("172.17.0.2:80", "172.17.0.1:40000", Established, 33, 201)}
	other := []Socket{listener(UDP, "[::]:5353", 1000, 300)}
	planted := plant(t, 77, map[string][]Socket{"host": host, "box": box, "other": other},
		running{pid: 1, name: "systemd", started: 1, namespace: "host", descriptors: []string{"socket:[100]"}},
		running{pid: 77, name: "seagull-agent", started: 900, namespace: "host"},
		running{pid: 500, name: "nginx", started: 700, namespace: "box", descriptors: []string{"socket:[200]"}},
		running{pid: 501, name: "nginx", started: 650, namespace: "box", descriptors: []string{"socket:[200]", "socket:[201]"}},
		running{pid: 900, name: "a) S 1 (b", started: 800, namespace: "other", descriptors: []string{"socket:[300]"}},
	)
	reading, err := read(t.Context(), planted.root, limits)
	if err != nil {
		t.Fatal(err)
	}
	if reading.Hidden || len(reading.Namespaces) != 3 {
		t.Fatalf("with procfs showing every process, the reading is %+v", reading)
	}
	for i, want := range []struct {
		id        string
		host      bool
		through   uint32
		processes int
		sockets   []Socket
		earliest  []uint32
	}{
		{id: identity("host"), host: true, processes: 2, sockets: host, earliest: []uint32{1, 77}},
		{id: identity("box"), through: 500, processes: 2, sockets: box, earliest: []uint32{501, 500}},
		{id: identity("other"), through: 900, processes: 1, sockets: other, earliest: []uint32{900}},
	} {
		space := reading.Namespaces[i]
		var earliest []uint32
		for _, member := range space.Earliest {
			earliest = append(earliest, member.PID)
		}
		if space.ID != want.id || space.Host != want.host || space.Own != (i == 0) || space.Through.PID != want.through || space.Processes != want.processes ||
			!slices.Equal(ordered(space.Sockets), ordered(want.sockets)) || !slices.Equal(earliest, want.earliest) || space.Failure != nil {
			t.Errorf("namespace %d reads as %+v", i, space)
		}
	}
	if through := reading.Namespaces[2].Through; through.Name != "a) S 1 (b" || !through.StartedAt.Equal(at(800)) {
		t.Errorf("the process another namespace was read through is %+v", through)
	}
	shared := reading.Holders[200]
	if len(shared) != 2 || shared[0].PID != 500 || shared[1].PID != 501 || len(reading.Holders[201]) != 1 || len(reading.Holders[100]) != 1 || len(reading.Holders[300]) != 1 {
		t.Errorf("the sockets are held by %v", reading.Holders)
	}
}

func TestDescriptorsTheAgentMayNotReadHoldNothing(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("the superuser reads every directory")
	}
	planted := plant(t, 77, map[string][]Socket{"host": {listener(TCP, "0.0.0.0:22", 0, 100)}},
		running{pid: 1, name: "systemd", started: 1, namespace: "host", descriptors: []string{"socket:[100]"}},
		running{pid: 77, name: "seagull-agent", started: 900, namespace: "host"},
	)
	closed := filepath.Join(planted.root, "1", "fd")
	if err := os.Chmod(closed, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(closed, 0o755) })
	reading, err := read(t.Context(), planted.root, limits)
	if err != nil || reading.Unread != 1 || len(reading.Holders) != 0 || reading.Hidden {
		t.Errorf("with the descriptors of process 1 closed to the agent, the reading is %+v, %v", reading, err)
	}
}

func TestAReadingLooksAtNoMoreThanItsLimitsAllow(t *testing.T) {
	many := []Socket{listener(TCP, "0.0.0.0:80", 0, 200), listener(TCP, "0.0.0.0:443", 0, 201), listener(TCP, "0.0.0.0:8080", 0, 202)}
	planted := plant(t, 77, map[string][]Socket{"host": {listener(TCP, "0.0.0.0:22", 0, 100)}, "box": many, "other": {listener(UDP, "0.0.0.0:53", 0, 300)}},
		running{pid: 1, name: "systemd", started: 1, namespace: "host", descriptors: []string{"socket:[100]"}},
		running{pid: 77, name: "seagull-agent", started: 900, namespace: "host"},
		running{pid: 500, name: "nginx", started: 700, namespace: "box", descriptors: []string{"socket:[200]", "/dev/null"}},
		running{pid: 900, name: "dnsmasq", started: 800, namespace: "other"},
	)
	reading, err := read(t.Context(), planted.root, Limits{Processes: 100, Namespaces: 2, Sockets: 3, Descriptors: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(reading.Namespaces) != 2 || reading.Skipped != 1 || reading.Unread != 1 || len(reading.Holders[100]) != 1 || len(reading.Holders) != 1 {
		t.Errorf("with room for two namespaces and one descriptor, the reading is %+v", reading)
	}
	if box := reading.Namespaces[1]; !errors.Is(box.Failure, ErrTooMany) || box.Sockets != nil || len(reading.Namespaces[0].Sockets) != 1 {
		t.Errorf("with room for three sockets, one of them read, a namespace of three reads as %+v", box)
	}
	reading, err = read(t.Context(), planted.root, Limits{Processes: 3, Namespaces: 8, Sockets: 100, Descriptors: 100})
	if err != nil || !errors.Is(reading.Unvisited, processes.ErrTooMany) || len(reading.Namespaces) != 1 || reading.Hidden || len(reading.Namespaces[0].Sockets) != 1 {
		t.Errorf("with room for three of four processes, the reading is %+v, %v", reading, err)
	}
}

func TestANamespaceWhoseProcessEndsAsItIsReadIsReadThroughTheNext(t *testing.T) {
	box := []Socket{listener(TCP, "0.0.0.0:80", 0, 200)}
	planted := plant(t, 77, map[string][]Socket{"host": {}, "box": box},
		running{pid: 77, name: "seagull-agent", started: 900, namespace: "host"},
		running{pid: 500, name: "ending", started: 700, namespace: "box"},
		running{pid: 501, name: "nginx", started: 701, namespace: "box"},
	)
	if err := os.Remove(filepath.Join(planted.root, "500", "net", "udp")); err != nil {
		t.Fatal(err)
	}
	reading, err := read(t.Context(), planted.root, limits)
	if err != nil || len(reading.Namespaces) != 2 {
		t.Fatalf("the reading is %+v, %v", reading, err)
	}
	if space := reading.Namespaces[1]; space.Failure != nil || space.Through.PID != 501 || !slices.Equal(space.Sockets, box) || space.Processes != 2 {
		t.Errorf("a namespace whose first process ended reads as %+v", space)
	}
}

func TestAnAgentThatCannotReadItsOwnNamespaceReadsNothing(t *testing.T) {
	planted := plant(t, 77, map[string][]Socket{"host": {}}, running{pid: 77, name: "seagull-agent", started: 900, namespace: "host"})
	if err := os.Remove(filepath.Join(planted.root, "77", "net", "tcp")); err != nil {
		t.Fatal(err)
	}
	if reading, err := read(t.Context(), planted.root, limits); !errors.Is(err, ErrUnreadable) {
		t.Errorf("without a table of its own the reading is %+v, %v", reading, err)
	}
	planted = plant(t, 77, map[string][]Socket{"host": {}}, running{pid: 77, name: "seagull-agent", started: 900, namespace: "host"})
	planted.write("namespaces/host/udp", "  sl  local_address\n   0: what\n")
	reading, err := read(t.Context(), planted.root, limits)
	if err != nil || !errors.Is(reading.Namespaces[0].Failure, ErrUnreadable) || reading.Namespaces[0].Sockets != nil {
		t.Errorf("with a table that does not read, the reading is %+v, %v", reading, err)
	}
}

func TestTheAgentReadsTheSocketsThisHostHolds(t *testing.T) {
	listening, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listening.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		held, err := listening.Accept()
		if err == nil {
			accepted <- held
		}
		close(accepted)
	}()
	dialed, err := net.Dial("tcp4", listening.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer dialed.Close()
	if held, ok := <-accepted; ok {
		defer held.Close()
	}
	bound, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer bound.Close()
	wanted := map[string]bool{
		"tcp listen " + listening.Addr().String():                                             false,
		"tcp established " + dialed.LocalAddr().String() + " " + dialed.RemoteAddr().String(): false,
		"udp unconnected " + bound.LocalAddr().String():                                       false,
	}
	if listening6, err := net.Listen("tcp6", "[::1]:0"); err == nil {
		defer listening6.Close()
		wanted["tcp listen "+listening6.Addr().String()] = false
	}
	reading, err := Read(t.Context(), Limits{Processes: 1 << 16, Namespaces: 256, Sockets: 1 << 16, Descriptors: 1 << 18})
	if err != nil {
		t.Fatal(err)
	}
	own := reading.Namespaces[0]
	if !own.Own || own.Failure != nil || !strings.HasPrefix(own.ID, "net:[") || len(reading.Boot) != 36 {
		t.Fatalf("this host's own namespace reads as %+v, %v", own.ID, own.Failure)
	}
	for _, socket := range own.Sockets {
		said := fmt.Sprintf("%s %s %s", socket.Protocol, socket.StateName(), socket.Local)
		if socket.State != Listen && socket.Protocol == TCP {
			said += " " + socket.Remote.String()
		}
		if _, wants := wanted[said]; !wants {
			continue
		}
		wanted[said] = true
		holders := reading.Holders[socket.Inode]
		if !socket.Owned || socket.User != uint32(os.Getuid()) || socket.Inode == 0 || len(holders) != 1 || holders[0].PID != uint32(os.Getpid()) {
			t.Errorf("%s reads as %+v, held by %v", said, socket, holders)
		}
	}
	for said, found := range wanted {
		if !found {
			t.Errorf("this host holds %s, which the reading does not", said)
		}
	}
}
