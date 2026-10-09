package sockets

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

// written is a socket as the kernel writes it in its tables, each address as
// the 32-bit words it holds in memory and the timer TIME_WAIT runs for a
// connection the kernel keeps for nobody.
func written(held Socket, timer int) string {
	encoded := func(endpoint netip.AddrPort) string {
		address := endpoint.Addr().AsSlice()
		var words strings.Builder
		for i := 0; i < len(address); i += 4 {
			fmt.Fprintf(&words, "%08X", binary.NativeEndian.Uint32(address[i:]))
		}
		return fmt.Sprintf("%s:%04X", words.String(), endpoint.Port())
	}
	return fmt.Sprintf("   4: %s %s %02X 00000000:00000000 %02X:00000000 00000000 %5d        0 %d 1 0000000000000000 100 0 0 10 0",
		encoded(held.Local), encoded(held.Remote), uint8(held.State), timer, held.User, held.Inode)
}

func header(size int) string {
	if size == 16 {
		return "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"
	}
	return "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode                                                     "
}

func endpoints(local, remote string) (netip.AddrPort, netip.AddrPort) {
	return netip.MustParseAddrPort(local), netip.MustParseAddrPort(remote)
}

func TestEachLineReadsAsTheSocketTheKernelKeeps(t *testing.T) {
	for _, held := range []struct {
		name     string
		protocol Protocol
		size     int
		local    string
		remote   string
		state    State
		timer    int
		user     uint32
		inode    uint64
		owned    bool
		listens  bool
		stated   string
	}{
		{name: "a listener", protocol: TCP, size: 4, local: "0.0.0.0:22", remote: "0.0.0.0:0", state: Listen, user: 0, inode: 27078, owned: true, listens: true, stated: "listen"},
		{name: "a connection", protocol: TCP, size: 4, local: "10.0.0.5:22", remote: "203.0.113.7:51514", state: Established, timer: 2, user: 0, inode: 88213, owned: true, stated: "established"},
		{name: "a connection the kernel keeps for nobody", protocol: TCP, size: 4, local: "10.0.0.5:41000", remote: "198.51.100.1:443", state: TimeWait, timer: timeWaiting, inode: 0, stated: "time-wait"},
		{name: "a connection closing for nobody", protocol: TCP, size: 4, local: "10.0.0.5:41002", remote: "198.51.100.1:443", state: FinWait2, timer: timeWaiting, inode: 0, stated: "fin-wait-2"},
		{name: "a connection not accepted yet", protocol: TCP, size: 4, local: "10.0.0.5:80", remote: "198.51.100.9:60000", state: SynReceived, timer: 1, user: 33, inode: 0, owned: true, stated: "syn-recv"},
		{name: "an IPv6 listener", protocol: TCP, size: 16, local: "[::]:22", remote: "[::]:0", state: Listen, user: 0, inode: 27080, owned: true, listens: true, stated: "listen"},
		{name: "an IPv4 peer of an IPv6 socket", protocol: TCP, size: 16, local: "[::ffff:127.0.0.1]:5432", remote: "[::ffff:127.0.0.1]:39812", state: Established, user: 112, inode: 90001, owned: true, stated: "established"},
		{name: "an IPv6 connection", protocol: TCP, size: 16, local: "[2001:db8::7]:443", remote: "[2001:db8:ffff::1]:52000", state: CloseWait, user: 1000, inode: 70001, owned: true, stated: "close-wait"},
		{name: "an unconnected UDP socket", protocol: UDP, size: 4, local: "127.0.0.53:53", remote: "0.0.0.0:0", state: Closed, user: 991, inode: 24574, owned: true, listens: true, stated: "unconnected"},
		{name: "a connected UDP socket", protocol: UDP, size: 4, local: "10.0.0.5:39000", remote: "192.0.2.53:53", state: Established, user: 1000, inode: 99999, owned: true, stated: "connected"},
		{name: "an unconnected UDP socket over IPv6", protocol: UDP, size: 16, local: "[fe80::1]:546", remote: "[::]:0", state: Closed, user: 0, inode: 12, owned: true, listens: true, stated: "unconnected"},
		{name: "a state no kernel has yet", protocol: TCP, size: 4, local: "10.0.0.5:7", remote: "10.0.0.6:7", state: 0xEE, user: 4294967294, inode: 18446744073709551615, owned: true, stated: "state 238"},
	} {
		local, remote := endpoints(held.local, held.remote)
		want := Socket{Protocol: held.protocol, Local: local, Remote: remote, State: held.state, User: held.user, Owned: held.owned, Inode: held.inode}
		line := written(want, held.timer)
		found, err := parse(held.protocol, held.size, line)
		switch {
		case err != nil:
			t.Errorf("%s, %q, does not read: %v", held.name, line, err)
		case found != want:
			t.Errorf("%s, %q, reads as %+v, want %+v", held.name, line, found, want)
		case found.Listening() != held.listens || found.StateName() != held.stated:
			t.Errorf("%s reads as listening %v in the state %q", held.name, found.Listening(), found.StateName())
		}
	}
}

func TestWhatTheKernelWritesOnALittleEndianHostReadsAsItsAddresses(t *testing.T) {
	if binary.NativeEndian.Uint16([]byte{1, 0}) != 1 {
		t.Skip("the kernel writes the words of an address in the order the host keeps them")
	}
	for _, held := range []struct {
		line string
		size int
		want string
	}{
		{"   0: 3600007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   991        0 24575 1 0000000000000000 100 0 0 10 5", 4, "127.0.0.54:53"},
		{"   1: 00000000000000000000000001000000:0277 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1", 16, "[::1]:631"},
		{"   2: 0000000000000000FFFF00000100007F:1538 0000000000000000FFFF00000100007F:9B84 01 00000000:00000000 00:00000000 00000000   112        0 3 1", 16, "[::ffff:127.0.0.1]:5432"},
	} {
		found, err := parse(TCP, held.size, held.line)
		if err != nil || found.Local.String() != held.want {
			t.Errorf("%q reads as %v, %v, want %s", held.line, found.Local, err, held.want)
		}
	}
}

func TestALineTheKernelWouldNotWriteIsRefused(t *testing.T) {
	good := written(Socket{Local: netip.MustParseAddrPort("10.0.0.5:22"), Remote: netip.MustParseAddrPort("0.0.0.0:0"), State: Listen, Inode: 1}, 0)
	fields := strings.Fields(good)
	replaced := func(at int, with string) string {
		changed := append([]string(nil), fields...)
		changed[at] = with
		return strings.Join(changed, " ")
	}
	for name, line := range map[string]string{
		"too few fields":        strings.Join(fields[:9], " "),
		"no slot":               replaced(0, "4"),
		"no port":               replaced(1, "0500000A"),
		"a short port":          replaced(1, "0500000A:16"),
		"a port that is no hex": replaced(1, "0500000A:00GG"),
		"an IPv6 address":       replaced(1, "00000000000000000000000001000000:0016"),
		"an address no hex":     replaced(1, "0500X00A:0016"),
		"a signed address":      replaced(2, "+0000000:0000"),
		"a state no hex":        replaced(3, "ZZ"),
		"a long state":          replaced(3, "00A"),
		"no timer":              replaced(5, "00"),
		"a timer no hex":        replaced(5, "QQ:00000000"),
		"an account no number":  replaced(7, "root"),
		"an account too large":  replaced(7, "4294967296"),
		"an inode no number":    replaced(9, "-1"),
	} {
		if found, err := parse(TCP, 4, line); err == nil {
			t.Errorf("a line with %s, %q, reads as %+v", name, line, found)
		}
	}
	if found, err := parse(TCP, 16, good); err == nil {
		t.Errorf("an IPv4 line read as IPv6 reads as %+v", found)
	}
}

func TestATableIsReadWholeWithinWhatTheAgentHolds(t *testing.T) {
	rows := []string{header(4)}
	for port := range 5 {
		rows = append(rows, written(Socket{Local: netip.AddrPortFrom(netip.MustParseAddr("10.0.0.5"), uint16(8000+port)), Remote: netip.MustParseAddrPort("0.0.0.0:0"), State: Listen, Inode: uint64(port + 1)}, 0))
	}
	content := strings.Join(rows, "\n") + "\n"
	found, read, err := table(strings.NewReader(content), TCP, 4, nil, 5)
	if err != nil || len(found) != 5 || read != int64(len(content)) || found[4].Local.Port() != 8004 {
		t.Errorf("a table of five sockets reads as %d sockets in %d bytes, %v", len(found), read, err)
	}
	earlier := []Socket{{Protocol: UDP}}
	if found, _, err := table(strings.NewReader(content), TCP, 4, earlier, 5); !errors.Is(err, ErrTooMany) || len(found) != 5 {
		t.Errorf("five sockets more than one already read, with room for five, read as %d, %v", len(found), err)
	}
	for name, content := range map[string]string{
		"nothing":            "",
		"a header it lacks":  rows[1] + "\n",
		"another header":     "  idx  local remote\n",
		"a line too long":    header(4) + "\n" + rows[1] + strings.Repeat(" 0", maxLine) + "\n",
		"a line that breaks": header(4) + "\n" + rows[1] + "\n   5: 0500000A\n",
	} {
		if found, _, err := table(strings.NewReader(content), TCP, 4, nil, 100); !errors.Is(err, ErrUnreadable) {
			t.Errorf("a table holding %s reads as %d sockets, %v", name, len(found), err)
		}
	}
	if found, _, err := table(strings.NewReader(header(16)+"\n"), UDP, 16, nil, 0); err != nil || len(found) != 0 {
		t.Errorf("a table of no socket reads as %d sockets, %v", len(found), err)
	}
}

func FuzzALineReadsAsTheSocketItWritesOrIsRefused(f *testing.F) {
	f.Add(uint8(TCP), 4, "   0: 3600007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   991        0 24575 1 0000000000000000 100 0 0 10 5")
	f.Add(uint8(TCP), 16, "   2: 0000000000000000FFFF00000100007F:1538 0000000000000000FFFF00000100007F:9B84 01 00000000:00000000 02:00000000 00000000   112        0 3 1")
	f.Add(uint8(UDP), 4, "  77: 00000000:0044 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 1 2 0000000000000000 0")
	f.Add(uint8(TCP), 4, "   9: 0500000A:A028 01643364:01BB 06 00000000:00000000 03:00001770 00000000     0        0 0 3 0000000000000000")
	f.Fuzz(func(t *testing.T, protocol uint8, size int, line string) {
		if size != 4 && size != 16 {
			return
		}
		found, err := parse(Protocol(protocol), size, line)
		if err != nil {
			return
		}
		timer := 0
		if !found.Owned && found.Protocol == TCP {
			timer = timeWaiting
		}
		again, err := parse(Protocol(protocol), size, written(found, timer))
		if err != nil || again != found {
			t.Errorf("%q reads as %+v, which written again reads as %+v, %v", line, found, again, err)
		}
		if found.Local.Addr().BitLen() != 8*size || found.Remote.Addr().BitLen() != 8*size {
			t.Errorf("%q reads as an address of %d bits", line, found.Local.Addr().BitLen())
		}
	})
}
