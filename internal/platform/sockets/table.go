package sockets

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"

	"github.com/dynasmon/Seagull-agent-v2/internal/secrets"
)

const (
	maxLine     = 512
	timeWaiting = 3
)

var (
	ErrUnreadable = errors.New("the sockets of the host cannot be read")
	ErrTooMany    = errors.New("the host holds more sockets than the agent reads")
)

type Protocol uint8

const (
	TCP Protocol = iota + 1
	UDP
)

func (p Protocol) String() string {
	switch p {
	case TCP:
		return "tcp"
	case UDP:
		return "udp"
	}
	return "protocol " + strconv.Itoa(int(p))
}

// A State is the number the kernel keeps for the state of a socket: where a
// TCP connection stands, or whether a UDP socket is connected to one peer,
// which the kernel says with the numbers of TCP's established and closed.
type State uint8

const (
	Established State = iota + 1
	SynSent
	SynReceived
	FinWait1
	FinWait2
	TimeWait
	Closed
	CloseWait
	LastAck
	Listen
	Closing
	NewSynReceived
)

var named = [...]string{
	Established: "established", SynSent: "syn-sent", SynReceived: "syn-recv", FinWait1: "fin-wait-1", FinWait2: "fin-wait-2", TimeWait: "time-wait",
	Closed: "close", CloseWait: "close-wait", LastAck: "last-ack", Listen: "listen", Closing: "closing", NewSynReceived: "new-syn-recv",
}

// A Socket is what a table says of one: its endpoints, its state, the account
// the kernel keeps it for and its inode, which is 0 when no process holds it,
// as for a connection the kernel finishes alone, one a listener has not
// accepted yet, or one closed whose last segments are on their way. The kernel
// keeps a TCP connection in TIME_WAIT for nobody, so its account is not Owned.
type Socket struct {
	Protocol Protocol
	Local    netip.AddrPort
	Remote   netip.AddrPort
	State    State
	User     uint32
	Owned    bool
	Inode    uint64
}

func (s Socket) Listening() bool {
	if s.Protocol == UDP {
		return s.State == Closed
	}
	return s.State == Listen
}

func (s Socket) StateName() string {
	switch {
	case s.Protocol == UDP && s.State == Established:
		return "connected"
	case s.Protocol == UDP && s.State == Closed:
		return "unconnected"
	case int(s.State) < len(named) && named[s.State] != "":
		return named[s.State]
	}
	return "state " + strconv.Itoa(int(s.State))
}

func table(reader io.Reader, protocol Protocol, size int, found []Socket, most int) ([]Socket, int64, error) {
	lines := bufio.NewScanner(reader)
	lines.Buffer(make([]byte, 0, maxLine), maxLine)
	var read int64
	header := true
	for lines.Scan() {
		line := lines.Text()
		read += int64(len(line)) + 1
		if header {
			header = false
			if fields := strings.Fields(line); len(fields) < 3 || fields[0] != "sl" || fields[1] != "local_address" {
				return found, read, fmt.Errorf("%w: a table begins %s", ErrUnreadable, secrets.Bounded(line))
			}
			continue
		}
		if len(found) >= most {
			return found, read, fmt.Errorf("%w: more than %d", ErrTooMany, most)
		}
		held, err := parse(protocol, size, line)
		if err != nil {
			return found, read, fmt.Errorf("%w: %w", ErrUnreadable, err)
		}
		found = append(found, held)
	}
	if err := lines.Err(); err != nil {
		return found, read, fmt.Errorf("%w: %w", ErrUnreadable, err)
	}
	if header {
		return found, read, fmt.Errorf("%w: a table is empty", ErrUnreadable)
	}
	return found, read, nil
}

// parse reads one line of a table as the kernel writes it for TCP and UDP
// over IPv4 and IPv6: each address as the 32-bit words it holds in memory,
// each port as a number, then the state, the queues, which timer runs, the
// account and the inode. TIME_WAIT's timer is the one a connection the kernel
// keeps for nobody runs, whatever state it shows.
func parse(protocol Protocol, size int, line string) (Socket, error) {
	fields := strings.Fields(line)
	if len(fields) < 10 || !strings.HasSuffix(fields[0], ":") {
		return Socket{}, fmt.Errorf("a socket reads %s", secrets.Bounded(line))
	}
	local, err := endpoint(fields[1], size)
	if err != nil {
		return Socket{}, err
	}
	remote, err := endpoint(fields[2], size)
	if err != nil {
		return Socket{}, err
	}
	state, err := strconv.ParseUint(fields[3], 16, 8)
	if err != nil || len(fields[3]) != 2 {
		return Socket{}, fmt.Errorf("a socket is in the state %s", secrets.Shown(fields[3]))
	}
	timer, _, found := strings.Cut(fields[5], ":")
	running, err := strconv.ParseUint(timer, 16, 8)
	if !found || err != nil {
		return Socket{}, fmt.Errorf("a socket runs the timer %s", secrets.Shown(fields[5]))
	}
	user, err := strconv.ParseUint(fields[7], 10, 32)
	if err != nil {
		return Socket{}, fmt.Errorf("a socket belongs to %s", secrets.Shown(fields[7]))
	}
	inode, err := strconv.ParseUint(fields[9], 10, 64)
	if err != nil {
		return Socket{}, fmt.Errorf("a socket has the inode %s", secrets.Shown(fields[9]))
	}
	held := Socket{Protocol: protocol, Local: local, Remote: remote, State: State(state), User: uint32(user), Owned: true, Inode: inode}
	if protocol == TCP && (running == timeWaiting || held.State == TimeWait) {
		held.User, held.Owned = 0, false
	}
	return held, nil
}

func endpoint(field string, size int) (netip.AddrPort, error) {
	written, port, found := strings.Cut(field, ":")
	number, err := strconv.ParseUint(port, 16, 16)
	if !found || len(port) != 4 || err != nil || len(written) != 2*size {
		return netip.AddrPort{}, fmt.Errorf("an endpoint reads %s", secrets.Shown(field))
	}
	held := make([]byte, size)
	for i := 0; i < size; i += 4 {
		word, err := strconv.ParseUint(written[2*i:2*i+8], 16, 32)
		if err != nil {
			return netip.AddrPort{}, fmt.Errorf("an endpoint reads %s", secrets.Shown(field))
		}
		binary.NativeEndian.PutUint32(held[i:], uint32(word))
	}
	address, _ := netip.AddrFromSlice(held)
	return netip.AddrPortFrom(address, uint16(number)), nil
}
