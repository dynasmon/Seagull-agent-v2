package network

import (
	"cmp"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/dynasmon/Seagull-agent-v2/internal/platform/sockets"
)

const (
	maxHolders = 16
	maxText    = 256
	cut        = "..."
)

type direction uint8

const (
	outbound direction = iota + 1
	inbound
)

func (d direction) String() string {
	if d == inbound {
		return "inbound"
	}
	return "outbound"
}

// How far the module knows who holds a socket: nobody, as for a connection
// the kernel keeps in TIME_WAIT that it never saw before; the account the
// kernel keeps the socket for; or, once it read the descriptors of every
// process it was shown, the processes holding it as well, which are none for
// a socket the kernel or another PID namespace holds.
type association uint8

const (
	byNobody association = iota + 1
	byAccount
	byProcess
)

func (a association) String() string {
	switch a {
	case byProcess:
		return "processes"
	case byAccount:
		return "accounts"
	}
	return "none"
}

type holder struct {
	PID     uint32
	Name    string
	Started time.Time
}

type listening struct {
	protocol sockets.Protocol
	address  netip.Addr
	port     uint16
}

type listener struct {
	accounts    []uint32
	sockets     int
	processes   []holder
	association association
}

type conversation struct {
	direction direction
	protocol  sockets.Protocol
	remote    netip.Addr
	port      uint16
	account   uint32
	owned     bool
}

type flow struct {
	first       time.Time
	last        time.Time
	connections int
	most        int
	missed      int
	states      []string
	processes   []holder
	association association
}

type connected struct {
	protocol sockets.Protocol
	local    netip.AddrPort
	remote   netip.AddrPort
}

type served struct {
	protocol sockets.Protocol
	port     uint16
}

type space struct {
	key       uint64
	own       bool
	id        string
	host      bool
	through   holder
	earliest  []holder
	processes int
	pending   bool
	listeners map[listening]listener
	flows     map[conversation]*flow
	connected map[connected]conversation
}

// viewed is what one namespace's sockets say of it in one round. A connection
// keeps the direction and the account it had when the last round saw it, so
// one the kernel now finishes in TIME_WAIT stays in the flow it was seen in;
// a connection seen first is inbound when a listener of its namespace serves
// its local port, or when the kernel has not handed it to a process yet.
func viewed(read sockets.Namespace, holders map[uint64][]sockets.Process, complete bool, before map[connected]conversation, now time.Time) *space {
	seen := &space{key: read.Key, own: read.Own, id: read.ID, host: read.Host, through: holding(read.Through), processes: read.Processes,
		listeners: map[listening]listener{}, flows: map[conversation]*flow{}, connected: map[connected]conversation{}}
	for _, member := range read.Earliest {
		seen.earliest = append(seen.earliest, holding(member))
	}
	known := byAccount
	if complete {
		known = byProcess
	}
	ports := map[served][]netip.Addr{}
	for _, socket := range read.Sockets {
		if !socket.Listening() {
			continue
		}
		at := listening{protocol: socket.Protocol, address: socket.Local.Addr(), port: socket.Local.Port()}
		kept := seen.listeners[at]
		kept.sockets++
		kept.association = known
		if socket.Owned {
			kept.accounts = added(kept.accounts, socket.User)
		}
		kept.processes = held(kept.processes, holders[socket.Inode])
		seen.listeners[at] = kept
		ports[served{socket.Protocol, at.port}] = append(ports[served{socket.Protocol, at.port}], at.address)
	}
	for _, socket := range read.Sockets {
		if socket.Listening() {
			continue
		}
		tuple := connected{protocol: socket.Protocol, local: socket.Local, remote: socket.Remote}
		talk, again := before[tuple]
		if !again {
			talk = conversation{direction: outbound, protocol: socket.Protocol, remote: socket.Remote.Addr().Unmap(), port: socket.Remote.Port()}
			if inward(socket, ports[served{socket.Protocol, socket.Local.Port()}]) {
				talk.direction, talk.port = inbound, socket.Local.Port()
			}
		}
		if socket.Owned {
			talk.account, talk.owned = socket.User, true
		}
		seen.connected[tuple] = talk
		kept := seen.flows[talk]
		if kept == nil {
			kept = &flow{first: now, association: byNobody}
			seen.flows[talk] = kept
		}
		kept.last = now
		kept.connections++
		kept.most = max(kept.most, kept.connections)
		kept.states = added(kept.states, socket.StateName())
		kept.processes = held(kept.processes, holders[socket.Inode])
		if talk.owned {
			kept.association = known
		}
	}
	return seen
}

func inward(socket sockets.Socket, serving []netip.Addr) bool {
	if socket.Protocol == sockets.TCP && (socket.State == sockets.SynReceived || socket.State == sockets.NewSynReceived) {
		return true
	}
	local := socket.Local.Addr().Unmap()
	return slices.ContainsFunc(serving, func(address netip.Addr) bool {
		if address.IsUnspecified() {
			return address.Is6() || local.Is4()
		}
		return address.Unmap() == local
	})
}

func holding(member sockets.Process) holder {
	if member.PID == 0 && member.StartedAt.IsZero() {
		return holder{}
	}
	return holder{PID: member.PID, Name: told(member.Name), Started: member.StartedAt.UTC()}
}

// same tells whether two holders are one process: a PID names another one
// once the first ended, so the moment it started is part of who it is.
func (h holder) same(other holder) bool {
	return h.PID == other.PID && h.Started.Equal(other.Started)
}

func held(kept []holder, found []sockets.Process) []holder {
	for _, member := range found {
		kept = joined(kept, []holder{holding(member)})
	}
	return kept
}

func joined(was, now []holder) []holder {
	for _, member := range was {
		if len(now) >= maxHolders {
			break
		}
		if !slices.ContainsFunc(now, member.same) {
			now = append(now, member)
		}
	}
	slices.SortFunc(now, func(a, b holder) int { return cmp.Or(cmp.Compare(a.PID, b.PID), a.Started.Compare(b.Started)) })
	return now
}

func added[T cmp.Ordered](kept []T, one T) []T {
	at, found := slices.BinarySearch(kept, one)
	if found {
		return kept
	}
	return slices.Insert(kept, at, one)
}

// told is a name the host keeps as a message may carry it: one that is not
// printable text is quoted as Go quotes a string, and every name is cut at
// 256 bytes, so no name a process chose for itself breaks the line it is in.
func told(text string) string {
	if text == "" || !utf8.ValidString(text) || strings.IndexFunc(text, func(held rune) bool { return !unicode.IsPrint(held) }) >= 0 {
		text = strconv.Quote(text)
	}
	if len(text) <= maxText {
		return text
	}
	held := text[:maxText-len(cut)]
	for !utf8.ValidString(held) {
		held = held[:len(held)-1]
	}
	return held + cut
}
