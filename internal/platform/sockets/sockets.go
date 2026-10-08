// Package sockets reads the TCP and UDP sockets of the network namespaces
// procfs shows the agent: its own through /proc/self, and each other one
// through the first process procfs lists in it, which procfs shows the agent
// once it shows it the processes of other accounts. Every process is read
// through the directory /proc keeps of it, and a socket is held by a process
// only when the agent read that socket's inode among the process's descriptors.
package sockets

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/platform/processes"
)

const (
	earliest     = 8
	maxHolders   = 16
	maxBootBytes = 64
	listing      = 256
	visitCost    = 1 << 10
	linkCost     = 64
)

var proc = "/proc"

var errMoved = errors.New("the process moved to another network namespace as its sockets were read")

var tables = []struct {
	name     string
	protocol Protocol
	size     int
}{{"tcp", TCP, 4}, {"tcp6", TCP, 16}, {"udp", UDP, 4}, {"udp6", UDP, 16}}

// What one reading may look at: the processes it lists, the namespaces it
// reads, its own among them, the sockets of every namespace together, and the
// descriptors of every process together.
type Limits struct {
	Processes   int
	Namespaces  int
	Sockets     int
	Descriptors int
}

type Process struct {
	PID       uint32
	Name      string
	StartedAt time.Time
}

type Namespace struct {
	Key       uint64
	ID        string
	Own       bool
	Host      bool
	Through   Process
	Earliest  []Process
	Processes int
	Sockets   []Socket
	Failure   error
}

type Reading struct {
	Boot       string
	Namespaces []Namespace
	Hidden     bool
	Unvisited  error
	Refused    int
	Skipped    int
	Holders    map[uint64][]Process
	Unread     int
	Bytes      int64
}

func read(ctx context.Context, root string, limits Limits) (Reading, error) {
	held, err := os.OpenRoot(root)
	if err != nil {
		return Reading{}, fmt.Errorf("%w: %w", ErrUnreadable, err)
	}
	defer held.Close()
	self, err := held.OpenRoot("self")
	if err != nil {
		return Reading{}, fmt.Errorf("%w: %w", ErrUnreadable, err)
	}
	defer self.Close()
	own, err := key(self)
	if err != nil {
		return Reading{}, fmt.Errorf("%w: the agent's own network namespace: %w", ErrUnreadable, err)
	}
	reading := Reading{Boot: booted(held), Hidden: true, Holders: map[uint64][]Process{}}
	left := limits.Sockets
	spaces := []*Namespace{{Key: own, Own: true, ID: identified(root, "self")}}
	spaces[0].Sockets, spaces[0].Failure = reading.tabled(self, own, &left)
	byKey := map[uint64]*Namespace{own: spaces[0]}
	kept := map[uint64]bool{own: true}
	descriptors := limits.Descriptors
	refused, unvisited := processes.Visit(ctx, root, limits.Processes, func(found processes.Process, directory *os.Root) error {
		reading.Bytes += visitCost
		in, err := key(directory)
		switch {
		case went(err):
			return nil
		case err != nil:
			reading.Refused++
			return nil
		}
		member := Process{PID: found.PID, Name: found.Name, StartedAt: found.StartedAt}
		space := byKey[in]
		if space == nil {
			space = &Namespace{Key: in}
			byKey[in] = space
			kept[in] = len(spaces) < limits.Namespaces
			if kept[in] {
				spaces = append(spaces, space)
			} else {
				reading.Skipped++
			}
		}
		if kept[in] && !space.Own && (space.Through.PID == 0 || went(space.Failure)) {
			space.ID, space.Through = identified(root, strconv.FormatUint(uint64(found.PID), 10)), member
			space.Sockets, space.Failure = reading.tabled(directory, in, &left)
			if space.Failure != nil {
				space.ID = ""
			}
		}
		if found.PID == 1 {
			space.Host, reading.Hidden = true, false
		}
		space.Processes++
		space.Earliest = before(space.Earliest, member)
		reading.holders(directory, member, &descriptors)
		return nil
	})
	reading.Refused += refused
	reading.Unvisited = unvisited
	if err := ctx.Err(); err != nil {
		return Reading{}, err
	}
	if reading.Unvisited != nil {
		reading.Hidden = false
	}
	tabled := map[uint64]bool{}
	for _, space := range spaces {
		reading.Namespaces = append(reading.Namespaces, *space)
		for _, socket := range space.Sockets {
			tabled[socket.Inode] = true
		}
	}
	maps.DeleteFunc(reading.Holders, func(inode uint64, _ []Process) bool { return !tabled[inode] })
	return reading, nil
}

// tabled reads the tables of the namespace directory's process runs in, and
// fails the reading when that process moved to another one meanwhile, or the
// tables hold more sockets than are left to read.
func (r *Reading) tabled(directory *os.Root, in uint64, left *int) ([]Socket, error) {
	var found []Socket
	for _, kept := range tables {
		file, err := directory.Open("net/" + kept.name)
		if errors.Is(err, fs.ErrNotExist) && kept.size == 16 {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrUnreadable, err)
		}
		var read int64
		found, read, err = table(file, kept.protocol, kept.size, found, *left)
		file.Close()
		r.Bytes += read
		if err != nil {
			return nil, err
		}
	}
	if still, err := key(directory); err != nil || still != in {
		return nil, fmt.Errorf("%w: %w", ErrUnreadable, errMoved)
	}
	*left -= len(found)
	return found, nil
}

func (r *Reading) holders(directory *os.Root, member Process, left *int) {
	descriptors, err := directory.OpenRoot("fd")
	if err != nil {
		if errors.Is(err, fs.ErrPermission) {
			r.Unread++
		}
		return
	}
	defer descriptors.Close()
	listed, err := descriptors.Open(".")
	if err != nil {
		r.Unread++
		return
	}
	defer listed.Close()
	for {
		names, err := listed.Readdirnames(listing)
		for _, name := range names {
			if *left <= 0 {
				r.Unread++
				return
			}
			*left--
			r.Bytes += linkCost
			target, err := descriptors.Readlink(name)
			if err != nil {
				continue
			}
			if inode, socket := pointed(target); socket && len(r.Holders[inode]) < maxHolders {
				r.Holders[inode] = append(r.Holders[inode], member)
			}
		}
		if err != nil {
			return
		}
	}
}

func pointed(target string) (uint64, bool) {
	written, found := strings.CutPrefix(target, "socket:[")
	written, closed := strings.CutSuffix(written, "]")
	inode, err := strconv.ParseUint(written, 10, 64)
	return inode, found && closed && err == nil && inode > 0
}

func went(err error) bool {
	return errors.Is(err, errMoved) || errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ESRCH)
}

func key(directory *os.Root) (uint64, error) {
	described, err := directory.Stat("net/tcp")
	if err != nil {
		return 0, err
	}
	held, known := inode(described)
	if !known {
		return 0, fmt.Errorf("procfs numbers no inode of %s: %w", described.Name(), errors.ErrUnsupported)
	}
	return held, nil
}

// identified reads which namespace a process runs in by the path of its link
// rather than through the directory /proc keeps of it: procfs closes the
// directory of the links of a process that may not be dumped, the agent among
// them, to everyone but root, and a path only needs to pass through it. The
// tables read through that directory afterwards say the process is the one
// whose link was read, and a reading that fails names no namespace.
func identified(root, pid string) string {
	link, err := os.Readlink(filepath.Join(root, pid, "ns", "net"))
	written, found := strings.CutPrefix(link, "net:[")
	written, closed := strings.CutSuffix(written, "]")
	if _, number := strconv.ParseUint(written, 10, 64); err != nil || !found || !closed || number != nil {
		return ""
	}
	return link
}

func booted(held *os.Root) string {
	file, err := held.Open("sys/kernel/random/boot_id")
	if err != nil {
		return ""
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, maxBootBytes))
	written := strings.TrimSpace(string(content))
	if err != nil || len(written) != 36 || strings.Trim(written, "0123456789abcdef-") != "" {
		return ""
	}
	return written
}

func before(held []Process, member Process) []Process {
	at, _ := slices.BinarySearchFunc(held, member, func(a, b Process) int {
		if c := a.StartedAt.Compare(b.StartedAt); c != 0 {
			return c
		}
		return int(a.PID) - int(b.PID)
	})
	if at >= earliest {
		return held
	}
	held = slices.Insert(held, at, member)
	return held[:min(len(held), earliest)]
}
