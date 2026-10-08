package network

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/platform/files"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/sockets"
	"github.com/dynasmon/Seagull-agent-v2/internal/secrets"
)

const (
	format         = 1
	stateFile      = "network.json"
	maxState       = 32 << 20
	maxNamespaces  = 256
	maxListeners   = 1 << 16
	maxStateText   = 256
	maxStateStates = 16
)

var (
	ErrDamaged   = errors.New("what the module last saw of the network cannot be read")
	ErrNewer     = errors.New("what the module last saw of the network was written down by a newer agent")
	ErrInsecure  = errors.New("what the module last saw of the network is not private to the account the agent runs as")
	errUnwritten = errors.New("the module has seen nothing of the network yet")
	interrupted  = regexp.MustCompile(`^\.` + regexp.QuoteMeta(stateFile) + `\.[0-9a-f]{16}\.tmp$`)
	protocols    = map[string]sockets.Protocol{"tcp": sockets.TCP, "udp": sockets.UDP}
	directions   = map[string]direction{"inbound": inbound, "outbound": outbound}
	associations = map[string]association{"none": byNobody, "accounts": byAccount, "processes": byProcess}
)

type stored struct {
	Format     int           `json:"format"`
	Boot       string        `json:"boot"`
	Namespaces []storedSpace `json:"namespaces"`
}

type storedSpace struct {
	Key       uint64           `json:"key"`
	Own       bool             `json:"own"`
	ID        string           `json:"id"`
	Host      bool             `json:"host"`
	Through   storedHolder     `json:"through"`
	Earliest  []storedHolder   `json:"earliest"`
	Processes int              `json:"processes"`
	Pending   bool             `json:"pending"`
	Listeners []storedListener `json:"listeners"`
	Flows     []storedFlow     `json:"flows"`
}

type storedHolder struct {
	PID     uint32 `json:"pid"`
	Name    string `json:"name"`
	Started int64  `json:"started_at"`
}

type storedListener struct {
	Protocol    string         `json:"protocol"`
	Address     string         `json:"address"`
	Port        uint16         `json:"port"`
	Accounts    []uint32       `json:"accounts"`
	Sockets     int            `json:"sockets"`
	Processes   []storedHolder `json:"processes"`
	Association string         `json:"association"`
}

type storedFlow struct {
	Direction   string         `json:"direction"`
	Protocol    string         `json:"protocol"`
	Remote      string         `json:"remote"`
	Port        uint16         `json:"port"`
	Account     uint32         `json:"account"`
	Owned       bool           `json:"owned"`
	First       int64          `json:"first"`
	Last        int64          `json:"last"`
	Most        int            `json:"most"`
	Missed      int            `json:"missed"`
	States      []string       `json:"states"`
	Processes   []storedHolder `json:"processes"`
	Association string         `json:"association"`
}

func encode(held *state) ([]byte, error) {
	written := stored{Format: format, Boot: held.boot, Namespaces: []storedSpace{}}
	for _, kept := range held.spaces {
		space := storedSpace{Key: kept.key, Own: kept.own, ID: kept.id, Host: kept.host, Through: storing(kept.through), Earliest: storingAll(kept.earliest),
			Processes: kept.processes, Pending: kept.pending, Listeners: []storedListener{}, Flows: []storedFlow{}}
		for _, at := range ordered(kept.listeners, byListening) {
			now := kept.listeners[at]
			space.Listeners = append(space.Listeners, storedListener{Protocol: at.protocol.String(), Address: at.address.String(), Port: at.port,
				Accounts: listed(now.accounts), Sockets: now.sockets, Processes: storingAll(now.processes), Association: now.association.String()})
		}
		for _, talk := range ordered(kept.flows, byConversation) {
			now := kept.flows[talk]
			space.Flows = append(space.Flows, storedFlow{Direction: talk.direction.String(), Protocol: talk.protocol.String(), Remote: talk.remote.String(), Port: talk.port,
				Account: talk.account, Owned: talk.owned, First: now.first.UnixNano(), Last: now.last.UnixNano(), Most: now.most, Missed: now.missed,
				States: listed(now.states), Processes: storingAll(now.processes), Association: now.association.String()})
		}
		written.Namespaces = append(written.Namespaces, space)
	}
	return json.Marshal(written)
}

func storing(member holder) storedHolder {
	if member.Started.IsZero() {
		return storedHolder{PID: member.PID, Name: member.Name}
	}
	return storedHolder{PID: member.PID, Name: member.Name, Started: member.Started.UnixNano()}
}

func storingAll(held []holder) []storedHolder {
	kept := []storedHolder{}
	for _, member := range held {
		kept = append(kept, storing(member))
	}
	return kept
}

func listed[T any](held []T) []T {
	if held == nil {
		return []T{}
	}
	return held
}

func decode(content []byte) (*state, error) {
	if len(content) > maxState {
		return nil, fmt.Errorf("%w: it is larger than %d bytes", ErrDamaged, maxState)
	}
	var declared struct {
		Format int `json:"format"`
	}
	if err := json.Unmarshal(content, &declared); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrDamaged, secrets.Bounded(err.Error()))
	}
	if declared.Format > format {
		return nil, fmt.Errorf("%w: format %d, and this agent reads format %d", ErrNewer, declared.Format, format)
	}
	var written stored
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&written); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrDamaged, secrets.Bounded(err.Error()))
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: it holds more than one state", ErrDamaged)
	}
	switch {
	case written.Format != format:
		return nil, fmt.Errorf("%w: format %d is not one this agent reads", ErrDamaged, written.Format)
	case len(written.Namespaces) > maxNamespaces || len(written.Boot) > maxStateText:
		return nil, fmt.Errorf("%w: it holds %d namespaces", ErrDamaged, len(written.Namespaces))
	case len(written.Namespaces) == 0 || !written.Namespaces[0].Own || slices.ContainsFunc(written.Namespaces[1:], func(space storedSpace) bool { return space.Own }):
		return nil, fmt.Errorf("%w: it does not hold the agent's own namespace first and alone", ErrDamaged)
	}
	held := &state{boot: written.Boot}
	flows := 0
	for _, space := range written.Namespaces {
		flows += len(space.Flows)
		kept, err := decoded(space)
		if err != nil {
			return nil, err
		}
		if flows > maxFlows || len(space.Listeners) > maxListeners {
			return nil, fmt.Errorf("%w: it holds %d flows and %d listeners", ErrDamaged, flows, len(space.Listeners))
		}
		held.spaces = append(held.spaces, kept)
	}
	return held, nil
}

func decoded(written storedSpace) (*space, error) {
	through, err := holderOf(written.Through)
	if err != nil || len(written.ID) > maxStateText || len(written.Earliest) > maxHolders || written.Processes < 0 {
		return nil, fmt.Errorf("%w: it describes the namespace %d as %s", ErrDamaged, written.Key, secrets.Bounded(written.ID))
	}
	kept := &space{key: written.Key, own: written.Own, id: written.ID, host: written.Host, through: through, processes: written.Processes, pending: written.Pending,
		listeners: map[listening]listener{}, flows: map[conversation]*flow{}, connected: map[connected]conversation{}}
	if kept.earliest, err = holdersOf(written.Earliest); err != nil {
		return nil, err
	}
	for _, saw := range written.Listeners {
		protocol, knownProtocol := protocols[saw.Protocol]
		address, err := netip.ParseAddr(saw.Address)
		known, knownAssociation := associations[saw.Association]
		at := listening{protocol: protocol, address: address, port: saw.Port}
		if !knownProtocol || err != nil || !knownAssociation || saw.Sockets < 1 || len(saw.Accounts) > maxHolders || !slices.IsSorted(saw.Accounts) {
			return nil, fmt.Errorf("%w: it holds the listener %s %s port %d", ErrDamaged, secrets.Shown(saw.Protocol), secrets.Shown(saw.Address), saw.Port)
		}
		if _, twice := kept.listeners[at]; twice {
			return nil, fmt.Errorf("%w: it holds the listener %s %s port %d twice", ErrDamaged, saw.Protocol, address, saw.Port)
		}
		processes, err := holdersOf(saw.Processes)
		if err != nil {
			return nil, err
		}
		kept.listeners[at] = listener{accounts: saw.Accounts, sockets: saw.Sockets, processes: processes, association: known}
	}
	for _, saw := range written.Flows {
		way, knownDirection := directions[saw.Direction]
		protocol, knownProtocol := protocols[saw.Protocol]
		remote, err := netip.ParseAddr(saw.Remote)
		known, knownAssociation := associations[saw.Association]
		talk := conversation{direction: way, protocol: protocol, remote: remote, port: saw.Port, account: saw.Account, owned: saw.Owned}
		if !knownDirection || !knownProtocol || err != nil || !knownAssociation || saw.Most < 0 || saw.Missed < 0 || saw.Missed >= linger ||
			len(saw.States) > maxStateStates || slices.ContainsFunc(saw.States, func(state string) bool { return len(state) > maxStateText }) {
			return nil, fmt.Errorf("%w: it holds the flow %s %s %s port %d", ErrDamaged, secrets.Shown(saw.Direction), secrets.Shown(saw.Protocol), secrets.Shown(saw.Remote), saw.Port)
		}
		if _, twice := kept.flows[talk]; twice {
			return nil, fmt.Errorf("%w: it holds the flow %s %s %s port %d twice", ErrDamaged, saw.Direction, saw.Protocol, remote, saw.Port)
		}
		processes, err := holdersOf(saw.Processes)
		if err != nil {
			return nil, err
		}
		kept.flows[talk] = &flow{first: time.Unix(0, saw.First).UTC(), last: time.Unix(0, saw.Last).UTC(), most: saw.Most, missed: saw.Missed, states: saw.States, processes: processes, association: known}
	}
	return kept, nil
}

func holderOf(written storedHolder) (holder, error) {
	if len(written.Name) > maxStateText {
		return holder{}, fmt.Errorf("%w: it names process %d %s", ErrDamaged, written.PID, secrets.Bounded(written.Name))
	}
	if written.Started == 0 {
		return holder{PID: written.PID, Name: written.Name}, nil
	}
	return holder{PID: written.PID, Name: written.Name, Started: time.Unix(0, written.Started).UTC()}, nil
}

func holdersOf(written []storedHolder) ([]holder, error) {
	if len(written) > maxHolders {
		return nil, fmt.Errorf("%w: it names %d processes where it keeps %d", ErrDamaged, len(written), maxHolders)
	}
	var held []holder
	for _, member := range written {
		one, err := holderOf(member)
		if err != nil {
			return nil, err
		}
		held = append(held, one)
	}
	return held, nil
}

func load(root *os.Root) (*state, error) {
	path := filepath.Join(root.Name(), stateFile)
	described, err := root.Lstat(stateFile)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, errUnwritten
	case err != nil:
		return nil, fmt.Errorf("inspect %s: %w", path, err)
	case !described.Mode().IsRegular():
		return nil, fmt.Errorf("%w: %s is not a regular file", ErrInsecure, path)
	}
	if err := files.Private(described); err != nil {
		if errors.Is(err, errors.ErrUnsupported) {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		return nil, fmt.Errorf("%w: %s %v", ErrInsecure, path, err)
	}
	file, err := root.Open(stateFile)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()
	if opened, err := file.Stat(); err != nil || !os.SameFile(opened, described) {
		return nil, fmt.Errorf("%w: %s changed while it was being opened", ErrInsecure, path)
	}
	content, err := io.ReadAll(io.LimitReader(file, maxState+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	held, err := decode(content)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return held, nil
}

// A state lost in a crash only has the module report again what it reported
// before, so the file is synced before it replaces the last one and the
// directory is not.
func save(root *os.Root, content []byte) error {
	path := filepath.Join(root.Name(), stateFile)
	random := make([]byte, 8)
	rand.Read(random)
	temporary := "." + stateFile + "." + hex.EncodeToString(random) + ".tmp"
	file, err := root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	_, err = file.Write(append(content, '\n'))
	if err == nil {
		err = file.Sync()
	}
	err = errors.Join(err, file.Close())
	if err == nil {
		err = root.Rename(temporary, stateFile)
	}
	if err != nil {
		if removed := root.Remove(temporary); removed != nil && !errors.Is(removed, fs.ErrNotExist) {
			err = errors.Join(err, removed)
		}
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func discard(root *os.Root) error {
	directory, err := root.Open(".")
	if err != nil {
		return fmt.Errorf("open %s: %w", root.Name(), err)
	}
	names, err := directory.Readdirnames(-1)
	directory.Close()
	if err != nil {
		return fmt.Errorf("list %s: %w", root.Name(), err)
	}
	for _, name := range names {
		if !interrupted.MatchString(name) {
			continue
		}
		if err := root.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("discard the interrupted write %s: %w", filepath.Join(root.Name(), name), err)
		}
	}
	return nil
}
