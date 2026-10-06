// Package interfaces reads the network interfaces of the network namespace
// the agent runs in: what sysfs says of each, the IPv6 addresses procfs lists
// for it, and the IPv4 addresses the kernel hands an AF_INET socket through
// SIOCGIFCONF. It opens no netlink socket, so the agent needs none.
package interfaces

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/dynasmon/Seagull-agent-v2/internal/platform/files"
	"github.com/dynasmon/Seagull-agent-v2/internal/secrets"
)

const (
	maxAttribute = 4 << 10
	maxListing   = 16 << 20
	attempts     = 3
	up           = 0x1
)

var (
	classes = "/sys/class/net"
	inet6   = "/proc/net/if_inet6"
)

var ErrUnreadable = errors.New("the network interfaces of the host cannot be read")

var linkTypes = map[int]string{
	1: "ether", 32: "infiniband", 280: "can", 512: "ppp", 768: "ipip", 769: "tunnel6", 772: "loopback",
	776: "sit", 778: "gre", 801: "ieee802.11", 823: "gre6", 65534: "none", 65535: "void",
}

// Type is the kind of device sysfs names, such as bridge or vlan, and the
// link type otherwise, named as ip-link(8) names it. Up is what the kernel
// reports as IFF_RUNNING: administratively up, and operationally up or unknown.
type Interface struct {
	Name      string
	Index     int
	MAC       string
	MTU       uint32
	Up        bool
	Type      string
	Addresses []netip.Prefix
}

type labeled struct {
	label   string
	address netip.Prefix
}

// List reads the interfaces again when the IPv4 addresses changed between the
// first reading and the last, so their prefixes are those of one moment.
func List() ([]Interface, error) {
	for range attempts {
		masked, err := ipv4(true)
		if err != nil {
			return nil, err
		}
		described, err := devices()
		if err != nil {
			return nil, err
		}
		listed, err := files.Read(inet6, maxListing)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%w: %w", ErrUnreadable, err)
		}
		again, err := ipv4(false)
		if err != nil {
			return nil, err
		}
		if !slices.EqualFunc(masked, again, func(a, b labeled) bool { return a.label == b.label && a.address.Addr() == b.address.Addr() }) {
			continue
		}
		return assemble(described, listed, masked)
	}
	return nil, fmt.Errorf("%w: their addresses changed each of the %d times they were read", ErrUnreadable, attempts)
}

func devices() ([]Interface, error) {
	entries, err := os.ReadDir(classes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnreadable, err)
	}
	held := make([]Interface, 0, len(entries))
	for _, entry := range entries {
		described, present, err := device(entry.Name())
		if err != nil {
			return nil, err
		}
		if present {
			held = append(held, described)
		}
	}
	return held, nil
}

// An interface removed after the directory was listed is no longer there,
// and is left out as one that never was.
func device(name string) (Interface, bool, error) {
	read := map[string]string{}
	for _, attribute := range []string{"ifindex", "address", "mtu", "type", "flags", "operstate", "uevent"} {
		content, err := files.Read(filepath.Join(classes, name, attribute), maxAttribute)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			return Interface{}, false, nil
		case err != nil:
			return Interface{}, false, fmt.Errorf("%w: %w", ErrUnreadable, err)
		}
		read[attribute] = strings.TrimSpace(string(content))
	}
	index, indexed := strconv.Atoi(read["ifindex"])
	mtu, measured := strconv.ParseUint(read["mtu"], 10, 32)
	link, typed := strconv.Atoi(read["type"])
	flags, flagged := strconv.ParseUint(strings.TrimPrefix(read["flags"], "0x"), 16, 32)
	if indexed != nil || measured != nil || typed != nil || flagged != nil {
		return Interface{}, false, fmt.Errorf("%w: sysfs describes %s as %s", ErrUnreadable, secrets.Shown(name), secrets.Bounded(fmt.Sprint(read)))
	}
	held := Interface{Name: name, Index: index, MAC: read["address"], MTU: uint32(mtu), Type: linkTypes[link]}
	held.Up = flags&up != 0 && (read["operstate"] == "up" || read["operstate"] == "unknown")
	for line := range strings.SplitSeq(read["uevent"], "\n") {
		if kind, found := strings.CutPrefix(line, "DEVTYPE="); found && kind != "" {
			held.Type = kind
		}
	}
	return held, true, nil
}

func assemble(described []Interface, listed []byte, masked []labeled) ([]Interface, error) {
	named := map[string]*Interface{}
	for i := range described {
		named[described[i].Name] = &described[i]
	}
	for _, held := range masked {
		device, _, _ := strings.Cut(held.label, ":")
		if found := named[device]; found != nil {
			found.Addresses = append(found.Addresses, held.address)
		}
	}
	for line := range strings.SplitSeq(strings.TrimSpace(string(listed)), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 6 {
			return nil, fmt.Errorf("%w: %s lists %s", ErrUnreadable, inet6, secrets.Shown(line))
		}
		raw, err := hex.DecodeString(fields[0])
		length, measured := strconv.ParseUint(fields[2], 16, 8)
		if err != nil || len(raw) != 16 || measured != nil || length > 128 {
			return nil, fmt.Errorf("%w: %s lists %s", ErrUnreadable, inet6, secrets.Shown(line))
		}
		if found := named[fields[5]]; found != nil {
			found.Addresses = append(found.Addresses, netip.PrefixFrom(netip.AddrFrom16([16]byte(raw)), int(length)))
		}
	}
	for _, held := range described {
		slices.SortFunc(held.Addresses, func(a, b netip.Prefix) int {
			if order := a.Addr().Compare(b.Addr()); order != 0 {
				return order
			}
			return a.Bits() - b.Bits()
		})
	}
	slices.SortFunc(described, func(a, b Interface) int { return strings.Compare(a.Name, b.Name) })
	return described, nil
}
