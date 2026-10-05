package interfaces

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

func placeDevice(t *testing.T, root, name string, attributes map[string]string) {
	t.Helper()
	directory := filepath.Join(root, name)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	for attribute, content := range attributes {
		if err := os.WriteFile(filepath.Join(directory, attribute), []byte(content+"\n"), 0o444); err != nil {
			t.Fatal(err)
		}
	}
}

func classesAt(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	held := classes
	classes = root
	t.Cleanup(func() { classes = held })
	return root
}

func attributes(index, mac, mtu, link, flags, operstate, uevent string) map[string]string {
	return map[string]string{"ifindex": index, "address": mac, "mtu": mtu, "type": link, "flags": flags, "operstate": operstate, "uevent": uevent}
}

func TestEachInterfaceIsWhatSysfsAndProcfsSayOfIt(t *testing.T) {
	root := classesAt(t)
	placeDevice(t, root, "lo", attributes("1", "00:00:00:00:00:00", "65536", "772", "0x9", "unknown", "INTERFACE=lo\nIFINDEX=1"))
	placeDevice(t, root, "ens33", attributes("2", "00:0c:29:22:5b:23", "1500", "1", "0x1003", "up", "INTERFACE=ens33\nIFINDEX=2"))
	placeDevice(t, root, "docker0", attributes("4", "5a:38:73:e8:7c:b3", "1500", "1", "0x1003", "down", "DEVTYPE=bridge\nINTERFACE=docker0\nIFINDEX=4"))
	placeDevice(t, root, "wg0", attributes("5", "", "1420", "65534", "0x91", "unknown", "DEVTYPE=wireguard\nINTERFACE=wg0\nIFINDEX=5"))
	placeDevice(t, root, "eth1", attributes("6", "52:54:00:12:34:56", "9000", "1", "0x1002", "down", "INTERFACE=eth1\nIFINDEX=6"))
	placeDevice(t, root, "odd0", attributes("7", "", "1500", "4242", "0x1", "lowerlayerdown", ""))
	described, err := devices()
	if err != nil {
		t.Fatal(err)
	}
	listed := "00000000000000000000000000000001 01 80 10 80       lo\n" +
		"fe80000000000000020c29fffe225b23 02 40 20 80    ens33\n" +
		"20010db8000000000000000000000007 02 40 00 00    ens33\n" +
		"20010db8000000000000000000000009 63 40 00 00    gone0\n"
	masked := []labeled{
		{label: "lo", address: netip.MustParsePrefix("127.0.0.1/8")},
		{label: "lo", address: netip.MustParsePrefix("203.0.113.10/32")},
		{label: "ens33", address: netip.MustParsePrefix("192.168.132.128/24")},
		{label: "ens33:1", address: netip.MustParsePrefix("10.0.0.5/8")},
		{label: "gone0", address: netip.MustParsePrefix("198.51.100.1/24")},
	}
	held, err := assemble(described, []byte(listed), masked)
	if err != nil {
		t.Fatal(err)
	}
	want := []Interface{
		{Name: "docker0", Index: 4, MAC: "5a:38:73:e8:7c:b3", MTU: 1500, Type: "bridge"},
		{Name: "ens33", Index: 2, MAC: "00:0c:29:22:5b:23", MTU: 1500, Up: true, Type: "ether", Addresses: []netip.Prefix{
			netip.MustParsePrefix("10.0.0.5/8"), netip.MustParsePrefix("192.168.132.128/24"), netip.MustParsePrefix("2001:db8::7/64"), netip.MustParsePrefix("fe80::20c:29ff:fe22:5b23/64"),
		}},
		{Name: "eth1", Index: 6, MAC: "52:54:00:12:34:56", MTU: 9000, Type: "ether"},
		{Name: "lo", Index: 1, MAC: "00:00:00:00:00:00", MTU: 65536, Up: true, Type: "loopback", Addresses: []netip.Prefix{
			netip.MustParsePrefix("127.0.0.1/8"), netip.MustParsePrefix("203.0.113.10/32"), netip.MustParsePrefix("::1/128"),
		}},
		{Name: "odd0", Index: 7, MTU: 1500},
		{Name: "wg0", Index: 5, MTU: 1420, Up: true, Type: "wireguard"},
	}
	if !slices.EqualFunc(held, want, func(a, b Interface) bool {
		return a.Name == b.Name && a.Index == b.Index && a.MAC == b.MAC && a.MTU == b.MTU && a.Up == b.Up && a.Type == b.Type && slices.Equal(a.Addresses, b.Addresses)
	}) {
		t.Errorf("the host's interfaces are\n%+v\nwant\n%+v", held, want)
	}
}

func TestAnInterfaceRemovedAsItIsReadIsLeftOut(t *testing.T) {
	root := classesAt(t)
	placeDevice(t, root, "lo", attributes("1", "00:00:00:00:00:00", "65536", "772", "0x9", "unknown", ""))
	placeDevice(t, root, "veth0", map[string]string{"ifindex": "9", "address": "06:5f:ee:da:46:a6"})
	described, err := devices()
	if err != nil || len(described) != 1 || described[0].Name != "lo" {
		t.Errorf("an interface whose attributes went away was read as %+v and %v", described, err)
	}
}

func TestWhatSysfsOrProcfsSayThatDoesNotReadIsRefused(t *testing.T) {
	root := classesAt(t)
	placeDevice(t, root, "lo", attributes("one", "00:00:00:00:00:00", "65536", "772", "0x9", "unknown", ""))
	if _, err := devices(); !errors.Is(err, ErrUnreadable) {
		t.Errorf("an index that is no number was read as %v", err)
	}
	for _, listed := range []string{
		"00000000000000000000000000000001 01 80 10 80\n",
		"0000000000000000000000000000000g 01 80 10 80 lo\n",
		"000000000000000000000000000001 01 80 10 80 lo\n",
		"00000000000000000000000000000001 01 81 10 80 lo\n",
	} {
		if _, err := assemble(nil, []byte(listed), nil); !errors.Is(err, ErrUnreadable) {
			t.Errorf("%q was read as %v", listed, err)
		}
	}
	classes = filepath.Join(root, "absent")
	if _, err := devices(); !errors.Is(err, ErrUnreadable) {
		t.Errorf("a host with no /sys/class/net was read as %v", err)
	}
}

// The interfaces the agent reads without netlink are the ones the standard
// library reads with it, with the same addresses and prefixes.
func TestTheInterfacesOfThisHostAreTheOnesNetlinkLists(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the agent reads the interfaces of linux hosts")
	}
	held, err := List()
	if err != nil {
		t.Fatal(err)
	}
	linked, err := net.Interfaces()
	if err != nil {
		t.Skipf("netlink cannot list the interfaces here: %v", err)
	}
	if len(held) != len(linked) {
		t.Fatalf("the agent read %d interfaces and netlink lists %d", len(held), len(linked))
	}
	for _, listed := range linked {
		index := slices.IndexFunc(held, func(found Interface) bool { return found.Name == listed.Name })
		if index < 0 {
			t.Errorf("the agent did not read %s", listed.Name)
			continue
		}
		found := held[index]
		addresses, err := listed.Addrs()
		if err != nil {
			t.Fatal(err)
		}
		var want []string
		for _, address := range addresses {
			want = append(want, address.String())
		}
		var got []string
		for _, address := range found.Addresses {
			got = append(got, address.String())
		}
		slices.Sort(want)
		slices.Sort(got)
		mac := listed.HardwareAddr.String()
		if found.Index != listed.Index || int(found.MTU) != listed.MTU || (mac != "" && !strings.EqualFold(found.MAC, mac)) || found.Up != (listed.Flags&net.FlagRunning != 0) || !slices.Equal(got, want) {
			t.Errorf("the agent read %+v, and netlink lists %+v with %v", found, listed, want)
		}
	}
}
