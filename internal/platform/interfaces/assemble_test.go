package interfaces

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func described() []Interface {
	return []Interface{{Name: "lo", Index: 1, Type: "loopback"}, {Name: "ens33", Index: 2, Type: "ether"}}
}

// Whatever procfs lists of the IPv6 addresses, each one read belongs to an
// interface sysfs described, in order, and is what listing it again reads as.
func FuzzAssemble(f *testing.F) {
	f.Add([]byte("00000000000000000000000000000001 01 80 10 80       lo\nfe80000000000000020c29fffe7d4b3c 02 40 20 80    ens33\n20010db8000000000000000000000007 05 40 00 00 seagull0\n"))
	f.Add([]byte("0000 01 80 10 80 lo\n"))
	f.Add([]byte("00000000000000000000000000000001 01 81 10 80 lo\n"))
	f.Fuzz(func(t *testing.T, listed []byte) {
		held, err := assemble(described(), listed, nil)
		if err != nil {
			if !errors.Is(err, ErrUnreadable) || len(err.Error()) > 1<<10 {
				t.Fatalf("the listing was refused for no reason it names, or a long one: %.200v", err)
			}
			return
		}
		var again strings.Builder
		for _, adapter := range held {
			if !slices.IsSortedFunc(adapter.Addresses, func(a, b netip.Prefix) int {
				if order := a.Addr().Compare(b.Addr()); order != 0 {
					return order
				}
				return a.Bits() - b.Bits()
			}) {
				t.Fatalf("the addresses of %s are not in order: %v", adapter.Name, adapter.Addresses)
			}
			for _, address := range adapter.Addresses {
				if !address.Addr().Is6() || address.Bits() < 0 || address.Bits() > 128 {
					t.Fatalf("%s was read as an address of %s", address, adapter.Name)
				}
				raw := address.Addr().As16()
				fmt.Fprintf(&again, "%s 01 %02x 00 00 %s\n", hex.EncodeToString(raw[:]), address.Bits(), adapter.Name)
			}
		}
		reread, err := assemble(described(), []byte(again.String()), nil)
		if err != nil || !slices.EqualFunc(reread, held, func(a, b Interface) bool { return a.Name == b.Name && slices.Equal(a.Addresses, b.Addresses) }) {
			t.Fatalf("the addresses read were listed again as %q, which reads as %+v: %v", again.String(), reread, err)
		}
	})
}
