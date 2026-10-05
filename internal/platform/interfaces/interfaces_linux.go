//go:build linux

package interfaces

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
	"net/netip"
	"runtime"
	"slices"
	"syscall"
	"unsafe"
)

const (
	nameBytes   = 16
	requestSize = nameBytes + 2*unsafe.Sizeof(uintptr(0)) + 8
	family      = nameBytes
	address     = nameBytes + 4
	firstRead   = 64
	mostEntries = 1 << 16
)

type configuration struct {
	length int32
	buffer *byte
}

// ipv4 asks the kernel for every IPv4 address an interface of the namespace
// holds, under the label it was given, and, when masked, for the prefix each
// was added with: SIOCGIFNETMASK matches a label and an address together when
// it is handed both.
func ipv4(masked bool) ([]labeled, error) {
	socket, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: open an IPv4 socket: %w", ErrUnreadable, err)
	}
	defer syscall.Close(socket)
	for entries := firstRead; entries <= mostEntries; entries *= 2 {
		buffer := make([]byte, entries*int(requestSize))
		listed := configuration{length: int32(len(buffer)), buffer: &buffer[0]}
		err := control(socket, syscall.SIOCGIFCONF, unsafe.Pointer(&listed))
		runtime.KeepAlive(buffer)
		if err != nil {
			return nil, fmt.Errorf("%w: list the IPv4 addresses: %w", ErrUnreadable, err)
		}
		if int(listed.length) >= len(buffer) {
			continue
		}
		var held []labeled
		for offset := 0; offset+int(requestSize) <= int(listed.length); offset += int(requestSize) {
			request := buffer[offset : offset+int(requestSize)]
			if binary.NativeEndian.Uint16(request[family:]) != syscall.AF_INET {
				continue
			}
			label := string(request[:nameBytes])
			if end := slices.Index(request[:nameBytes], 0); end >= 0 {
				label = string(request[:end])
			}
			found := netip.AddrFrom4([4]byte(request[address : address+4]))
			prefix, present := netip.PrefixFrom(found, found.BitLen()), true
			if masked {
				if prefix, present, err = mask(socket, label, found); err != nil {
					return nil, err
				}
			}
			if present {
				held = append(held, labeled{label: label, address: prefix})
			}
		}
		return held, nil
	}
	return nil, fmt.Errorf("%w: the interfaces hold more than %d IPv4 addresses", ErrUnreadable, mostEntries)
}

func mask(socket int, label string, found netip.Addr) (netip.Prefix, bool, error) {
	var request [requestSize]byte
	copy(request[:nameBytes-1], label)
	binary.NativeEndian.PutUint16(request[family:], syscall.AF_INET)
	copied := found.As4()
	copy(request[address:], copied[:])
	err := control(socket, syscall.SIOCGIFNETMASK, unsafe.Pointer(&request))
	switch {
	case errors.Is(err, syscall.EADDRNOTAVAIL), errors.Is(err, syscall.ENODEV):
		return netip.Prefix{}, false, nil
	case err != nil:
		return netip.Prefix{}, false, fmt.Errorf("%w: read the prefix of %s: %w", ErrUnreadable, found, err)
	}
	ones := bits.OnesCount32(binary.BigEndian.Uint32(request[address : address+4]))
	return netip.PrefixFrom(found, ones), true, nil
}

func control(socket int, request uint, argument unsafe.Pointer) error {
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(socket), uintptr(request), uintptr(argument)); errno != 0 {
		return errno
	}
	return nil
}
