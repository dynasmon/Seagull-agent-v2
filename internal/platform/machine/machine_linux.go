//go:build linux

package machine

import (
	"fmt"
	"syscall"
)

func Running() (Kernel, error) {
	var named syscall.Utsname
	if err := syscall.Uname(&named); err != nil {
		return Kernel{}, fmt.Errorf("%w: uname: %w", ErrUnreadable, err)
	}
	return Kernel{Name: text(named.Sysname[:]), Release: text(named.Release[:]), Version: text(named.Version[:]), Machine: text(named.Machine[:])}, nil
}

func text[T int8 | uint8](field []T) string {
	held := make([]byte, 0, len(field))
	for _, character := range field {
		if character == 0 {
			break
		}
		held = append(held, byte(character))
	}
	return string(held)
}
