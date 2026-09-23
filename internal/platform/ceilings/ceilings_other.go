//go:build !linux

package ceilings

import (
	"errors"
	"fmt"
)

func Enforced() (Ceilings, error) {
	return Ceilings{}, fmt.Errorf("read what the operating system enforces on the agent: %w", errors.ErrUnsupported)
}
