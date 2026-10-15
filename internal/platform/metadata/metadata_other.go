//go:build !linux && !darwin

package metadata

import (
	"errors"
	"fmt"
)

func Describe(path string) (Node, error) {
	return Node{}, fmt.Errorf("describe %s: %w", path, errors.ErrUnsupported)
}
