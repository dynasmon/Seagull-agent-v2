package update

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

const (
	generationFile     = "generation"
	maxGenerationBytes = 32
)

// The generation of the local state is the newest one a release that ran on it
// kept it at, so an older release written down after a newer one never lowers
// it.
func KeepGeneration(root *os.Root) error {
	held, err := ReadGeneration(root)
	if err != nil || held >= StateGeneration {
		return err
	}
	return keep(root, generationFile, []byte(strconv.FormatUint(StateGeneration, 10)+"\n"))
}

func ReadGeneration(root *os.Root) (uint32, error) {
	content, found, err := read(root, generationFile, maxGenerationBytes)
	if err != nil || !found {
		return 1, err
	}
	parsed, err := strconv.ParseUint(strings.TrimSpace(string(content)), 10, 32)
	if err != nil || parsed == 0 {
		return 0, fmt.Errorf("%w: the generation of the state reads %q", ErrDamaged, strings.TrimSpace(string(content)))
	}
	return uint32(parsed), nil
}
