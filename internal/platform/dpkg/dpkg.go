// Package dpkg reads what dpkg holds installed, through dpkg-query, in the
// format its manual documents: one line for each package its database knows,
// with the fields the query names. A package is on the host while dpkg keeps
// any of its files there, whether or not dpkg finished configuring it.
package dpkg

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/dynasmon/Seagull-agent-v2/internal/platform/command"
	"github.com/dynasmon/Seagull-agent-v2/internal/secrets"
)

const (
	MaxOutput = 32 << 20
	format    = "${Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\t${Installed-Size}\t${db:Status-Status}\n"
	fields    = 7
)

var program = "/usr/bin/dpkg-query"

var (
	ErrAbsent     = errors.New("this host has no dpkg")
	ErrUnreadable = errors.New("dpkg-query wrote what is not the list of packages dpkg holds")
)

var unpacked = map[string]bool{
	"installed":        true,
	"triggers-pending": true,
	"triggers-awaited": true,
	"half-configured":  true,
	"unpacked":         true,
	"half-installed":   true,
	"config-files":     false,
	"not-installed":    false,
}

type Package struct {
	Name          string
	Version       string
	Architecture  string
	Source        string
	SourceVersion string
	InstalledKiB  uint64
	Status        string
}

func Installed(ctx context.Context) ([]Package, error) {
	written, err := command.Output(ctx, program, []string{"--show", "--showformat=" + format}, MaxOutput)
	switch {
	case errors.Is(err, command.ErrAbsent):
		return nil, fmt.Errorf("%w: %w", ErrAbsent, err)
	case err != nil:
		return nil, fmt.Errorf("list the packages dpkg holds: %w", err)
	}
	return parse(written)
}

// Every line has to read as a package for the list to be the whole of what
// dpkg holds: a line that does not, or a state of a package that this agent
// does not know, refuses the list rather than leave a package out of it.
func parse(written []byte) ([]Package, error) {
	held := []Package{}
	switch {
	case len(written) == 0:
		return held, nil
	case written[len(written)-1] != '\n':
		return nil, fmt.Errorf("%w: its last line is cut short", ErrUnreadable)
	case bytes.IndexByte(written, 0) >= 0:
		return nil, fmt.Errorf("%w: it holds a NUL byte", ErrUnreadable)
	}
	for number, line := range strings.Split(string(written[:len(written)-1]), "\n") {
		parts := strings.Split(line, "\t")
		if len(parts) != fields || parts[0] == "" {
			return nil, fmt.Errorf("%w: line %d is %s", ErrUnreadable, number+1, secrets.Shown(line))
		}
		status := parts[6]
		present, known := unpacked[status]
		if !known {
			return nil, fmt.Errorf("%w: dpkg says %s is %s, a state this agent does not know", ErrUnreadable, secrets.Shown(parts[0]), secrets.Shown(status))
		}
		if !present {
			continue
		}
		var size uint64
		if parts[5] != "" {
			parsed, err := strconv.ParseUint(parts[5], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("%w: dpkg says %s takes %s KiB", ErrUnreadable, secrets.Shown(parts[0]), secrets.Shown(parts[5]))
			}
			size = parsed
		}
		held = append(held, Package{
			Name:          parts[0],
			Version:       parts[1],
			Architecture:  parts[2],
			Source:        parts[3],
			SourceVersion: parts[4],
			InstalledKiB:  size,
			Status:        status,
		})
	}
	return held, nil
}
