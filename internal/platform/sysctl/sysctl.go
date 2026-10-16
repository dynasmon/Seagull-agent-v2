// Package sysctl reads the parameters of the running kernel as /proc/sys holds
// them: the values in force, which may differ from what the host is configured
// to set at boot, named as sysctl(8) names them.
package sysctl

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/dynasmon/Seagull-agent-v2/internal/platform/files"
	"github.com/dynasmon/Seagull-agent-v2/internal/secrets"
)

const (
	MaxBytes = 4 << 10
	maxName  = 255
)

var root = "/proc/sys"

var named = regexp.MustCompile(`^[A-Za-z0-9_-]+(/[A-Za-z0-9_-]+)*(\.[A-Za-z0-9_-]+(/[A-Za-z0-9_-]+)*)*$`)

var (
	ErrAbsent    = errors.New("the kernel has no such parameter")
	ErrDenied    = errors.New("the agent's account may not read the parameter")
	ErrMalformed = errors.New("the parameter is not named as sysctl names one")
)

// Path is where /proc/sys holds the parameter: its components separated by
// dots, a slash within a component standing for a dot, as in an interface
// named eth0.100. A name that would resolve to anything else is refused.
func Path(name string) (string, error) {
	if len(name) > maxName || !named.MatchString(name) {
		return "", fmt.Errorf("%w: %s", ErrMalformed, secrets.Shown(name))
	}
	components := strings.Split(name, ".")
	for index, component := range components {
		components[index] = strings.ReplaceAll(component, "/", ".")
	}
	return filepath.Join(append([]string{root}, components...)...), nil
}

// Read returns what the kernel holds for the parameter, every run of white
// space in it made one space.
func Read(name string) (string, error) {
	path, err := Path(name)
	if err != nil {
		return "", err
	}
	content, err := files.Read(path, MaxBytes)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "", fmt.Errorf("%w: %s", ErrAbsent, name)
	case errors.Is(err, fs.ErrPermission):
		return "", fmt.Errorf("%w: %s", ErrDenied, name)
	case err != nil:
		return "", fmt.Errorf("read %s: %w", name, err)
	}
	return strings.Join(strings.Fields(string(content)), " "), nil
}
