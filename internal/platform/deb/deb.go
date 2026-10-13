// Package deb is the agent's own package on a host whose package manager is
// dpkg: the Debian version a release of the agent is packaged as, what a package
// file says of itself, and installing one through apt-get, with the arguments
// and the environment the agent fixes and through no shell.
package deb

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/dynasmon/Seagull-agent-v2/internal/platform/command"
	"github.com/dynasmon/Seagull-agent-v2/internal/secrets"
)

const (
	Package   = "seagull-agent"
	revision  = "1"
	maxFields = 4 << 10
	maxOutput = 1 << 20
)

var (
	inspector = "/usr/bin/dpkg-deb"
	installer = "/usr/bin/apt-get"
)

var environment = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "DEBIAN_FRONTEND=noninteractive", "LC_ALL=C"}

var semantic = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$`)

var architectures = map[string]string{"amd64": "amd64", "arm64": "arm64"}

var ErrUnreadable = errors.New("dpkg-deb wrote what is not the fields of a package")

// Version is the Debian version an agent built as stamped is packaged as: its
// release, with a prerelease after a tilde so dpkg orders it before the release
// itself, and one packaging revision.
func Version(stamped string) (string, error) {
	parts := semantic.FindStringSubmatch(stamped)
	if parts == nil {
		return "", fmt.Errorf("it was built as %s, which names no release or commit of the agent", secrets.Shown(stamped))
	}
	upstream := strings.Join(parts[1:4], ".")
	if parts[4] != "" {
		upstream += "~" + strings.ReplaceAll(parts[4], "-", ".")
	}
	return upstream + "-" + revision, nil
}

func Architecture(goarch string) (string, bool) {
	named, known := architectures[goarch]
	return named, known
}

type Fields struct {
	Package      string
	Version      string
	Architecture string
}

func Inspect(ctx context.Context, path string) (Fields, error) {
	if !filepath.IsAbs(path) {
		return Fields{}, fmt.Errorf("inspect %s: a package is named by its absolute path", secrets.Shown(path))
	}
	written, err := command.OutputIn(ctx, inspector, []string{"--field", path, "Package", "Version", "Architecture"}, environment, maxFields)
	if err != nil {
		return Fields{}, err
	}
	var fields Fields
	for line := range strings.SplitSeq(string(bytes.TrimSpace(written)), "\n") {
		name, value, found := strings.Cut(line, ": ")
		if !found {
			return Fields{}, fmt.Errorf("%w: %s", ErrUnreadable, secrets.Shown(line))
		}
		switch name {
		case "Package":
			fields.Package = value
		case "Version":
			fields.Version = value
		case "Architecture":
			fields.Architecture = value
		default:
			return Fields{}, fmt.Errorf("%w: %s", ErrUnreadable, secrets.Shown(line))
		}
	}
	if fields.Package == "" || fields.Version == "" || fields.Architecture == "" {
		return Fields{}, fmt.Errorf("%w: it names no package, version or architecture", ErrUnreadable)
	}
	return fields, nil
}

// Install leaves dpkg the files the host changed in place, and installs an
// older version only when it is told to.
func Install(ctx context.Context, path string, downgrade bool) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("install %s: a package is named by its absolute path", secrets.Shown(path))
	}
	arguments := []string{"install", "--yes", "--no-install-recommends",
		"-o", "DPkg::Lock::Timeout=300", "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold"}
	if downgrade {
		arguments = append(arguments, "--allow-downgrades")
	}
	_, err := command.OutputIn(ctx, installer, append(arguments, path), environment, maxOutput)
	return err
}
