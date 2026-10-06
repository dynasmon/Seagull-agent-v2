// Package services reads the services systemd manages, through systemctl, as
// the JSON it writes of the service units it holds loaded and of the unit files
// it has. systemctl reaches systemd over the system bus, a local socket, so the
// account it runs as needs the local sockets that bus listens on.
package services

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/dynasmon/Seagull-agent-v2/internal/platform/command"
	"github.com/dynasmon/Seagull-agent-v2/internal/secrets"
)

const (
	MaxOutput  = 16 << 20
	suffix     = ".service"
	unreached  = "Failed to connect to"
	notFound   = "not-found"
	inactive   = "inactive"
	dead       = "dead"
	aliased    = "alias"
	instanceOf = "@" + suffix
)

var (
	program = "/usr/bin/systemctl"
	booted  = "/run/systemd/system"
)

var (
	ErrAbsent     = errors.New("systemd does not manage this host")
	ErrDenied     = errors.New("systemctl cannot reach systemd from where the agent runs")
	ErrUnreadable = errors.New("systemctl wrote what is not a list of services")
)

// A Service in systemd's own words: how its unit loaded, its active and sub
// state, and the state of its unit file, empty when it has none.
type Service struct {
	Name        string
	Description string
	Load        string
	Active      string
	Sub         string
	File        string
}

type loaded struct {
	Unit        string `json:"unit"`
	Load        string `json:"load"`
	Active      string `json:"active"`
	Sub         string `json:"sub"`
	Description string `json:"description"`
}

type unitFile struct {
	Name  string `json:"unit_file"`
	State string `json:"state"`
}

// List returns every service of the host: each unit systemd holds loaded, and
// each unit file it holds none of, which is a service that is not running.
// A template is not a service until it is instantiated, an alias is another
// name of a service listed under its own, and a unit systemd was asked for and
// found no file of is not on the host unless it still runs.
func List(ctx context.Context) ([]Service, error) {
	if _, err := os.Stat(booted); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s is not there", ErrAbsent, booted)
		}
		return nil, fmt.Errorf("find whether systemd manages this host: %w", err)
	}
	var units []loaded
	if err := run(ctx, &units, "list-units", "--all"); err != nil {
		return nil, err
	}
	var files []unitFile
	if err := run(ctx, &files, "list-unit-files"); err != nil {
		return nil, err
	}
	return merge(units, files)
}

func run(ctx context.Context, into any, verb string, flags ...string) error {
	arguments := append([]string{verb, "--type=service", "--output=json", "--no-pager"}, flags...)
	written, err := command.Output(ctx, program, arguments, MaxOutput)
	var failed *command.Failure
	switch {
	case errors.Is(err, command.ErrAbsent):
		return fmt.Errorf("%w: %w", ErrAbsent, err)
	case errors.As(err, &failed) && strings.Contains(failed.Said, unreached):
		return fmt.Errorf("%w: %w", ErrDenied, err)
	case err != nil:
		return fmt.Errorf("list the services systemd manages: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(written))
	if err := decoder.Decode(into); err != nil {
		return fmt.Errorf("%w: %s %s", ErrUnreadable, verb, secrets.Bounded(err.Error()))
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: %s wrote more than one list", ErrUnreadable, verb)
	}
	return nil
}

func merge(units []loaded, files []unitFile) ([]Service, error) {
	states := make(map[string]string, len(files))
	for _, file := range files {
		if !named(file.Name) || file.State == "" {
			return nil, fmt.Errorf("%w: a unit file is listed as %s, %s", ErrUnreadable, secrets.Shown(file.Name), secrets.Shown(file.State))
		}
		states[file.Name] = file.State
	}
	held := make(map[string]Service, len(units)+len(files))
	for _, unit := range units {
		switch {
		case !named(unit.Unit) || unit.Load == "" || unit.Active == "":
			return nil, fmt.Errorf("%w: a unit is listed as %s, loaded %s and %s", ErrUnreadable, secrets.Shown(unit.Unit), secrets.Shown(unit.Load), secrets.Shown(unit.Active))
		case held[unit.Unit].Name != "":
			return nil, fmt.Errorf("%w: %s is listed twice", ErrUnreadable, secrets.Shown(unit.Unit))
		case strings.HasSuffix(unit.Unit, instanceOf), unit.Load == notFound && unit.Active == inactive:
			continue
		}
		held[unit.Unit] = Service{Name: unit.Unit, Description: unit.Description, Load: unit.Load, Active: unit.Active, Sub: unit.Sub, File: states[unit.Unit]}
	}
	for name, state := range states {
		if state == aliased || strings.HasSuffix(name, instanceOf) || held[name].Name != "" {
			continue
		}
		held[name] = Service{Name: name, Active: inactive, Sub: dead, File: state}
	}
	listed := make([]Service, 0, len(held))
	for _, name := range slices.Sorted(maps.Keys(held)) {
		listed = append(listed, held[name])
	}
	return listed, nil
}

func named(name string) bool {
	return len(name) > len(suffix) && strings.HasSuffix(name, suffix) && utf8.ValidString(name) && !strings.ContainsAny(name, "/\x00\n")
}
