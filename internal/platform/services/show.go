package services

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/dynasmon/Seagull-agent-v2/internal/platform/command"
	"github.com/dynasmon/Seagull-agent-v2/internal/secrets"
)

const (
	MaxShownUnits = 64
	maxShown      = 1 << 20
)

// A Unit as systemd holds it when asked for it by name: the name it knows it
// by, which an alias does not have, how it loaded, whether it runs and the
// state of its unit file, empty when it has none.
type Unit struct {
	Asked  string
	ID     string
	Load   string
	Active string
	File   string
}

// Show asks systemd for each unit named, at most MaxShownUnits at a time, and
// returns what it says of them in the order they were named. A unit the host
// does not have is loaded as not-found.
func Show(ctx context.Context, units []string) ([]Unit, error) {
	if _, err := os.Stat(booted); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s is not there", ErrAbsent, booted)
		}
		return nil, fmt.Errorf("find whether systemd manages this host: %w", err)
	}
	var shown []Unit
	for start := 0; start < len(units); start += MaxShownUnits {
		asked := units[start:min(start+MaxShownUnits, len(units))]
		for _, name := range asked {
			if !unit(name) {
				return nil, fmt.Errorf("show %s: it is not the name of a unit", secrets.Shown(name))
			}
		}
		arguments := append([]string{"show", "--no-pager", "--property=Id,LoadState,ActiveState,UnitFileState", "--"}, asked...)
		written, err := command.Output(ctx, program, arguments, maxShown)
		var failed *command.Failure
		switch {
		case errors.Is(err, command.ErrAbsent):
			return nil, fmt.Errorf("%w: %w", ErrAbsent, err)
		case errors.As(err, &failed) && strings.Contains(failed.Said, unreached):
			return nil, fmt.Errorf("%w: %w", ErrDenied, err)
		case err != nil:
			return nil, fmt.Errorf("show the units systemd holds: %w", err)
		}
		blocks := strings.Split(strings.TrimSpace(string(written)), "\n\n")
		if len(blocks) != len(asked) {
			return nil, fmt.Errorf("%w: it said %d things of %d units", ErrUnreadable, len(blocks), len(asked))
		}
		for index, block := range blocks {
			held := Unit{Asked: asked[index]}
			for line := range strings.SplitSeq(block, "\n") {
				key, value, _ := strings.Cut(line, "=")
				switch key {
				case "Id":
					held.ID = value
				case "LoadState":
					held.Load = value
				case "ActiveState":
					held.Active = value
				case "UnitFileState":
					held.File = value
				}
			}
			if held.ID == "" || held.Load == "" || held.Active == "" {
				return nil, fmt.Errorf("%w: what it said of %s is %s", ErrUnreadable, secrets.Shown(asked[index]), secrets.Shown(block))
			}
			shown = append(shown, held)
		}
	}
	return shown, nil
}

func unit(name string) bool {
	if len(name) == 0 || len(name) > 255 || strings.HasPrefix(name, "-") {
		return false
	}
	return strings.IndexFunc(name, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune(":_.\\@-", r))
	}) < 0 && strings.Contains(name, ".")
}
