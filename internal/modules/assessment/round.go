package assessment

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/dynasmon/Seagull-agent-v2/internal/platform/accounts"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/dpkg"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/logindefs"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/services"
	"github.com/dynasmon/Seagull-agent-v2/internal/secrets"
	assessmentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/assessment/v1"
)

const listed = 8

type read[T any] struct {
	done  bool
	value T
	err   error
}

func (r *read[T]) get(reading func() (T, error)) (T, error) {
	if !r.done {
		r.value, r.err = reading()
		r.done = true
	}
	return r.value, r.err
}

// A round reads each source of the host once, when the first check needs it,
// so a checklist of many checks of one source costs one reading of it.
type round struct {
	ctx   context.Context
	host  Host
	asked []string

	accounts  read[accounts.Database]
	modules   read[Modules]
	modprobe  read[Modprobe]
	packages  read[[]dpkg.Package]
	units     read[map[string]services.Unit]
	sshd      read[Directives]
	loginDefs read[map[string]logindefs.Setting]
}

func newRound(ctx context.Context, host Host, checks []*assessmentv1.Check) *round {
	held := &round{ctx: ctx, host: host}
	for _, check := range checks {
		if unit := check.GetService().GetUnit(); unit != "" && unread(check) == nil && !slices.Contains(held.asked, unit) {
			held.asked = append(held.asked, unit)
		}
	}
	return held
}

func (r *round) unit(name string) (services.Unit, error) {
	shown, err := r.units.get(func() (map[string]services.Unit, error) {
		units, err := r.host.Units(r.ctx, r.asked)
		if err != nil {
			return nil, err
		}
		held := make(map[string]services.Unit, len(units))
		for _, unit := range units {
			held[unit.Asked] = unit
		}
		return held, nil
	})
	if err != nil {
		return services.Unit{}, err
	}
	unit, found := shown[name]
	if !found {
		return services.Unit{}, fmt.Errorf("systemd said nothing of %s", name)
	}
	return unit, nil
}

// told is what an error says, as an assessment may carry it: as it is when it
// is printable text, and quoted when it is not.
func told(err error) string {
	text := err.Error()
	if utf8.ValidString(text) && strings.IndexFunc(text, func(r rune) bool { return !unicode.IsPrint(r) }) < 0 {
		return text
	}
	return strconv.Quote(text)
}

// named lists what a host holds, each as a message may carry it, and says how
// many more there are past the first few.
func named(held []string) string {
	shown := make([]string, 0, min(len(held), listed))
	for _, name := range held[:min(len(held), listed)] {
		shown = append(shown, secrets.Bounded(name))
	}
	written := strings.Join(shown, ", ")
	if len(held) > listed {
		written += fmt.Sprintf(" and %d more", len(held)-listed)
	}
	return written
}
