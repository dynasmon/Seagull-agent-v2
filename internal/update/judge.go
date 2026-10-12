package update

import (
	"fmt"
	"slices"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/secrets"
	updatev1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/update/v1"
)

// What the agent runs and keeps, which decides what it may install.
type Running struct {
	Version      Version
	OS           string
	Architecture string
	Format       updatev1.Format
	State        uint32
}

// What was verified before, which nothing handed over later may go below.
type Held struct {
	Root    *Root
	Catalog uint64
}

type Judgment struct {
	Root    *Root
	Catalog *Catalog
	Version string
	Target  *updatev1.Release
	Current *updatev1.Release
}

func (j Judgment) Held() Held {
	held := Held{Root: j.Root}
	if j.Catalog != nil {
		held.Catalog = j.Catalog.Version()
	}
	return held
}

// Judge finds the release an offer asks the agent to run and whether it may
// install it. A judgment with no target asks nothing of the agent. Whatever it
// verified on the way is in the judgment even when it refuses, so the newest
// root and catalog are kept either way.
func Judge(offer *updatev1.Offer, held Held, running Running, now time.Time) (Judgment, error) {
	judged := Judgment{Root: held.Root.Walk(offer.GetRoots(), now), Version: offer.GetVersion()}
	if offer.GetCatalog() == nil {
		if judged.Version != "" {
			return judged, fmt.Errorf("%w: the platform asks for %s and hands over no catalog naming it", ErrMalformed, secrets.Shown(judged.Version))
		}
		return judged, nil
	}
	if judged.Root.Expired(now) {
		return judged, fmt.Errorf("%w: root %d ran out at %s, and nothing is installed until a newer root is handed over",
			ErrExpired, judged.Root.Version(), judged.Root.ExpiresAt().Format(time.RFC3339))
	}
	catalog, err := judged.Root.Catalog(offer.GetCatalog(), now)
	if err != nil {
		return judged, err
	}
	switch {
	case catalog.Version() < held.Catalog:
		return judged, fmt.Errorf("%w: it is catalog %d, and catalog %d was verified before", ErrStale, catalog.Version(), held.Catalog)
	case catalog.Expired(now):
		return judged, fmt.Errorf("%w: catalog %d ran out at %s", ErrExpired, catalog.Version(), catalog.ExpiresAt().Format(time.RFC3339))
	}
	judged.Catalog = catalog
	if judged.Version == "" || judged.Version == running.Version.String() {
		return judged, nil
	}

	platform := running.OS + "/" + running.Architecture + " " + running.Format.String()
	target := catalog.Release(judged.Version, running.OS, running.Architecture, running.Format)
	if target == nil {
		return judged, fmt.Errorf("%w: catalog %d names no release %s for %s", ErrRefused, catalog.Version(), secrets.Shown(judged.Version), platform)
	}
	version, _ := ParseVersion(target.GetVersion())
	order := version.Compare(running.Version)
	switch {
	case order == 0:
		return judged, nil
	case order < 0 && !slices.Contains(target.GetReplaces(), running.Version.String()):
		return judged, fmt.Errorf("%w: %s is older than %s, which it does not replace", ErrRefused, version, running.Version)
	}
	if minimum := target.GetCompatibility().GetMinimumVersion(); order > 0 && minimum != "" {
		if oldest, _ := ParseVersion(minimum); running.Version.Compare(oldest) < 0 {
			return judged, fmt.Errorf("%w: %s is installed only over %s or later, and this agent runs %s", ErrRefused, version, minimum, running.Version)
		}
	}
	if kept := target.GetCompatibility().GetStateGeneration(); kept < running.State {
		return judged, fmt.Errorf("%w: %s keeps state of generation %d, and the state of this agent is of generation %d", ErrRefused, version, kept, running.State)
	}
	current := catalog.Release(running.Version.String(), running.OS, running.Architecture, running.Format)
	if current == nil {
		return judged, fmt.Errorf("%w: catalog %d does not name %s, the release this agent runs, so there would be nothing to go back to", ErrRefused, catalog.Version(), running.Version)
	}
	judged.Target, judged.Current = target, current
	return judged, nil
}
