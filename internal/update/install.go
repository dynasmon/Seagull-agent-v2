package update

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-agent-v2/internal/secrets"
	updatev1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/update/v1"
)

// What the host's package manager makes of the agent's package: whether a file
// is the release it is said to be, and installing it.
type Packages interface {
	Matches(ctx context.Context, path string, release *updatev1.Release) error
	Install(ctx context.Context, path string, downgrade bool) error
}

// Whether the agent runs as it should as release version, by what a run
// started after since says of itself.
type Health func(ctx context.Context, version Version, since time.Time) error

type InstallerOptions struct {
	Staging    *Staging
	Directory  *os.Root
	Anchor     *Root
	Running    Running
	Generation func() uint32
	Packages   Packages
	Health     Health
	Logger     *slog.Logger
	Now        func() time.Time
}

type Installer struct {
	options InstallerOptions
	store   *Store
}

func NewInstaller(options InstallerOptions) (*Installer, error) {
	if options.Staging == nil || options.Directory == nil || options.Anchor == nil || options.Generation == nil ||
		options.Packages == nil || options.Health == nil || options.Logger == nil {
		return nil, errors.New("install updates: a staging area, a directory of its own, the provisioned root, the generation of the state, a package manager, a health check and a logger are all needed")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	store, err := OpenStore(options.Directory)
	if err != nil {
		return nil, err
	}
	return &Installer{options: options, store: store}, nil
}

// Run takes an installation a crash interrupted to its end, or else the release
// the agent staged. How it ended is in the journal; an error is one the
// installer could not record.
func (i *Installer) Run(ctx context.Context) error {
	journal, found, err := ReadJournal(i.options.Directory)
	if err != nil {
		return err
	}
	if found && !journal.Done() {
		i.options.Logger.Info("update_install_resumed", slog.String("stage", string(journal.Stage)), slog.String("version", journal.Version))
		return i.resume(ctx, journal)
	}
	if !i.options.Staging.Ready() {
		return nil
	}
	return i.take(ctx)
}

func (i *Installer) take(ctx context.Context) error {
	now := i.options.Now()
	offered, err := i.options.Staging.Offer()
	var offer updatev1.Offer
	if err == nil {
		err = proto.Unmarshal(offered, &offer)
	}
	if err != nil {
		return errors.Join(fmt.Errorf("read what the agent staged: %w", err), i.options.Staging.Clear())
	}
	journal := Journal{Version: offer.GetVersion(), Previous: i.options.Running.Version.String(), Started: now, Since: now}
	held, err := i.store.Held(i.options.Anchor, now)
	if err != nil {
		return i.ended(journal, Refused, fmt.Sprintf("what the installer verified before cannot be read back, so it installs nothing: %v", err))
	}
	judged, err := Judge(&offer, held, i.options.Running, now)
	if progressed := judged.Held(); progressed.Root.Version() > held.Root.Version() || progressed.Catalog > held.Catalog {
		if kept := i.store.Keep(progressed); kept != nil {
			return errors.Join(kept, i.options.Staging.Clear())
		}
	}
	journal.Root = judged.Root.Version()
	if judged.Catalog != nil {
		journal.Catalog = judged.Catalog.Version()
	}
	switch {
	case err != nil:
		return i.ended(journal, failureOf(err), err.Error())
	case judged.Target == nil:
		return i.options.Staging.Clear()
	}

	for _, release := range []*updatev1.Release{judged.Target, judged.Current} {
		if err := i.options.Staging.Take(release, i.options.Directory); err != nil {
			return i.ended(journal, Unverified, err.Error())
		}
	}
	if err := i.options.Staging.Clear(); err != nil {
		return err
	}
	journal.Target, journal.Fallback = PackageName(judged.Target.GetPayload().GetSha256()), PackageName(judged.Current.GetPayload().GetSha256())
	journal.PreviousState = judged.Current.GetCompatibility().GetStateGeneration()
	for _, named := range []struct {
		file    string
		release *updatev1.Release
	}{{journal.Target, judged.Target}, {journal.Fallback, judged.Current}} {
		if err := i.options.Packages.Matches(ctx, i.path(named.file), named.release); err != nil {
			return i.ended(journal, Unverified, err.Error())
		}
	}
	journal.Stage = Installing
	if err := i.kept(journal); err != nil {
		return err
	}
	return i.install(ctx, journal)
}

func (i *Installer) resume(ctx context.Context, journal Journal) error {
	switch journal.Stage {
	case Installing:
		return i.install(ctx, journal)
	case Checking:
		return i.check(ctx, journal)
	case Reverting:
		return i.revert(ctx, journal, journal.Failure, journal.Reason)
	}
	return i.ended(journal, Installation, fmt.Sprintf("the installer's journal stood at %s, which it never writes", secrets.Shown(string(journal.Stage))))
}

func (i *Installer) install(ctx context.Context, journal Journal) error {
	i.options.Logger.Info("update_installing", slog.String("version", journal.Version), slog.String("previous", journal.Previous))
	if err := i.options.Packages.Install(ctx, i.path(journal.Target), older(journal.Version, journal.Previous)); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return i.revert(ctx, journal, Installation, "the package manager did not install it: "+err.Error())
	}
	journal.Stage, journal.Since = Checking, i.options.Now()
	if err := i.kept(journal); err != nil {
		return err
	}
	return i.check(ctx, journal)
}

func (i *Installer) check(ctx context.Context, journal Journal) error {
	version, _ := ParseVersion(journal.Version)
	if err := i.options.Health(ctx, version, journal.Started); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return i.revert(ctx, journal, Unhealthy, err.Error())
	}
	journal.Stage, journal.Since, journal.Failure, journal.Reason = Installed, i.options.Now(), "", ""
	if err := i.kept(journal); err != nil {
		return err
	}
	i.options.Logger.Info("update_installed", slog.String("version", journal.Version), slog.String("previous", journal.Previous))
	return i.pruned(journal)
}

// Going back is refused once the state was moved past the generation the
// release before reads, since that release would run on state it cannot read.
func (i *Installer) revert(ctx context.Context, journal Journal, failure Failure, reason string) error {
	journal.Failure, journal.Reason = failure, explained(reason)
	if generation := i.options.Generation(); journal.PreviousState < generation {
		return i.ended(journal, failure, fmt.Sprintf("%s; going back to %s is refused, as it keeps state of generation %d and the state is now of generation %d",
			reason, journal.Previous, journal.PreviousState, generation))
	}
	if journal.Stage != Reverting {
		journal.Stage, journal.Since = Reverting, i.options.Now()
		if err := i.kept(journal); err != nil {
			return err
		}
	}
	i.options.Logger.Warn("update_reverting", slog.String("version", journal.Version), slog.String("previous", journal.Previous),
		slog.String("failure", string(failure)), slog.String("reason", journal.Reason))
	if err := i.options.Packages.Install(ctx, i.path(journal.Fallback), older(journal.Previous, journal.Version)); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return i.ended(journal, failure, fmt.Sprintf("%s; and going back to %s failed too: %v", reason, journal.Previous, err))
	}
	previous, _ := ParseVersion(journal.Previous)
	if err := i.options.Health(ctx, previous, journal.Since); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return i.ended(journal, failure, fmt.Sprintf("%s; and %s, installed again, did not run as it should either: %v", reason, journal.Previous, err))
	}
	journal.Stage, journal.Since = RolledBack, i.options.Now()
	if err := i.kept(journal); err != nil {
		return err
	}
	i.options.Logger.Warn("update_rolled_back", slog.String("version", journal.Version), slog.String("previous", journal.Previous),
		slog.String("failure", string(failure)), slog.String("reason", journal.Reason))
	return i.pruned(journal)
}

func (i *Installer) ended(journal Journal, failure Failure, reason string) error {
	journal.Stage, journal.Since, journal.Failure, journal.Reason = Failed, i.options.Now(), failure, explained(reason)
	i.options.Logger.Warn("update_failed", slog.String("version", journal.Version), slog.String("failure", string(failure)), slog.String("reason", journal.Reason))
	return errors.Join(i.options.Staging.Clear(), i.kept(journal), i.pruned(journal))
}

func (i *Installer) kept(journal Journal) error {
	journal.Reason = explained(journal.Reason)
	return KeepJournal(i.options.Directory, journal)
}

func (i *Installer) pruned(journal Journal) error {
	var found []error
	for _, name := range []string{journal.Target, journal.Fallback} {
		if name == "" || !strings.HasSuffix(name, packageSuffix) {
			continue
		}
		if _, err := hex.DecodeString(strings.TrimSuffix(name, packageSuffix)); err != nil {
			continue
		}
		if err := i.options.Directory.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
			found = append(found, err)
		}
	}
	return errors.Join(found...)
}

func (i *Installer) path(name string) string { return filepath.Join(i.options.Directory.Name(), name) }

func older(version, than string) bool {
	left, valid := ParseVersion(version)
	right, also := ParseVersion(than)
	return valid && also && left.Compare(right) < 0
}
