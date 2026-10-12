package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-agent-v2/internal/config"
	"github.com/dynasmon/Seagull-agent-v2/internal/identity"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/deb"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/files"
	"github.com/dynasmon/Seagull-agent-v2/internal/protocol"
	"github.com/dynasmon/Seagull-agent-v2/internal/status"
	"github.com/dynasmon/Seagull-agent-v2/internal/update"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
	updatev1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/update/v1"
)

const (
	updateDirectory = "update"
	stagedDirectory = "staged"
	healthPoll      = 2 * time.Second
)

var (
	installerDirectory = "/var/lib/seagull-agent-update"
	healthWithin       = 4 * time.Minute
	healthSettle       = statusEvery
)

var stages = map[update.Stage]agentv1.Status_Update_Stage{
	update.Downloading: agentv1.Status_Update_STAGE_DOWNLOADING,
	update.Staged:      agentv1.Status_Update_STAGE_STAGED,
	update.Installing:  agentv1.Status_Update_STAGE_INSTALLING,
	update.Checking:    agentv1.Status_Update_STAGE_CHECKING,
	update.Reverting:   agentv1.Status_Update_STAGE_INSTALLING,
	update.Installed:   agentv1.Status_Update_STAGE_INSTALLED,
	update.RolledBack:  agentv1.Status_Update_STAGE_ROLLED_BACK,
	update.Failed:      agentv1.Status_Update_STAGE_FAILED,
}

var failures = map[update.Failure]agentv1.Status_Update_Failure{
	update.Unreachable:  agentv1.Status_Update_FAILURE_UNREACHABLE,
	update.Unverified:   agentv1.Status_Update_FAILURE_UNVERIFIED,
	update.Refused:      agentv1.Status_Update_FAILURE_REFUSED,
	update.Installation: agentv1.Status_Update_FAILURE_INSTALLATION,
	update.Unhealthy:    agentv1.Status_Update_FAILURE_UNHEALTHY,
}

// The release this binary is, as Go stamped it, on the platform it was built
// for, installed as this host installs packages.
func runningRelease() (update.Running, error) {
	info, read := debug.ReadBuildInfo()
	if !read {
		return update.Running{}, errors.New("this build records no version, so it takes no update")
	}
	version, valid := update.ParseVersion(info.Main.Version)
	if !valid {
		return update.Running{}, fmt.Errorf("this build is %q, which names no release, so it takes no update", info.Main.Version)
	}
	format := updatev1.Format_FORMAT_UNSPECIFIED
	if runtime.GOOS == "linux" {
		format = updatev1.Format_FORMAT_DEB
	}
	return update.Running{Version: version, OS: runtime.GOOS, Architecture: runtime.GOARCH, Format: format, State: update.StateGeneration}, nil
}

func followUpdates(installation *identity.Installation, settings config.Config, client update.Client, every func() time.Duration,
	logger *slog.Logger, recovery func(error) string) (*update.Follower, error) {
	provisioned, err := settings.Updates.Anchor()
	if err != nil {
		return nil, err
	}
	anchor, err := update.Anchor(provisioned, time.Now())
	if err != nil {
		return nil, fmt.Errorf("updates.root names %s: %w", settings.Updates.Root, err)
	}
	running, err := runningRelease()
	if err != nil {
		return nil, err
	}
	kept, err := installation.Directory(updateDirectory)
	if err != nil {
		return nil, err
	}
	if err := update.KeepGeneration(kept); err != nil {
		return nil, err
	}
	store, err := update.OpenStore(kept)
	if err != nil {
		return nil, err
	}
	staged, err := installation.Directory(stagedDirectory)
	if err != nil {
		return nil, err
	}
	return update.NewFollower(update.Options{
		Client:   client,
		URL:      settings.Server.RenewalURL,
		Anchor:   anchor,
		Store:    store,
		Staging:  update.OpenStaging(staged),
		Journal:  installerJournal,
		Running:  running,
		Every:    every,
		Logger:   logger,
		Recovery: recovery,
	})
}

func installerJournal() (update.Journal, bool, error) {
	held, err := os.OpenRoot(installerDirectory)
	if errors.Is(err, fs.ErrNotExist) {
		return update.Journal{}, false, nil
	}
	if err != nil {
		return update.Journal{}, false, err
	}
	defer held.Close()
	return update.ReadJournal(held)
}

func (o *observing) updated() status.Component {
	if o.updater == nil {
		return status.Component{Name: "update", State: status.Disabled,
			Reason: "updates.enabled is false or the installation is not enrolled, so the agent installs no release the platform hands it"}
	}
	held := o.updater.State()
	switch {
	case held.Stage == "":
		return status.Component{Name: "update", State: status.Running}
	case held.Failure == "":
		return status.Component{Name: "update", State: status.Running, Since: held.Since.UTC(),
			Reason: status.Text(fmt.Sprintf("%s: %s", held.Version, held.Stage))}
	}
	return status.Component{Name: "update", State: status.Degraded, Since: held.Since.UTC(),
		Reason: status.Text(fmt.Sprintf("%s: %s, %s: %s", held.Version, held.Stage, held.Failure, held.Reason))}
}

func (o *observing) updateReport() *agentv1.Status_Update {
	if o.updater == nil {
		return nil
	}
	held := o.updater.State()
	stage, known := stages[held.Stage]
	if !known {
		return nil
	}
	reported := &agentv1.Status_Update{
		Stage:          stage,
		Version:        protocol.Cut(held.Version, protocol.MaxStatusVersion),
		CatalogVersion: held.Catalog,
		RootVersion:    held.Root,
		Since:          timestamppb.New(held.Since),
		Failure:        failures[held.Failure],
		Reason:         protocol.Cut(held.Reason, protocol.MaxStatusText),
	}
	if reported.GetVersion() == "" {
		reported.Version = "(none)"
	}
	if held.Since.IsZero() {
		reported.Since = timestamppb.Now()
	}
	return reported
}

// The installer runs as root from a service of its own, started when the agent
// stages a release or when an installation was left pending, and it trusts
// nothing the agent's account wrote but what it verifies again.
func installRelease(ctx context.Context, path string, stderr io.Writer) int {
	logger := slog.New(slog.NewJSONHandler(stderr, nil))
	refused := func(err error) int {
		logger.Error("update_not_installed", slog.Any("error", err))
		return 1
	}
	if os.Geteuid() != 0 {
		return refused(errors.New("the installer installs packages, which only root does, and runs as root from seagull-agent-update.service"))
	}
	settings, err := config.Load(path)
	if err != nil {
		return refused(err)
	}
	if !settings.Updates.Enabled {
		logger.Info("update_not_enabled", slog.String("config", path))
		return 0
	}
	provisioned, err := settings.Updates.Anchor()
	if err != nil {
		return refused(err)
	}
	anchor, err := update.Anchor(provisioned, time.Now())
	if err != nil {
		return refused(err)
	}
	running, err := runningRelease()
	if err != nil {
		return refused(err)
	}
	state := settings.Identity.StateDirectory
	owner, err := ownerOf(state)
	if err != nil {
		return refused(err)
	}
	generation := func() uint32 {
		held, err := opened(filepath.Join(state, updateDirectory))
		if err != nil || held == nil {
			return 1
		}
		defer held.Close()
		read, err := update.ReadGeneration(held)
		if err != nil {
			return update.StateGeneration
		}
		return read
	}
	running.State = generation()
	directory, err := os.OpenRoot(installerDirectory)
	if err != nil {
		return refused(err)
	}
	defer directory.Close()
	options := update.InstallerOptions{
		Directory:  directory,
		Anchor:     anchor,
		Running:    running,
		Generation: generation,
		Packages:   debianPackages{},
		Health:     healthy(filepath.Join(state, statusDirectory), owner),
		Logger:     logger,
	}
	staged, err := opened(filepath.Join(state, stagedDirectory))
	if err != nil {
		return refused(err)
	}
	if staged != nil {
		defer staged.Close()
		options.Staging = update.OpenStaging(staged)
	}
	installer, err := update.NewInstaller(options)
	if err != nil {
		return refused(err)
	}
	if err := installer.Run(ctx); err != nil {
		return refused(err)
	}
	return 0
}

func opened(path string) (*os.Root, error) {
	held, err := os.OpenRoot(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return held, err
}

func ownerOf(state string) (int, error) {
	described, err := os.Lstat(state)
	if err != nil {
		return 0, fmt.Errorf("inspect the installation in %s: %w", state, err)
	}
	owner, err := files.Owner(described)
	if err != nil {
		return 0, fmt.Errorf("the installation in %s %w", state, err)
	}
	return owner, nil
}

type debianPackages struct{}

func (debianPackages) Matches(ctx context.Context, path string, release *updatev1.Release) error {
	fields, err := deb.Inspect(ctx, path)
	if err != nil {
		return err
	}
	version, err := deb.Version(release.GetVersion())
	if err != nil {
		return err
	}
	architecture, known := deb.Architecture(release.GetPlatform().GetArchitecture())
	switch {
	case !known:
		return fmt.Errorf("release %s is for %s, which this host packages nothing for", release.GetVersion(), release.GetPlatform().GetArchitecture())
	case fields.Package != deb.Package || fields.Version != version || fields.Architecture != architecture:
		return fmt.Errorf("the package is %s %s for %s, and release %s is %s %s for %s",
			fields.Package, fields.Version, fields.Architecture, release.GetVersion(), deb.Package, version, architecture)
	}
	return nil
}

func (debianPackages) Install(ctx context.Context, path string, downgrade bool) error {
	return deb.Install(ctx, path, downgrade)
}

// A release runs as it should once a run of it that began after it was
// installed has said so for a whole status interval, recently, with nothing
// the agent holds on the host failing. What the platform does not answer is
// left out, so an outage is never taken for a release that went wrong.
func healthy(directory string, owner int) update.Health {
	return func(ctx context.Context, version update.Version, since time.Time) error {
		deadline := time.Now().Add(healthWithin)
		for {
			last := judged(directory, owner, version, since)
			if last == nil {
				return nil
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("%s did not run as it should within %s: %w", version, healthWithin, last)
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(healthPoll):
			}
		}
	}
}

func judged(directory string, owner int, version update.Version, since time.Time) error {
	snapshot, err := status.ReadOwned(directory, owner)
	switch {
	case err != nil:
		return err
	case snapshot.Agent.StartedAt.Before(since):
		return fmt.Errorf("no run of the agent began after it was installed at %s", since.UTC().Format(time.RFC3339))
	case !strings.Contains(string(snapshot.Agent.Build)+" ", " "+version.String()+" "):
		return fmt.Errorf("the agent that runs is %s", snapshot.Agent.Build)
	case snapshot.State == status.Stopped:
		return fmt.Errorf("the agent stopped: %s", snapshot.Reason)
	case time.Since(snapshot.WrittenAt) > 2*healthSettle+healthPoll:
		return fmt.Errorf("the agent last said anything of itself at %s", snapshot.WrittenAt.UTC().Format(time.RFC3339))
	}
	for _, component := range snapshot.Components {
		if local(component.Name) && component.State == status.Failed {
			return fmt.Errorf("its %s failed: %s", component.Name, component.Reason)
		}
	}
	if ran := snapshot.WrittenAt.Sub(snapshot.Agent.StartedAt); ran < healthSettle {
		return fmt.Errorf("it has run for %s, short of the %s it is judged over", ran.Truncate(time.Second), healthSettle)
	}
	return nil
}

func local(component status.Text) bool {
	switch component {
	case "configuration", "collection", "spool", "resources":
		return true
	}
	return false
}
