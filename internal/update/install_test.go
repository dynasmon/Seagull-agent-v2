package update_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-agent-v2/internal/update"
	updatev1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/update/v1"
)

type manager struct {
	mu         sync.Mutex
	installed  []string
	downgrades []bool
	failing    map[string]error
	mismatched map[string]bool
}

func (m *manager) Matches(_ context.Context, path string, release *updatev1.Release) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.mismatched[release.GetVersion()] {
		return errors.New("dpkg-deb says the package is another release")
	}
	return nil
}

func (m *manager) Install(_ context.Context, path string, downgrade bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.installed, m.downgrades = append(m.installed, filepath.Base(path)), append(m.downgrades, downgrade)
	return m.failing[filepath.Base(path)]
}

type checking struct {
	mu      sync.Mutex
	healthy map[string]bool
	asked   []string
}

func (c *checking) check(_ context.Context, version update.Version, _ time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.asked = append(c.asked, version.String())
	if !c.healthy[version.String()] {
		return errors.New(version.String() + " never said it ran")
	}
	return nil
}

type installing struct {
	installer  *update.Installer
	manager    *manager
	health     *checking
	staged     *os.Root
	held       *os.Root
	generation uint32
	current    []byte
	next       []byte
}

func (e estate) installing(t *testing.T, healthy ...string) *installing {
	t.Helper()
	current, next, catalog := pair(t)
	held := &installing{
		manager:    &manager{failing: map[string]error{}, mismatched: map[string]bool{}},
		health:     &checking{healthy: map[string]bool{}},
		staged:     directory(t),
		held:       directory(t),
		generation: 1,
		current:    current,
		next:       next,
	}
	for _, version := range healthy {
		held.health.healthy[version] = true
	}
	offer, err := proto.Marshal(e.offer(t, "v0.3.0", catalog))
	if err != nil {
		t.Fatal(err)
	}
	staging := update.OpenStaging(held.staged)
	for _, content := range [][]byte{current, next} {
		release := releaseFor("staged", content)
		if err := staging.Fetch(release, func(into io.Writer) error { _, err := into.Write(content); return err }); err != nil {
			t.Fatal(err)
		}
	}
	if err := staging.Hand(offer); err != nil {
		t.Fatal(err)
	}
	held.installer, err = update.NewInstaller(update.InstallerOptions{
		Staging:    staging,
		Directory:  held.held,
		Anchor:     e.anchor,
		Running:    running("v0.2.0"),
		Generation: func() uint32 { return held.generation },
		Packages:   held.manager,
		Health:     held.health.check,
		Logger:     slog.New(slog.NewJSONHandler(io.Discard, nil)),
		Now:        func() time.Time { return written },
	})
	if err != nil {
		t.Fatal(err)
	}
	return held
}

func (i *installing) journal(t *testing.T) update.Journal {
	t.Helper()
	journal, found, err := update.ReadJournal(i.held)
	if err != nil || !found {
		t.Fatalf("the installer kept no journal: %v", err)
	}
	return journal
}

func (i *installing) packages(t *testing.T) []string {
	t.Helper()
	var held []string
	for _, name := range entries(t, i.held) {
		if strings.HasSuffix(name, ".deb") {
			held = append(held, name)
		}
	}
	return held
}

func TestTheInstallerInstallsTheStagedReleaseOnceItVerifiedItAgain(t *testing.T) {
	land := newEstate(t)
	installing := land.installing(t, "v0.3.0")

	if err := installing.installer.Run(t.Context()); err != nil {
		t.Fatalf("run: %v", err)
	}
	journal := installing.journal(t)
	switch {
	case journal.Stage != update.Installed || journal.Version != "v0.3.0" || journal.Previous != "v0.2.0" || journal.Catalog != 7 || journal.Failure != "":
		t.Fatalf("the installer ended at %+v", journal)
	case !slices.Equal(installing.manager.installed, []string{update.PackageName(digest(installing.next))}) || installing.manager.downgrades[0]:
		t.Fatalf("the installer installed %v, downgrading %v", installing.manager.installed, installing.manager.downgrades)
	case len(entries(t, installing.staged)) != 0 || len(installing.packages(t)) != 0:
		t.Fatalf("the installer left %v staged and %v of its own", entries(t, installing.staged), installing.packages(t))
	}
	if _, err := os.Stat(filepath.Join(installing.held.Name(), "pending")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("an installation that ended is still pending: %v", err)
	}
	store, _ := update.OpenStore(installing.held)
	if held, err := store.Held(land.anchor, written); err != nil || held.Catalog != 7 {
		t.Fatalf("the installer keeps catalog %d: %v", held.Catalog, err)
	}
}

func TestAReleaseThatDoesNotRunIsUndoneByTheReleaseBeforeIt(t *testing.T) {
	land := newEstate(t)
	installing := land.installing(t, "v0.2.0")

	if err := installing.installer.Run(t.Context()); err != nil {
		t.Fatalf("run: %v", err)
	}
	journal := installing.journal(t)
	want := []string{update.PackageName(digest(installing.next)), update.PackageName(digest(installing.current))}
	switch {
	case journal.Stage != update.RolledBack || journal.Failure != update.Unhealthy || !strings.Contains(journal.Reason, "never said it ran"):
		t.Fatalf("the installer ended at %+v", journal)
	case !slices.Equal(installing.manager.installed, want) || !slices.Equal(installing.manager.downgrades, []bool{false, true}):
		t.Fatalf("the installer installed %v, downgrading %v", installing.manager.installed, installing.manager.downgrades)
	case !slices.Equal(installing.health.asked, []string{"v0.3.0", "v0.2.0"}):
		t.Fatalf("the installer checked %v", installing.health.asked)
	}
}

func TestAReleaseThePackageManagerDidNotInstallIsUndone(t *testing.T) {
	land := newEstate(t)
	installing := land.installing(t, "v0.2.0", "v0.3.0")
	installing.manager.failing[update.PackageName(digest(installing.next))] = errors.New("dpkg: error processing package seagull-agent")

	if err := installing.installer.Run(t.Context()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if journal := installing.journal(t); journal.Stage != update.RolledBack || journal.Failure != update.Installation || len(installing.manager.installed) != 2 {
		t.Fatalf("the installer ended at %+v after installing %v", journal, installing.manager.installed)
	}
}

func TestGoingBackIsRefusedOnceTheStateMovedPastTheReleaseBefore(t *testing.T) {
	land := newEstate(t)
	installing := land.installing(t)
	installing.generation = 2

	if err := installing.installer.Run(t.Context()); err != nil {
		t.Fatalf("run: %v", err)
	}
	journal := installing.journal(t)
	if journal.Stage != update.Failed || journal.Failure != update.Unhealthy || !strings.Contains(journal.Reason, "going back to v0.2.0 is refused") || len(installing.manager.installed) != 1 {
		t.Fatalf("the installer ended at %+v after installing %v", journal, installing.manager.installed)
	}
}

func TestTheInstallerRefusesWhatItsOwnTrustRefusesWhateverTheAgentStaged(t *testing.T) {
	land := newEstate(t)
	installing := land.installing(t, "v0.3.0")
	store, err := update.OpenStore(installing.held)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Keep(update.Held{Root: land.anchor, Catalog: 9}); err != nil {
		t.Fatal(err)
	}

	if err := installing.installer.Run(t.Context()); err != nil {
		t.Fatalf("run: %v", err)
	}
	journal := installing.journal(t)
	if journal.Stage != update.Failed || journal.Failure != update.Refused || len(installing.manager.installed) != 0 || len(entries(t, installing.staged)) != 0 {
		t.Fatalf("a catalog older than the installer's ended at %+v, installing %v", journal, installing.manager.installed)
	}
}

func TestAPackageThatIsNotTheReleaseItIsSaidToBeIsNotInstalled(t *testing.T) {
	land := newEstate(t)
	installing := land.installing(t, "v0.3.0")
	installing.manager.mismatched["v0.3.0"] = true

	if err := installing.installer.Run(t.Context()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if journal := installing.journal(t); journal.Stage != update.Failed || journal.Failure != update.Unverified || len(installing.manager.installed) != 0 {
		t.Fatalf("a package that is another release ended at %+v, installing %v", journal, installing.manager.installed)
	}
}

func TestAnInstallationACrashInterruptedIsTakenToItsEnd(t *testing.T) {
	for stage, want := range map[update.Stage]struct {
		installed []string
		end       update.Stage
	}{
		update.Installing: {[]string{"next"}, update.Installed},
		update.Checking:   {nil, update.Installed},
		update.Reverting:  {[]string{"current"}, update.RolledBack},
	} {
		t.Run(string(stage), func(t *testing.T) {
			land := newEstate(t)
			installing := land.installing(t, "v0.2.0", "v0.3.0")
			staging := update.OpenStaging(installing.staged)
			named := map[string]string{"current": update.PackageName(digest(installing.current)), "next": update.PackageName(digest(installing.next))}
			for _, content := range [][]byte{installing.current, installing.next} {
				if err := staging.Take(releaseFor("staged", content), installing.held); err != nil {
					t.Fatal(err)
				}
			}
			if err := staging.Clear(); err != nil {
				t.Fatal(err)
			}
			interrupted := update.Journal{Stage: stage, Version: "v0.3.0", Previous: "v0.2.0", PreviousState: 1, Catalog: 7, Root: 1,
				Target: named["next"], Fallback: named["current"], Started: written, Since: written}
			if stage == update.Reverting {
				interrupted.Failure, interrupted.Reason = update.Unhealthy, "it never said it ran"
			}
			if err := update.KeepJournal(installing.held, interrupted); err != nil {
				t.Fatal(err)
			}

			if err := installing.installer.Run(t.Context()); err != nil {
				t.Fatalf("run: %v", err)
			}
			var expected []string
			for _, which := range want.installed {
				expected = append(expected, named[which])
			}
			if journal := installing.journal(t); journal.Stage != want.end || !slices.Equal(installing.manager.installed, expected) {
				t.Fatalf("resuming at %s ended at %s after installing %v, want %s after %v", stage, journal.Stage, installing.manager.installed, want.end, expected)
			}
		})
	}
}

func TestAnInstallerWithNothingStagedDoesNothing(t *testing.T) {
	land := newEstate(t)
	installing := land.installing(t)
	if err := update.OpenStaging(installing.staged).Clear(); err != nil {
		t.Fatal(err)
	}
	if err := installing.installer.Run(t.Context()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if _, found, err := update.ReadJournal(installing.held); found || err != nil || len(installing.manager.installed) != 0 {
		t.Fatalf("an installer with nothing staged kept a journal or installed %v: %v", installing.manager.installed, err)
	}
}

func TestAnInstallationThatCannotGoBackEitherEndsFailedAndSaysWhy(t *testing.T) {
	for name, arrange := range map[string]func(*installing){
		"the release before did not run either": func(*installing) {},
		"the release before did not install": func(installing *installing) {
			installing.manager.failing[update.PackageName(digest(installing.current))] = errors.New("dpkg: error processing package seagull-agent")
		},
	} {
		t.Run(name, func(t *testing.T) {
			land := newEstate(t)
			installing := land.installing(t)
			arrange(installing)
			if err := installing.installer.Run(t.Context()); err != nil {
				t.Fatalf("run: %v", err)
			}
			journal := installing.journal(t)
			if journal.Stage != update.Failed || journal.Failure != update.Unhealthy || !strings.Contains(journal.Reason, "v0.2.0") || len(installing.packages(t)) != 0 {
				t.Fatalf("the installer ended at %+v holding %v", journal, installing.packages(t))
			}
		})
	}
}

func TestAnInstallerWithNoStagingAreaStillTakesAnInterruptedInstallationToItsEnd(t *testing.T) {
	land := newEstate(t)
	installing := land.installing(t, "v0.3.0")
	staging := update.OpenStaging(installing.staged)
	for _, content := range [][]byte{installing.current, installing.next} {
		if err := staging.Take(releaseFor("staged", content), installing.held); err != nil {
			t.Fatal(err)
		}
	}
	if err := update.KeepJournal(installing.held, update.Journal{Stage: update.Checking, Version: "v0.3.0", Previous: "v0.2.0", PreviousState: 1,
		Target: update.PackageName(digest(installing.next)), Fallback: update.PackageName(digest(installing.current)), Started: written, Since: written}); err != nil {
		t.Fatal(err)
	}
	installer, err := update.NewInstaller(update.InstallerOptions{
		Directory: installing.held, Anchor: land.anchor, Running: running("v0.2.0"),
		Generation: func() uint32 { return 1 }, Packages: installing.manager, Health: installing.health.check,
		Logger: slog.New(slog.NewJSONHandler(io.Discard, nil)), Now: func() time.Time { return written },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := installer.Run(t.Context()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if journal := installing.journal(t); journal.Stage != update.Installed {
		t.Fatalf("an installer with no staging area ended at %+v", journal)
	}
}
