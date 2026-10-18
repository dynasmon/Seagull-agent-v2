package main

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/status"
	"github.com/dynasmon/Seagull-agent-v2/internal/update"
	updatev1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/update/v1"
)

func keptStatus(t *testing.T, snapshot status.Snapshot) string {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "status")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	keeper, err := status.NewKeeper(root, time.Hour, func() status.Snapshot { return snapshot }, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	stopped := make(chan error, 1)
	go func() { stopped <- keeper.Run(ctx) }()
	for deadline := time.Now().Add(5 * time.Second); ; {
		if _, err := os.Stat(filepath.Join(directory, "status.json")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the keeper wrote no status")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-stopped
	return directory
}

func TestAReleaseRunsAsItShouldOnlyOnceARunOfItSaidSoForAWholeInterval(t *testing.T) {
	now := time.Now()
	since := now.Add(-time.Minute)
	version, _ := update.ParseVersion("v0.3.0")
	healthyRun := func() status.Snapshot {
		return status.Snapshot{
			State: status.Degraded,
			Agent: status.Agent{Build: "seagull-agent v0.3.0 go1.26.9 linux/amd64", StartedAt: now.Add(-40 * time.Second)},
			Components: []status.Component{
				{Name: "configuration", State: status.Running},
				{Name: "spool", State: status.Running},
				{Name: "delivery", State: status.Failed, Reason: "the platform does not answer"},
			},
		}
	}
	if err := judged(keptStatus(t, healthyRun()), os.Geteuid(), version, since); err != nil {
		t.Fatalf("a release that ran an interval with only the platform out of reach was judged %v", err)
	}
	for name, change := range map[string]func(*status.Snapshot){
		"a run that began before it was installed": func(s *status.Snapshot) { s.Agent.StartedAt = since.Add(-time.Second) },
		"another release":                          func(s *status.Snapshot) { s.Agent.Build = "seagull-agent v0.3.0-rc.1 go1.26.9 linux/amd64" },
		"a spool that failed":                      func(s *status.Snapshot) { s.Components[1].State = status.Failed },
		"a run that has not lasted an interval":    func(s *status.Snapshot) { s.Agent.StartedAt = now.Add(-5 * time.Second) },
		"a run that stopped":                       func(s *status.Snapshot) { s.State = status.Stopped },
	} {
		t.Run(name, func(t *testing.T) {
			run := healthyRun()
			change(&run)
			if err := judged(keptStatus(t, run), os.Geteuid(), version, since); err == nil {
				t.Fatal("judged as running as it should")
			}
		})
	}
	if err := judged(keptStatus(t, healthyRun()), os.Geteuid()+1, version, since); err == nil {
		t.Fatal("a status another account wrote was taken for the agent's")
	}
}

func TestAPackageIsTheReleaseItIsSaidToBeOnlyWhenDpkgSaysSo(t *testing.T) {
	if _, err := exec.LookPath("dpkg-deb"); err != nil {
		t.Skip("dpkg-deb reads a package, and this host has none")
	}
	tree := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tree, "DEBIAN"), 0o755); err != nil {
		t.Fatal(err)
	}
	control := "Package: seagull-agent\nVersion: 0.3.0-1\nArchitecture: amd64\nMaintainer: Seagull <seagull@example.com>\nDescription: a package\n"
	if err := os.WriteFile(filepath.Join(tree, "DEBIAN", "control"), []byte(control), 0o644); err != nil {
		t.Fatal(err)
	}
	built := filepath.Join(t.TempDir(), "seagull-agent.deb")
	if output, err := exec.Command("dpkg-deb", "--root-owner-group", "--build", tree, built).CombinedOutput(); err != nil {
		t.Fatalf("build a package: %v: %s", err, output)
	}
	release := func(version, architecture string) *updatev1.Release {
		return &updatev1.Release{Version: version, Platform: &updatev1.Platform{Os: "linux", Architecture: architecture, Format: updatev1.Format_FORMAT_DEB}}
	}
	if err := (debianPackages{}).Matches(t.Context(), built, release("v0.3.0", "amd64")); err != nil {
		t.Fatalf("the package of v0.3.0 was judged another release: %v", err)
	}
	for _, other := range []*updatev1.Release{release("v0.3.1", "amd64"), release("v0.3.0", "arm64"), release("v0.3.0", "riscv64")} {
		if err := (debianPackages{}).Matches(t.Context(), built, other); err == nil {
			t.Errorf("the package of v0.3.0 for amd64 was taken for %s for %s", other.GetVersion(), other.GetPlatform().GetArchitecture())
		}
	}
}

func TestTheInstallerOpensOnlyDirectoriesTheInstallationHolds(t *testing.T) {
	state, outside := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "ready"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(state, "staged"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(state, "update")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "status"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	installation, err := os.OpenRoot(state)
	if err != nil {
		t.Fatal(err)
	}
	defer installation.Close()

	staged, err := opened(installation, "staged")
	if err != nil || staged == nil || staged.Name() != filepath.Join(state, "staged") {
		t.Fatalf("the staging area of the installation was not opened: %v", err)
	}
	staged.Close()
	if held, err := opened(installation, "absent"); held != nil || err != nil {
		t.Fatalf("a directory never made was opened: %v", err)
	}
	for _, name := range []string{"update", "status"} {
		if held, err := opened(installation, name); held != nil || err == nil {
			t.Fatalf("%s, which is not a directory of the installation, was opened as one", name)
		}
	}
}

func TestTheInstallerRunsOnlyAsRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the test runs as root, where the installer runs")
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-config", filepath.Join(t.TempDir(), "agent.json"), "update", "install"}, &stdout, &stderr); code != 1 ||
		!strings.Contains(stderr.String(), "only root does") {
		t.Fatalf("the installer ran as uid %d and exited %d: %s", os.Geteuid(), code, stderr.String())
	}
}

func TestAnAgentThatTakesNoUpdateSaysSoAndReportsNone(t *testing.T) {
	observed := &observing{}
	if component := observed.updated(); component.Name != "update" || component.State != status.Disabled {
		t.Fatalf("an agent that takes no update reports %+v", component)
	}
	if reported := observed.updateReport(); reported != nil {
		t.Fatalf("an agent that takes no update reports %v", reported)
	}
	if updates := observed.compatibility().GetUpdates(); updates.GetEnabled() || updates.GetRootVersion() != 0 || updates.GetCatalogVersion() != 0 ||
		updates.GetFormat() != packaged() || updates.GetStateGeneration() != update.StateGeneration {
		t.Fatalf("an agent that takes no update says it takes %v", updates)
	}
}
