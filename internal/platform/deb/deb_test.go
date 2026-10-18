package deb

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestAReleaseIsPackagedAsTheDebianVersionGoStampedItWith(t *testing.T) {
	versioned := map[string]string{
		"v0.1.0":                               "0.1.0-1",
		"v1.2.3-rc.1":                          "1.2.3~rc.1-1",
		"v0.0.0-20260926004346-7d7db5969ad5":   "0.0.0~20260926004346.7d7db5969ad5-1",
		"v0.1.1-0.20260926004346-7d7db5969ad5": "0.1.1~0.20260926004346.7d7db5969ad5-1",
	}
	for stamped, want := range versioned {
		if got, err := Version(stamped); err != nil || got != want {
			t.Errorf("an agent built as %s is packaged as %q (%v), want %q", stamped, got, err, want)
		}
	}
	for _, stamped := range []string{"", "(devel)", "v0.0.0-20260926004346-7d7db5969ad5+dirty", "0.1.0", "v0.1", "v01.2.3", "v1.2.3-", "v1.2.3-rc..1",
		"v1.2.3-rc-1", "v1.2.3-rc9", "v1.2.3-rc.01", "v1.2.3-1", "v1.2.3-rc.1234567890", "v18446744073709551616.0.0"} {
		if got, err := Version(stamped); err == nil {
			t.Errorf("an agent built as %q is packaged as %q", stamped, got)
		}
	}
}

func TestDpkgOrdersPackagesAsGoOrdersTheVersionsOfTheirAgents(t *testing.T) {
	if _, err := exec.LookPath("dpkg"); err != nil {
		t.Skip("dpkg compares Debian versions, and this host has none")
	}
	ascending := []string{
		"v0.0.0-20260101000000-aaaaaaaaaaaa",
		"v0.0.0-20260201000000-000000000000",
		"v0.1.0-rc.1",
		"v0.1.0-rc.2",
		"v0.1.0",
		"v0.1.1-0.20260301000000-bbbbbbbbbbbb",
		"v0.1.1",
		"v0.10.0",
		"v1.0.0-beta",
		"v1.0.0",
	}
	for i := 1; i < len(ascending); i++ {
		older, _ := Version(ascending[i-1])
		newer, _ := Version(ascending[i])
		if err := exec.Command("dpkg", "--compare-versions", older, "lt", newer).Run(); err != nil {
			t.Errorf("dpkg does not order %s (%s) before %s (%s): upgrading from one to the other would go backwards",
				older, ascending[i-1], newer, ascending[i])
		}
	}
}

func TestAPackageSaysItsNameVersionAndArchitecture(t *testing.T) {
	if _, err := exec.LookPath("dpkg-deb"); err != nil {
		t.Skip("dpkg-deb builds and reads a package, and this host has none")
	}
	tree := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tree, "DEBIAN"), 0o755); err != nil {
		t.Fatal(err)
	}
	control := "Package: seagull-agent\nVersion: 0.2.0-1\nArchitecture: amd64\nMaintainer: Seagull <seagull@example.com>\nDescription: a package\n"
	if err := os.WriteFile(filepath.Join(tree, "DEBIAN", "control"), []byte(control), 0o644); err != nil {
		t.Fatal(err)
	}
	built := filepath.Join(t.TempDir(), "seagull-agent_0.2.0-1_amd64.deb")
	if output, err := exec.Command("dpkg-deb", "--root-owner-group", "--build", tree, built).CombinedOutput(); err != nil {
		t.Fatalf("build a package: %v: %s", err, output)
	}

	fields, err := Inspect(t.Context(), built)
	if err != nil || fields != (Fields{Package: "seagull-agent", Version: "0.2.0-1", Architecture: "amd64"}) {
		t.Fatalf("the package says %+v: %v", fields, err)
	}
	if _, err := Inspect(t.Context(), filepath.Base(built)); err == nil {
		t.Fatal("a package named by a relative path was read")
	}
	notAPackage := filepath.Join(t.TempDir(), "not.deb")
	if err := os.WriteFile(notAPackage, []byte("no package"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Inspect(t.Context(), notAPackage); err == nil {
		t.Fatal("a file that is no package was read as one")
	}
}

func TestAPackageIsInstalledWithTheArgumentsAndTheEnvironmentTheAgentFixes(t *testing.T) {
	t.Setenv("SEAGULL_SECRET", "kept by the agent alone")
	directory := t.TempDir()
	recorded := filepath.Join(directory, "recorded")
	fake := filepath.Join(directory, "apt-get")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + recorded + "\nprintf '%s|%s|%s\\n' \"${SEAGULL_SECRET-unset}\" \"${DEBIAN_FRONTEND-unset}\" \"${PATH-unset}\" >> " + recorded + "\n"
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	held := installer
	installer = fake
	t.Cleanup(func() { installer = held })

	for downgrade, last := range map[bool]string{false: "-o\nDpkg::Options::=--force-confold\n/var/lib/seagull-agent-upgrade/next.deb", true: "--allow-downgrades\n/var/lib/seagull-agent-upgrade/next.deb"} {
		if err := Install(t.Context(), "/var/lib/seagull-agent-upgrade/next.deb", downgrade); err != nil {
			t.Fatalf("install: %v", err)
		}
		written, err := os.ReadFile(recorded)
		if err != nil {
			t.Fatal(err)
		}
		lines := string(written)
		if !strings.HasPrefix(lines, "install\n--yes\n--no-install-recommends\n") || !strings.Contains(lines, last+"\n") ||
			!strings.HasSuffix(lines, "unset|noninteractive|/usr/sbin:/usr/bin:/sbin:/bin\n") {
			t.Errorf("apt-get ran, downgrading %v, as\n%s", downgrade, lines)
		}
	}
	if err := Install(t.Context(), "next.deb", false); err == nil {
		t.Fatal("a package named by a relative path was installed")
	}
}
