package dpkg

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/dynasmon/Seagull-agent-v2/internal/platform/command"
)

type fake struct {
	directory string
}

// A dpkg-query that writes what the test hands it and keeps the arguments it
// was given, run as the agent runs dpkg-query.
func faked(t *testing.T, listed string) fake {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("the agent runs dpkg-query on linux alone")
	}
	directory := t.TempDir()
	script := fmt.Sprintf(`#!/bin/sh
for argument in "$@"; do printf '%%s\n' "$argument"; done > '%[1]s/arguments'
/bin/cat '%[1]s/listed'
if [ -f '%[1]s/complaint' ]; then /bin/cat '%[1]s/complaint' >&2; exit 2; fi
exit 0
`, directory)
	write(t, filepath.Join(directory, "dpkg-query"), script)
	if err := os.Chmod(filepath.Join(directory, "dpkg-query"), 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(directory, "listed"), listed)
	held := program
	program = filepath.Join(directory, "dpkg-query")
	t.Cleanup(func() { program = held })
	return fake{directory: directory}
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func line(fields ...string) string { return strings.Join(fields, "\t") + "\n" }

func TestDpkgQueryIsAskedForTheFieldsOfEveryPackageItKnows(t *testing.T) {
	fake := faked(t, "")
	if _, err := Installed(t.Context()); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(filepath.Join(fake.directory, "arguments"))
	if err != nil {
		t.Fatal(err)
	}
	want := "--show\n--showformat=${Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\t${Installed-Size}\t${db:Status-Status}\n\n"
	if string(content) != want {
		t.Errorf("dpkg-query was given %q, want %q", content, want)
	}
}

func TestAPackageIsOnTheHostWhileDpkgKeepsItsFiles(t *testing.T) {
	faked(t, line("libc6", "2.39-0ubuntu8.4", "amd64", "glibc", "2.39-0ubuntu8.4", "13608", "installed")+
		line("libc6", "2.39-0ubuntu8.4", "i386", "glibc", "2.39-0ubuntu8.4", "12345", "installed")+
		line("linux-image-6.8.0-45-generic", "6.8.0-45.45", "amd64", "linux-signed", "6.8.0-45.45", "14812", "triggers-pending")+
		line("man-db", "2.12.0-4build2", "amd64", "man-db", "2.12.0-4build2", "2809", "triggers-awaited")+
		line("broken", "1.0-1", "all", "broken", "1.0-1", "", "half-configured")+
		line("arriving", "2.0-1", "all", "arriving", "2.0-1", "4", "unpacked")+
		line("interrupted", "3.0-1", "all", "interrupted", "3.0-1", "8", "half-installed")+
		line("removed", "1.0-1", "all", "removed", "1.0-1", "16", "config-files")+
		line("purged", "", "", "purged", "", "", "not-installed"))
	held, err := Installed(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, installed := range held {
		names = append(names, installed.Name+":"+installed.Architecture+" "+installed.Status)
	}
	want := []string{
		"libc6:amd64 installed", "libc6:i386 installed", "linux-image-6.8.0-45-generic:amd64 triggers-pending", "man-db:amd64 triggers-awaited",
		"broken:all half-configured", "arriving:all unpacked", "interrupted:all half-installed",
	}
	if !slices.Equal(names, want) {
		t.Errorf("dpkg holds %v on the host, want %v", names, want)
	}
	if got := held[2]; got != (Package{Name: "linux-image-6.8.0-45-generic", Version: "6.8.0-45.45", Architecture: "amd64", Source: "linux-signed", SourceVersion: "6.8.0-45.45", InstalledKiB: 14812, Status: "triggers-pending"}) {
		t.Errorf("a package was read as %+v", got)
	}
	if held[4].InstalledKiB != 0 {
		t.Errorf("a package whose size dpkg does not record was read as %d KiB", held[4].InstalledKiB)
	}
}

func TestADatabaseThatHoldsNothingIsAnEmptyList(t *testing.T) {
	faked(t, "")
	held, err := Installed(t.Context())
	if err != nil || held == nil || len(held) != 0 {
		t.Errorf("an empty database was read as %v and %v", held, err)
	}
}

func TestAListThatCannotBeReadWholeIsRefused(t *testing.T) {
	good := line("bash", "5.2.21-2ubuntu4", "amd64", "bash", "5.2.21-2ubuntu4", "1828", "installed")
	for name, listed := range map[string]string{
		"a field too few":          good + "coreutils\t9.4-3ubuntu6\tamd64\tcoreutils\t9.4-3ubuntu6\tinstalled\n",
		"a field too many":         good + line("coreutils", "9.4-3ubuntu6", "amd64", "coreutils", "9.4-3ubuntu6", "7175", "installed", "extra"),
		"a package with no name":   good + line("", "1.0", "all", "", "1.0", "1", "installed"),
		"a state nobody knows":     good + line("coreutils", "9.4-3ubuntu6", "amd64", "coreutils", "9.4-3ubuntu6", "7175", "reinstalling"),
		"a size that is no number": good + line("coreutils", "9.4-3ubuntu6", "amd64", "coreutils", "9.4-3ubuntu6", "7175 KiB", "installed"),
		"a last line cut short":    good + "coreutils\t9.4-3ubuntu6",
		"a NUL byte":               good + line("core\x00utils", "9.4-3ubuntu6", "amd64", "coreutils", "9.4-3ubuntu6", "7175", "installed"),
		"an empty line":            good + "\n" + good,
	} {
		faked(t, listed)
		if held, err := Installed(t.Context()); !errors.Is(err, ErrUnreadable) {
			t.Errorf("%s: dpkg-query's list was read as %v and %v", name, held, err)
		}
	}
}

func TestAHostWithoutDpkgIsToldApartFromADpkgThatFails(t *testing.T) {
	fake := faked(t, "")
	write(t, filepath.Join(fake.directory, "complaint"), "dpkg-query: error: failed to open package info file '/var/lib/dpkg/status' for reading: Permission denied\n")
	_, err := Installed(t.Context())
	var failed *command.Failure
	if !errors.As(err, &failed) || errors.Is(err, ErrAbsent) || !strings.Contains(err.Error(), "dpkg-query: error: failed to open package info file") {
		t.Errorf("a dpkg-query that failed reported %v", err)
	}

	program = filepath.Join(fake.directory, "dpkg-query-gone")
	if _, err := Installed(t.Context()); !errors.Is(err, ErrAbsent) || !errors.Is(err, command.ErrAbsent) {
		t.Errorf("a host with no dpkg-query reported %v", err)
	}
}

func TestTheDpkgOfThisHostIsReadWhole(t *testing.T) {
	if _, err := os.Stat(program); err != nil || runtime.GOOS != "linux" {
		t.Skip("this host has no dpkg")
	}
	held, err := Installed(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	statuses, err := exec.Command(program, "--show", "--showformat=${Package}:${Architecture} ${db:Status-Status}\n").Output()
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for listed := range strings.SplitSeq(strings.TrimSpace(string(statuses)), "\n") {
		name, status, _ := strings.Cut(listed, " ")
		if unpacked[status] {
			want = append(want, name)
		}
	}
	var got []string
	for _, installed := range held {
		got = append(got, installed.Name+":"+installed.Architecture)
		if installed.Version == "" || installed.Source == "" || installed.SourceVersion == "" {
			t.Errorf("dpkg holds %+v", installed)
		}
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) || len(slices.Compact(slices.Clone(got))) != len(got) || !slices.Contains(got, "dpkg:"+runtime.GOARCH) {
		t.Errorf("the agent read %d packages of this host's dpkg, which lists %d", len(got), len(want))
	}
}
