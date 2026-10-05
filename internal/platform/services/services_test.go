package services

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

type fake struct {
	directory string
}

// A systemctl that answers each listing with what the test hands it and keeps
// the arguments of every call, run as the agent runs systemctl, on a host
// systemd manages.
func faked(t *testing.T, units, files string) fake {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("the agent runs systemctl on linux alone")
	}
	directory := t.TempDir()
	script := fmt.Sprintf(`#!/bin/sh
for argument in "$@"; do printf '%%s ' "$argument"; done >> '%[1]s/arguments'
echo >> '%[1]s/arguments'
if [ -f '%[1]s/complaint' ]; then /bin/cat '%[1]s/complaint' >&2; exit 1; fi
/bin/cat '%[1]s/'"$1"
`, directory)
	write(t, filepath.Join(directory, "systemctl"), script)
	if err := os.Chmod(filepath.Join(directory, "systemctl"), 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(directory, "list-units"), units)
	write(t, filepath.Join(directory, "list-unit-files"), files)
	if err := os.Mkdir(filepath.Join(directory, "system"), 0o755); err != nil {
		t.Fatal(err)
	}
	heldProgram, heldBooted := program, booted
	program, booted = filepath.Join(directory, "systemctl"), filepath.Join(directory, "system")
	t.Cleanup(func() { program, booted = heldProgram, heldBooted })
	return fake{directory: directory}
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

const (
	units = `[{"unit":"ssh.service","load":"loaded","active":"active","sub":"running","description":"OpenBSD Secure Shell server"},
{"unit":"apt-daily.service","load":"loaded","active":"inactive","sub":"dead","description":"Daily apt download activities"},
{"unit":"getty@tty1.service","load":"loaded","active":"active","sub":"running","description":"Getty on tty1"},
{"unit":"auditd.service","load":"not-found","active":"inactive","sub":"dead","description":"auditd.service"},
{"unit":"vanished.service","load":"not-found","active":"active","sub":"running","description":"Still running without its file"},
{"unit":"run-u42.service","load":"loaded","active":"failed","sub":"failed","description":"/usr/bin/false"},
{"unit":"alsa-utils.service","load":"masked","active":"inactive","sub":"dead","description":"alsa-utils.service"}]
`
	files = `[{"unit_file":"ssh.service","state":"enabled","preset":"enabled"},
{"unit_file":"sshd.service","state":"alias","preset":null},
{"unit_file":"apt-daily.service","state":"static","preset":null},
{"unit_file":"getty@.service","state":"enabled","preset":"enabled"},
{"unit_file":"cron.service","state":"disabled","preset":"enabled"},
{"unit_file":"alsa-utils.service","state":"masked","preset":"enabled"}]
`
)

func TestEveryServiceSystemdHoldsLoadedOrHasAFileOfIsListed(t *testing.T) {
	fake := faked(t, units, files)
	listed, err := List(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	want := []Service{
		{Name: "alsa-utils.service", Description: "alsa-utils.service", Load: "masked", Active: "inactive", Sub: "dead", File: "masked"},
		{Name: "apt-daily.service", Description: "Daily apt download activities", Load: "loaded", Active: "inactive", Sub: "dead", File: "static"},
		{Name: "cron.service", Active: "inactive", Sub: "dead", File: "disabled"},
		{Name: "getty@tty1.service", Description: "Getty on tty1", Load: "loaded", Active: "active", Sub: "running"},
		{Name: "run-u42.service", Description: "/usr/bin/false", Load: "loaded", Active: "failed", Sub: "failed"},
		{Name: "ssh.service", Description: "OpenBSD Secure Shell server", Load: "loaded", Active: "active", Sub: "running", File: "enabled"},
		{Name: "vanished.service", Description: "Still running without its file", Load: "not-found", Active: "active", Sub: "running"},
	}
	if !slices.Equal(listed, want) {
		t.Errorf("systemd manages\n%v\nwant\n%v", listed, want)
	}
	content, err := os.ReadFile(filepath.Join(fake.directory, "arguments"))
	if err != nil {
		t.Fatal(err)
	}
	if got := string(content); got != "list-units --type=service --output=json --no-pager --all \nlist-unit-files --type=service --output=json --no-pager \n" {
		t.Errorf("systemctl was asked %q", got)
	}
}

func TestAHostSystemdDoesNotManageHasNoServicesToList(t *testing.T) {
	fake := faked(t, "[]\n", "[]\n")
	booted = filepath.Join(fake.directory, "absent")
	if _, err := List(t.Context()); !errors.Is(err, ErrAbsent) {
		t.Errorf("a host whose PID 1 is not systemd reported %v", err)
	}
	booted = filepath.Join(fake.directory, "system")
	program = filepath.Join(fake.directory, "absent")
	if _, err := List(t.Context()); !errors.Is(err, ErrAbsent) {
		t.Errorf("a host with no systemctl reported %v", err)
	}
}

func TestASystemctlThatCannotReachSystemdIsDeniedRatherThanEmpty(t *testing.T) {
	fake := faked(t, units, files)
	write(t, filepath.Join(fake.directory, "complaint"), "Failed to connect to bus: Address family not supported by protocol\n")
	if listed, err := List(t.Context()); !errors.Is(err, ErrDenied) || listed != nil {
		t.Errorf("a systemctl that could not reach systemd gave %v and %v", listed, err)
	}
	write(t, filepath.Join(fake.directory, "complaint"), "Unknown command verb list-units.\n")
	if _, err := List(t.Context()); err == nil || errors.Is(err, ErrDenied) || errors.Is(err, ErrUnreadable) {
		t.Errorf("a systemctl that failed otherwise reported %v", err)
	}
}

func TestAListingThatCannotBeReadWholeIsRefused(t *testing.T) {
	for name, listings := range map[string][2]string{
		"no JSON":                   {"UNIT LOAD ACTIVE SUB\n", files},
		"two documents":             {"[]\n[]\n", files},
		"a unit with no name":       {`[{"unit":"","load":"loaded","active":"active","sub":"running"}]`, files},
		"a unit that is no service": {`[{"unit":"ssh.socket","load":"loaded","active":"active","sub":"running"}]`, files},
		"a unit of no state":        {`[{"unit":"ssh.service","load":"loaded","active":"","sub":""}]`, files},
		"a unit listed twice":       {`[{"unit":"ssh.service","load":"loaded","active":"active","sub":"running"},{"unit":"ssh.service","load":"loaded","active":"active","sub":"running"}]`, files},
		"a unit file of no state":   {units, `[{"unit_file":"ssh.service","state":""}]`},
		"a unit file of a path":     {units, `[{"unit_file":"../ssh.service","state":"enabled"}]`},
	} {
		faked(t, listings[0], listings[1])
		if listed, err := List(t.Context()); !errors.Is(err, ErrUnreadable) {
			t.Errorf("%s: the listing was read as %v and %v", name, listed, err)
		}
	}
}

func TestTheServicesOfThisHostAreListed(t *testing.T) {
	if _, err := os.Stat(booted); err != nil || runtime.GOOS != "linux" {
		t.Skip("systemd does not manage this host")
	}
	listed, err := List(t.Context())
	if errors.Is(err, ErrDenied) {
		t.Skipf("systemctl cannot reach systemd from here: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	journald := slices.IndexFunc(listed, func(held Service) bool { return held.Name == "systemd-journald.service" })
	if journald < 0 || listed[journald].Active != "active" || listed[journald].Load != "loaded" {
		t.Errorf("this host's journald is listed as %v", listed)
	}
	for _, held := range listed {
		if strings.HasSuffix(held.Name, "@.service") || held.File == "alias" || held.Active == "" {
			t.Errorf("listed %+v", held)
		}
	}
}
