package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"maps"
	"math/big"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/config"
)

var committed = time.Date(2026, 9, 26, 0, 43, 46, 0, time.UTC)

func TestAPackageIsVersionedAsGoStampedTheAgent(t *testing.T) {
	versioned := map[string]string{
		"v0.1.0":                               "0.1.0-1",
		"v1.2.3-rc.1":                          "1.2.3~rc.1-1",
		"v0.0.0-20260926004346-7d7db5969ad5":   "0.0.0~20260926004346.7d7db5969ad5-1",
		"v0.1.1-0.20260926004346-7d7db5969ad5": "0.1.1~0.20260926004346.7d7db5969ad5-1",
	}
	for stamped, want := range versioned {
		if got, err := debianVersion(stamped); err != nil || got != want {
			t.Errorf("an agent built as %s is packaged as %q (%v), want %q", stamped, got, err, want)
		}
	}
	for _, stamped := range []string{"", "(devel)", "v0.0.0-20260926004346-7d7db5969ad5+dirty", "0.1.0", "v0.1", "v01.2.3", "v1.2.3-", "v1.2.3-rc..1"} {
		if got, err := debianVersion(stamped); err == nil {
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
		older, _ := debianVersion(ascending[i-1])
		newer, _ := debianVersion(ascending[i])
		if err := exec.Command("dpkg", "--compare-versions", older, "lt", newer).Run(); err != nil {
			t.Errorf("dpkg does not order %s (%s) before %s (%s): upgrading from one to the other would go backwards",
				older, ascending[i-1], newer, ascending[i])
		}
	}
}

func TestOnlyAPortableLinuxBuildOfACommitIsPackaged(t *testing.T) {
	want := release{version: "0.0.0~20260926004346.7d7db5969ad5-1", architecture: "amd64", committed: committed}
	if described, err := describe(built(nil)); err != nil || described != want {
		t.Fatalf("a portable linux build of a commit is described as %+v (%v), want %+v", described, err, want)
	}
	if described, err := describe(built(map[string]string{"GOARCH": "arm64", "GOAMD64": "", "GOARM64": "v8.0"})); err != nil || described.architecture != "arm64" {
		t.Fatalf("an arm64 build is described as %+v (%v)", described, err)
	}
	for _, c := range []struct {
		changed map[string]string
		said    string
	}{
		{changed: map[string]string{"path": modulePath + "/packaging"}, said: "and the package installs " + command},
		{changed: map[string]string{"main": "github.com/example/fork"}, said: "and the package installs " + command},
		{changed: map[string]string{"GOOS": "windows"}, said: "built for windows"},
		{changed: map[string]string{"GOARCH": "386"}, said: "built for 386"},
		{changed: map[string]string{"GOAMD64": "v3"}, said: "GOAMD64=v3"},
		{changed: map[string]string{"GOARCH": "arm64", "GOARM64": "v9.0"}, said: "GOARM64=v9.0"},
		{changed: map[string]string{"CGO_ENABLED": "1"}, said: "built with cgo"},
		{changed: map[string]string{"-trimpath": ""}, said: "without -trimpath"},
		{changed: map[string]string{"vcs.revision": "", "vcs.modified": ""}, said: "names no commit"},
		{changed: map[string]string{"vcs.modified": "true"}, said: "changes no commit holds"},
		{changed: map[string]string{"version": "(devel)"}, said: "names no release or commit"},
		{changed: map[string]string{"vcs.time": "yesterday"}, said: "as the time of its commit"},
	} {
		if described, err := describe(built(c.changed)); err == nil {
			t.Errorf("a build with %v is packaged as %+v", c.changed, described)
		} else if !strings.Contains(err.Error(), c.said) {
			t.Errorf("a build with %v is refused as %q, which does not say %q", c.changed, err, c.said)
		}
	}
}

func TestThePackageHoldsTheAgentItsServiceAndNothingElse(t *testing.T) {
	requireDpkgDeb(t)
	agent := []byte("\x7fELF the agent")
	written := packaged(t, release{version: "0.1.0-1", architecture: "amd64", committed: committed}, agent)
	if name := filepath.Base(written); name != "seagull-agent_0.1.0-1_amd64.deb" {
		t.Fatalf("the package is written as %s", name)
	}

	want := map[string]string{
		"./usr/bin/seagull-agent":                        "-rwxr-xr-x",
		"./usr/lib/systemd/system/seagull-agent.service": "-rw-r--r--",
		"./usr/lib/sysusers.d/seagull-agent.conf":        "-rw-r--r--",
		"./usr/lib/tmpfiles.d/seagull-agent.conf":        "-rw-r--r--",
		"./usr/share/doc/seagull-agent/copyright":        "-rw-r--r--",
		"./usr/share/seagull-agent/agent.json":           "-rw-r--r--",
	}
	entries := listed(t, "--fsys-tarfile", written)
	var files []string
	for name, entry := range entries {
		directory := strings.HasSuffix(name, "/")
		if !directory {
			files = append(files, name)
		}
		switch {
		case entry.owner != "0/0":
			t.Errorf("%s belongs to %s", name, entry.owner)
		case !entry.modified.Equal(committed.Truncate(time.Minute)):
			t.Errorf("%s is dated %s, and the commit %s", name, entry.modified, committed)
		case directory && entry.mode != "drwxr-xr-x":
			t.Errorf("the directory %s is %s", name, entry.mode)
		case !directory && entry.mode != want[name]:
			t.Errorf("%s is %s, want %s", name, entry.mode, want[name])
		}
	}
	if slices.Sort(files); !slices.Equal(files, slices.Sorted(maps.Keys(want))) {
		t.Fatalf("the package installs %q", files)
	}

	scripts := listed(t, "--ctrl-tarfile", written)
	for _, script := range maintainerScripts {
		if entry := scripts["./"+script]; entry.mode != "-rwxr-xr-x" || entry.owner != "0/0" {
			t.Errorf("the %s script is %+v", script, entry)
		}
	}
	for field, value := range map[string]string{
		"Package":      "seagull-agent",
		"Version":      "0.1.0-1",
		"Architecture": "amd64",
		"Maintainer":   maintainer,
		"Depends":      "systemd (>= 254), procps",
	} {
		if got := strings.TrimSpace(output(t, "dpkg-deb", "--field", written, field)); got != value {
			t.Errorf("the package declares %s: %q, want %q", field, got, value)
		}
	}

	control := filepath.Join(t.TempDir(), "DEBIAN")
	output(t, "dpkg-deb", "--control", written, control)
	extracted := t.TempDir()
	output(t, "dpkg-deb", "--extract", written, extracted)
	sums, err := os.ReadFile(filepath.Join(control, "md5sums"))
	if err != nil {
		t.Fatalf("read the checksums the package holds: %v", err)
	}
	var summed []string
	for line := range strings.Lines(string(sums)) {
		sum, name, _ := strings.Cut(strings.TrimSpace(line), "  ")
		content, err := os.ReadFile(filepath.Join(extracted, filepath.FromSlash(name)))
		if err != nil || fmt.Sprintf("%x", md5.Sum(content)) != sum {
			t.Errorf("the checksum of %s does not match what the package installs: %v", name, err)
		}
		summed = append(summed, "./"+name)
	}
	if !slices.Equal(summed, slices.Sorted(maps.Keys(want))) {
		t.Errorf("the package holds checksums of %q", summed)
	}
	if installed, err := os.ReadFile(filepath.Join(extracted, "usr", "bin", "seagull-agent")); err != nil || !bytes.Equal(installed, agent) {
		t.Errorf("the package installs another agent than the one it was given: %v", err)
	}
}

func TestTheSameCommitIsPackagedIntoTheSameBytes(t *testing.T) {
	requireDpkgDeb(t)
	built := release{version: "0.1.0-1", architecture: "arm64", committed: committed}
	first, err := os.ReadFile(packaged(t, built, []byte("the agent")))
	if err != nil {
		t.Fatalf("read the package: %v", err)
	}
	time.Sleep(1100 * time.Millisecond)
	second, err := os.ReadFile(packaged(t, built, []byte("the agent")))
	if err != nil {
		t.Fatalf("read the package: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("packaging the same commit twice wrote two different packages")
	}
}

// The unit, the account, the directories and the settings a package starts from
// are four files that have to agree, and the agent's own defaults have to fit
// within what the service allows.
func TestTheServiceRunsTheAgentAsThePackageInstallsIt(t *testing.T) {
	unit := sections(t, "linux/seagull-agent.service")
	service := unit["Service"]
	declared := strings.Split(strings.TrimSpace(asset(t, "linux/sysusers.conf")), "\n")
	account := strings.Fields(declared[0])
	if len(account) < 3 || account[0] != "u" || account[2] != "-" {
		t.Fatalf("the package declares its account as %q", account)
	}
	if want := []string{"m", account[1], "systemd-journal"}; len(declared) != 2 || !slices.Equal(strings.Fields(declared[1]), want) {
		t.Errorf("the package declares %q, and the account reads the system journal, as a member of %s, outside its service too", declared, want[2])
	}
	settings, bundle := template(t)
	state := settings.Identity.StateDirectory
	configuration := "/etc/seagull-agent/agent.json"
	directories := strings.Split(strings.TrimSpace(asset(t, "linux/tmpfiles.conf")), "\n")
	purged := asset(t, "deb/postrm")

	for name, want := range map[string]string{
		"User":                    account[1],
		"Group":                   account[1],
		"DynamicUser":             "",
		"SupplementaryGroups":     "systemd-journal",
		"ExecStart":               "/" + agentPath + " -config " + configuration + " run",
		"StateDirectory":          path.Base(state),
		"StateDirectoryMode":      "0700",
		"NoNewPrivileges":         "yes",
		"CapabilityBoundingSet":   "",
		"AmbientCapabilities":     "",
		"ProtectSystem":           "strict",
		"ReadOnlyPaths":           "/run",
		"BindReadOnlyPaths":       "/sys",
		"ReadWritePaths":          "",
		"ProtectHome":             "yes",
		"PrivateTmp":              "yes",
		"PrivateDevices":          "yes",
		"PrivateIPC":              "yes",
		"InaccessiblePaths":       "-/dev/shm -/dev/mqueue",
		"ProtectKernelTunables":   "yes",
		"ProtectKernelModules":    "yes",
		"ProtectKernelLogs":       "yes",
		"ProtectControlGroups":    "yes",
		"ProtectClock":            "yes",
		"ProtectHostname":         "yes",
		"ProtectProc":             "invisible",
		"ProcSubset":              "",
		"PrivateUsers":            "",
		"RestrictAddressFamilies": "AF_INET AF_INET6 AF_UNIX",
		"RestrictNamespaces":      "yes",
		"RestrictRealtime":        "yes",
		"RestrictSUIDSGID":        "yes",
		"LockPersonality":         "yes",
		"MemoryDenyWriteExecute":  "yes",
		"SystemCallArchitectures": "native",
		"SystemCallFilter":        "@system-service\n~@privileged",
		"SystemCallErrorNumber":   "EPERM",
		"LimitCORE":               "0",
		"MemorySwapMax":           "0",
		"MemoryPressureWatch":     "off",
		"Restart":                 "on-failure",
	} {
		if got := service[name]; got != want {
			t.Errorf("the unit sets %s=%q, want %q", name, got, want)
		}
	}
	for _, bound := range []string{"MemoryMax", "CPUQuota", "TasksMax", "LimitNOFILE", "RestartMaxDelaySec", "TimeoutStopSec"} {
		if service[bound] == "" {
			t.Errorf("the unit leaves %s to the host", bound)
		}
	}
	if unit["Install"]["WantedBy"] != "multi-user.target" ||
		!strings.Contains(purged, "/etc/systemd/system/multi-user.target.wants/seagull-agent.service") {
		t.Error("purging the package does not remove the link that enabling the service creates")
	}

	for _, collector := range []string{"authentication", "inventory"} {
		if !settings.Modules[collector].Enabled {
			t.Errorf("the settings the package installs leave the %s collector out: %v", collector, settings.Modules)
		}
	}
	if path.Dir(state) != "/var/lib" || !slices.Contains(directories, "d "+state+" 0700 "+account[1]+" "+account[1]+" -") {
		t.Errorf("the installation is kept in %s, and the package creates %q", state, directories)
	}
	if !slices.Contains(directories, "d "+path.Dir(configuration)+" 0755 root root -") || path.Dir(bundle) != path.Dir(configuration) {
		t.Errorf("the package creates %q for a configuration at %s trusting %s", directories, configuration, bundle)
	}
	if !strings.Contains(purged, state) || !strings.Contains(purged, path.Dir(configuration)) {
		t.Errorf("purging the package leaves %s or %s", state, path.Dir(configuration))
	}

	if limit := size(t, service["MemoryMax"]); int64(settings.Resources.MemoryLimit) >= limit {
		t.Errorf("resources.memory_limit is %s by default, and the service holds the agent to %s", settings.Resources.MemoryLimit, service["MemoryMax"])
	}
	if stop, err := time.ParseDuration(service["TimeoutStopSec"]); err != nil || time.Duration(settings.Resources.ShutdownTimeout) >= stop {
		t.Errorf("resources.shutdown_timeout is %s by default, and the service waits %s for the agent to stop", settings.Resources.ShutdownTimeout, service["TimeoutStopSec"])
	}
}

func built(changed map[string]string) *debug.BuildInfo {
	settings := map[string]string{
		"-buildmode":   "exe",
		"-compiler":    "gc",
		"-trimpath":    "true",
		"CGO_ENABLED":  "0",
		"GOARCH":       "amd64",
		"GOOS":         "linux",
		"GOAMD64":      "v1",
		"vcs":          "git",
		"vcs.revision": "7d7db5969ad555287048c591dd2e991198184f46",
		"vcs.time":     "2026-09-26T00:43:46Z",
		"vcs.modified": "false",
	}
	info := &debug.BuildInfo{
		GoVersion: "go1.26.8",
		Path:      command,
		Main:      debug.Module{Path: modulePath, Version: "v0.0.0-20260926004346-7d7db5969ad5"},
	}
	for name, value := range changed {
		switch name {
		case "path":
			info.Path = value
		case "main":
			info.Main.Path = value
		case "version":
			info.Main.Version = value
		default:
			settings[name] = value
		}
	}
	for _, name := range slices.Sorted(maps.Keys(settings)) {
		if settings[name] != "" {
			info.Settings = append(info.Settings, debug.BuildSetting{Key: name, Value: settings[name]})
		}
	}
	return info
}

func packaged(t *testing.T, built release, agent []byte) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "seagull-agent")
	if err := os.WriteFile(binary, agent, 0o755); err != nil {
		t.Fatalf("write the agent: %v", err)
	}
	written, err := assemble(built, binary, t.TempDir())
	if err != nil {
		t.Fatalf("package the agent: %v", err)
	}
	return written
}

func requireDpkgDeb(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("dpkg-deb"); err != nil {
		t.Skip("dpkg-deb builds the package, and this host has none")
	}
}

type entry struct {
	mode     string
	owner    string
	modified time.Time
}

// What an archive of the package lists, as tar lists it: the mode, the owner,
// the date to the minute and the name of every entry.
func listed(t *testing.T, member, written string) map[string]entry {
	t.Helper()
	archive := output(t, "sh", "-c", `dpkg-deb "$1" "$2" | tar --numeric-owner -tvf -`, "sh", member, written)
	entries := map[string]entry{}
	lines := bufio.NewScanner(strings.NewReader(archive))
	for lines.Scan() {
		fields := strings.Fields(lines.Text())
		if len(fields) != 6 {
			t.Fatalf("read the entry %q", lines.Text())
		}
		modified, err := time.Parse("2006-01-02 15:04", fields[3]+" "+fields[4])
		if err != nil {
			t.Fatalf("read the date of %q: %v", lines.Text(), err)
		}
		entries[fields[5]] = entry{mode: fields[0], owner: fields[1], modified: modified}
	}
	return entries
}

func output(t *testing.T, name string, args ...string) string {
	t.Helper()
	command := exec.Command(name, args...)
	command.Env = []string{"LC_ALL=C", "TZ=UTC", "PATH=/usr/bin:/bin"}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	said, err := command.Output()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, stderr.String())
	}
	return string(said)
}

func asset(t *testing.T, name string) string {
	t.Helper()
	content, err := assets.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(content)
}

func sections(t *testing.T, name string) map[string]map[string]string {
	t.Helper()
	read := map[string]map[string]string{}
	var current map[string]string
	for line := range strings.Lines(asset(t, name)) {
		line = strings.TrimSpace(line)
		switch {
		case line == "" || strings.HasPrefix(line, "#"):
		case strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]"):
			current = map[string]string{}
			read[strings.Trim(line, "[]")] = current
		default:
			key, value, found := strings.Cut(line, "=")
			if !found || current == nil {
				t.Fatalf("%s holds %q", name, line)
			}
			if held, set := current[key]; set && key == "SystemCallFilter" {
				value = held + "\n" + value
			} else if set {
				t.Fatalf("%s sets %s twice", name, key)
			}
			current[key] = value
		}
	}
	return read
}

// The settings the package installs, read as the agent reads them once an
// operator has written the platform's authority where they name it, and the
// path they name for it.
func template(t *testing.T) (config.Config, string) {
	t.Helper()
	var held struct {
		Format   int            `json:"format"`
		Identity map[string]any `json:"identity"`
		Server   map[string]any `json:"server"`
		Modules  map[string]any `json:"modules"`
	}
	if err := json.Unmarshal([]byte(asset(t, "linux/agent.json")), &held); err != nil {
		t.Fatalf("read the settings the package installs: %v", err)
	}
	named, ok := held.Server["trust_bundle"].(string)
	if !ok {
		t.Fatalf("the settings the package installs name no trust bundle: %v", held.Server)
	}
	directory := filepath.Join(t.TempDir(), "etc")
	if err := os.Mkdir(directory, 0o755); err != nil {
		t.Fatalf("create %s: %v", directory, err)
	}
	held.Server["trust_bundle"] = filepath.Join(directory, "platform-ca.pem")
	authority(t, filepath.Join(directory, "platform-ca.pem"))
	rewritten, err := json.Marshal(held)
	if err != nil {
		t.Fatalf("write the settings: %v", err)
	}
	file := filepath.Join(directory, "agent.json")
	if err := os.WriteFile(file, rewritten, 0o644); err != nil {
		t.Fatalf("write %s: %v", file, err)
	}
	settings, err := config.Load(file)
	if err != nil {
		t.Fatalf("the agent refuses the settings the package installs: %v", err)
	}
	return settings, named
}

func authority(t *testing.T, bundle string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("draw the key of an authority: %v", err)
	}
	certificate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Seagull platform"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, key.Public(), key)
	if err != nil {
		t.Fatalf("sign the certificate of an authority: %v", err)
	}
	if err := os.WriteFile(bundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatalf("write %s: %v", bundle, err)
	}
}

func size(t *testing.T, value string) int64 {
	t.Helper()
	units := map[string]int64{"K": 1 << 10, "M": 1 << 20, "G": 1 << 30}
	var amount int64
	var unit string
	if _, err := fmt.Sscanf(value, "%d%s", &amount, &unit); err != nil || units[unit] == 0 {
		t.Fatalf("read the size %q", value)
	}
	return amount * units[unit]
}
