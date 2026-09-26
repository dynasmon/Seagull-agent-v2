package main

import (
	"bytes"
	"crypto/md5"
	"debug/buildinfo"
	"embed"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"time"
)

//go:embed linux deb
var assets embed.FS

const (
	packageName = "seagull-agent"
	modulePath  = "github.com/dynasmon/Seagull-agent-v2"
	command     = modulePath + "/cmd/seagull-agent"
	maintainer  = "Nathan <nathanmblima@gmail.com>"
	homepage    = "https://github.com/dynasmon/Seagull-agent-v2"
	depends     = "systemd (>= 254), procps"
	revision    = "1"
	agentPath   = "usr/bin/seagull-agent"
)

const description = `Seagull endpoint agent
 The agent observes the host it is installed on and delivers what it observed
 to the Seagull platform, durably and over mutual TLS, with a key the
 installation draws itself. The package installs it as the seagull-agent
 service, which runs as an account of its own once an operator has configured
 and enrolled it.`

var installed = []struct{ from, to string }{
	{from: "linux/seagull-agent.service", to: "usr/lib/systemd/system/seagull-agent.service"},
	{from: "linux/sysusers.conf", to: "usr/lib/sysusers.d/seagull-agent.conf"},
	{from: "linux/tmpfiles.conf", to: "usr/lib/tmpfiles.d/seagull-agent.conf"},
	{from: "linux/agent.json", to: "usr/share/seagull-agent/agent.json"},
	{from: "deb/copyright", to: "usr/share/doc/seagull-agent/copyright"},
}

var maintainerScripts = []string{"postinst", "prerm", "postrm"}

// The architectures a package is built for, and the instruction set each is
// built to, which every host of that architecture runs.
var architectures = map[string]struct{ setting, baseline string }{
	"amd64": {setting: "GOAMD64", baseline: "v1"},
	"arm64": {setting: "GOARM64", baseline: "v8.0"},
}

var semantic = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$`)

type release struct {
	version      string
	architecture string
	committed    time.Time
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("package", flag.ContinueOnError)
	flags.SetOutput(stderr)
	binary := flags.String("binary", "", "the agent, built for linux from a commit, with -trimpath and without cgo")
	out := flags.String("out", "", "the directory the package is written to")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *binary == "" || *out == "" || flags.NArg() > 0 {
		flags.Usage()
		return 2
	}
	built, err := buildinfo.ReadFile(*binary)
	if err != nil {
		fmt.Fprintf(stderr, "package: read how %s was built: %v\n", *binary, err)
		return 1
	}
	described, err := describe(built)
	if err != nil {
		fmt.Fprintf(stderr, "package: %s: %v\n", *binary, err)
		return 1
	}
	written, err := assemble(described, *binary, *out)
	if err != nil {
		fmt.Fprintf(stderr, "package: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, written)
	return 0
}

// A package is a commit of the agent built so that any host of its
// architecture runs it and nothing of the machine that built it is in it.
func describe(built *debug.BuildInfo) (release, error) {
	settings := map[string]string{}
	for _, setting := range built.Settings {
		settings[setting.Key] = setting.Value
	}
	target, supported := architectures[settings["GOARCH"]]
	switch {
	case built.Path != command || built.Main.Path != modulePath:
		return release{}, fmt.Errorf("it is %s of %s, and the package installs %s", built.Path, built.Main.Path, command)
	case settings["GOOS"] != "linux":
		return release{}, fmt.Errorf("it was built for %s, and the package installs it on linux", settings["GOOS"])
	case !supported:
		return release{}, fmt.Errorf("it was built for %s, and a package is built for %s",
			settings["GOARCH"], strings.Join(slices.Sorted(maps.Keys(architectures)), " or "))
	case settings[target.setting] != target.baseline:
		return release{}, fmt.Errorf("it was built with %s=%s, and a package runs on every %s host, which %s=%s builds for",
			target.setting, settings[target.setting], settings["GOARCH"], target.setting, target.baseline)
	case settings["CGO_ENABLED"] != "0":
		return release{}, errors.New("it was built with cgo, and the package depends on no C library")
	case settings["-trimpath"] != "true":
		return release{}, errors.New("it was built without -trimpath, so it holds paths of the machine that built it")
	case settings["vcs.revision"] == "" || settings["vcs.modified"] == "":
		return release{}, errors.New("it names no commit it was built from")
	case settings["vcs.modified"] != "false":
		return release{}, errors.New("it was built from changes no commit holds")
	}
	version, err := debianVersion(built.Main.Version)
	if err != nil {
		return release{}, err
	}
	committed, err := time.Parse(time.RFC3339, settings["vcs.time"])
	if err != nil {
		return release{}, fmt.Errorf("it names %q as the time of its commit", settings["vcs.time"])
	}
	return release{version: version, architecture: settings["GOARCH"], committed: committed.UTC()}, nil
}

// The version dpkg orders packages by. A pre-release, which is what the
// pseudo-version of a commit is too, follows a tilde, so dpkg sorts it before
// the release it leads to, as Go does.
func debianVersion(stamped string) (string, error) {
	parts := semantic.FindStringSubmatch(stamped)
	if parts == nil {
		return "", fmt.Errorf("it was built as %q, which names no release or commit of the agent", stamped)
	}
	upstream := strings.Join(parts[1:4], ".")
	if parts[4] != "" {
		upstream += "~" + strings.ReplaceAll(parts[4], "-", ".")
	}
	return upstream + "-" + revision, nil
}

// The package holds the same bytes whenever the same commit is packaged: every
// file and directory has the mode given here whatever the umask, root owns
// them, and dpkg-deb dates them no later than the commit.
func assemble(built release, binary, out string) (string, error) {
	files := map[string][]byte{}
	agent, err := os.ReadFile(binary)
	if err != nil {
		return "", fmt.Errorf("read the agent: %w", err)
	}
	files[agentPath] = agent
	for _, asset := range installed {
		content, err := assets.ReadFile(asset.from)
		if err != nil {
			return "", err
		}
		files[asset.to] = content
	}
	stage, err := os.MkdirTemp("", "seagull-agent-package-")
	if err != nil {
		return "", fmt.Errorf("stage the package: %w", err)
	}
	defer os.RemoveAll(stage)
	directories := map[string]bool{"DEBIAN": true}
	for name := range files {
		for parent := path.Dir(name); parent != "."; parent = path.Dir(parent) {
			directories[parent] = true
		}
	}
	for _, name := range slices.Sorted(maps.Keys(directories)) {
		if err := place(stage, name, nil, 0o755|fs.ModeDir); err != nil {
			return "", err
		}
	}
	if err := os.Chmod(stage, 0o755); err != nil {
		return "", fmt.Errorf("stage the package: %w", err)
	}
	var sums bytes.Buffer
	size := int64(len(directories) - 1)
	for _, name := range slices.Sorted(maps.Keys(files)) {
		mode := fs.FileMode(0o644)
		if name == agentPath {
			mode = 0o755
		}
		if err := place(stage, name, files[name], mode); err != nil {
			return "", err
		}
		fmt.Fprintf(&sums, "%x  %s\n", md5.Sum(files[name]), name)
		size += (int64(len(files[name])) + 1023) / 1024
	}
	for _, script := range maintainerScripts {
		content, err := assets.ReadFile("deb/" + script)
		if err != nil {
			return "", err
		}
		if err := place(stage, "DEBIAN/"+script, content, 0o755); err != nil {
			return "", err
		}
	}
	if err := place(stage, "DEBIAN/md5sums", sums.Bytes(), 0o644); err != nil {
		return "", err
	}
	if err := place(stage, "DEBIAN/control", control(built, size), 0o644); err != nil {
		return "", err
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		return "", fmt.Errorf("create %s: %w", out, err)
	}
	target := filepath.Join(out, fmt.Sprintf("%s_%s_%s.deb", packageName, built.version, built.architecture))
	build := exec.Command("dpkg-deb", "--root-owner-group", "-Zxz", "--build", stage, target)
	build.Env = []string{"SOURCE_DATE_EPOCH=" + strconv.FormatInt(built.committed.Unix(), 10), "LC_ALL=C", "PATH=/usr/bin:/bin"}
	if said, err := build.CombinedOutput(); err != nil {
		return "", fmt.Errorf("dpkg-deb builds the package: %w\n%s", err, bytes.TrimSpace(said))
	}
	return target, nil
}

func place(stage, name string, content []byte, mode fs.FileMode) error {
	placed := filepath.Join(stage, filepath.FromSlash(name))
	var err error
	if mode.IsDir() {
		err = os.Mkdir(placed, mode.Perm())
	} else {
		err = os.WriteFile(placed, content, mode.Perm())
	}
	if err == nil {
		err = os.Chmod(placed, mode.Perm())
	}
	if err != nil {
		return fmt.Errorf("stage %s: %w", name, err)
	}
	return nil
}

func control(built release, size int64) []byte {
	return fmt.Appendf(nil, `Package: %s
Version: %s
Architecture: %s
Maintainer: %s
Installed-Size: %d
Depends: %s
Section: admin
Priority: optional
Homepage: %s
Description: %s
`, packageName, built.version, built.architecture, maintainer, size, depends, homepage, description)
}
