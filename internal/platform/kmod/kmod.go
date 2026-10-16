// Package kmod reads which modules the running kernel holds, as /proc/modules
// and /sys/module show them to any account, and what the host's modprobe
// configuration says of loading one, read from the directories modprobe.d(5)
// names the way kmod reads them.
package kmod

import (
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/dynasmon/Seagull-agent-v2/internal/platform/files"
	"github.com/dynasmon/Seagull-agent-v2/internal/secrets"
)

const (
	MaxBytes      = 1 << 20
	MaxFileBytes  = 256 << 10
	MaxFiles      = 512
	maxModuleName = 55
)

var (
	modules     = "/proc/modules"
	sysModule   = "/sys/module"
	directories = []string{"/etc/modprobe.d", "/run/modprobe.d", "/usr/local/lib/modprobe.d", "/usr/lib/modprobe.d", "/lib/modprobe.d"}
)

var moduleName = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

var (
	ErrMalformed  = errors.New("the module is not named as the kernel names one")
	ErrUnreadable = errors.New("what the kernel or modprobe says of its modules cannot be read")
)

type State int

const (
	Absent State = iota
	Loaded
	BuiltIn
)

func (s State) String() string {
	switch s {
	case Loaded:
		return "loaded"
	case BuiltIn:
		return "built into the kernel"
	default:
		return "not loaded"
	}
}

func Name(name string) (string, error) {
	if len(name) > maxModuleName || !moduleName.MatchString(name) {
		return "", fmt.Errorf("%w: %s", ErrMalformed, secrets.Shown(name))
	}
	return strings.ReplaceAll(name, "-", "_"), nil
}

type Kernel struct {
	loaded map[string]bool
}

func ReadKernel() (Kernel, error) {
	content, err := files.Read(modules, MaxBytes)
	if err != nil {
		return Kernel{}, fmt.Errorf("%w: %w", ErrUnreadable, err)
	}
	held := Kernel{loaded: map[string]bool{}}
	for line := range strings.SplitSeq(string(content), "\n") {
		if fields := strings.Fields(line); len(fields) > 0 {
			held.loaded[fields[0]] = true
		}
	}
	return held, nil
}

// State says whether the kernel holds a module: loaded, as /proc/modules lists
// it, or built into it, which /sys/module shows of a module that has
// parameters. A module built in with none shows nowhere an account other than
// root can read, and reads as absent.
func (k Kernel) State(name string) (State, error) {
	normal, err := Name(name)
	if err != nil {
		return Absent, err
	}
	if k.loaded[normal] {
		return Loaded, nil
	}
	described, err := os.Lstat(filepath.Join(sysModule, normal))
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return Absent, nil
	case err != nil:
		return Absent, fmt.Errorf("%w: %w", ErrUnreadable, err)
	case !described.IsDir():
		return Absent, nil
	}
	if _, err := os.Lstat(filepath.Join(sysModule, normal, "initstate")); err == nil {
		return Loaded, nil
	}
	return BuiltIn, nil
}

type Rule struct {
	Module  string
	Command string
	File    string
	Line    int
}

type Configuration struct {
	install   []Rule
	blacklist []Rule
}

// ReadConfiguration reads every .conf and .alias file of the directories
// modprobe.d(5) names, a file of a directory listed earlier standing in for
// one of the same name further down, in the order of their names, as kmod
// does. A file it cannot read leaves the configuration unknown.
func ReadConfiguration() (Configuration, error) {
	chosen := map[string]string{}
	for _, directory := range directories {
		entries, err := os.ReadDir(directory)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			continue
		case err != nil:
			return Configuration{}, fmt.Errorf("%w: %w", ErrUnreadable, err)
		}
		for _, entry := range entries {
			name := entry.Name()
			if strings.HasPrefix(name, ".") || (!strings.HasSuffix(name, ".conf") && !strings.HasSuffix(name, ".alias")) || entry.IsDir() {
				continue
			}
			if _, held := chosen[name]; !held {
				chosen[name] = filepath.Join(directory, name)
			}
		}
	}
	if len(chosen) > MaxFiles {
		return Configuration{}, fmt.Errorf("%w: the modprobe configuration is spread over %d files, and the agent reads %d", ErrUnreadable, len(chosen), MaxFiles)
	}
	var held Configuration
	for _, name := range slices.Sorted(maps.Keys(chosen)) {
		content, err := files.Read(chosen[name], MaxFileBytes)
		if err != nil {
			return Configuration{}, fmt.Errorf("%w: %w", ErrUnreadable, err)
		}
		held.read(chosen[name], string(content))
	}
	return held, nil
}

func (c *Configuration) read(file, content string) {
	number, joined, first := 0, "", 0
	for line := range strings.SplitSeq(content, "\n") {
		number++
		if joined == "" {
			first = number
		}
		if continued, wrapped := strings.CutSuffix(line, "\\"); wrapped {
			joined += continued
			continue
		}
		joined += line
		c.rule(file, first, joined)
		joined = ""
	}
	if joined != "" {
		c.rule(file, first, joined)
	}
}

func (c *Configuration) rule(file string, number int, line string) {
	fields := strings.Fields(line)
	if len(fields) < 2 || strings.HasPrefix(fields[0], "#") {
		return
	}
	module := underscores(fields[1])
	switch fields[0] {
	case "install":
		if len(fields) > 2 {
			c.install = append(c.install, Rule{Module: module, Command: strings.Join(fields[2:], " "), File: file, Line: number})
		}
	case "blacklist":
		c.blacklist = append(c.blacklist, Rule{Module: module, File: file, Line: number})
	}
}

// Install is the first install line naming the module, which is the one
// modprobe follows whoever asks for the module, by name or by alias, and runs
// instead of loading it. Refuses says whether such a command keeps the module
// out: one that runs nothing but /bin/false or /bin/true.
func (c Configuration) Install(name string) (Rule, bool) {
	normal, err := Name(name)
	if err != nil {
		return Rule{}, false
	}
	for _, rule := range c.install {
		if matched, err := path.Match(rule.Module, normal); err == nil && matched {
			return rule, true
		}
	}
	return Rule{}, false
}

func (c Configuration) Blacklisted(name string) (Rule, bool) {
	normal, err := Name(name)
	if err != nil {
		return Rule{}, false
	}
	for _, rule := range c.blacklist {
		if rule.Module == normal {
			return rule, true
		}
	}
	return Rule{}, false
}

func Refuses(command string) bool {
	fields := strings.Fields(command)
	if len(fields) == 0 || !slices.Contains([]string{"/bin/false", "/bin/true", "/usr/bin/false", "/usr/bin/true"}, fields[0]) {
		return false
	}
	return len(fields) == 1 || strings.HasPrefix(fields[1], "#")
}

func underscores(name string) string {
	var built strings.Builder
	bracketed := false
	for _, r := range name {
		switch {
		case r == '[':
			bracketed = true
		case r == ']':
			bracketed = false
		case r == '-' && !bracketed:
			r = '_'
		}
		built.WriteRune(r)
	}
	return built.String()
}
