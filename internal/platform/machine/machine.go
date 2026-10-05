// Package machine describes the machine the agent runs on: the distribution
// it runs, as os-release(5) describes it; the kernel it booted, as uname
// reports it; and what it is made of, as procfs and sysfs show it to an
// account that is not the superuser, which the firmware's serial number is not.
package machine

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/dynasmon/Seagull-agent-v2/internal/platform/files"
	"github.com/dynasmon/Seagull-agent-v2/internal/secrets"
)

const (
	maxRelease = 64 << 10
	maxProc    = 4 << 20
	maxValue   = 4 << 10
)

var (
	releases = []string{"/etc/os-release", "/usr/lib/os-release"}
	proc     = "/proc"
	sys      = "/sys"
)

var (
	ErrUnreadable = errors.New("what the host says of itself cannot be read")
	keyPattern    = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
	cpuPattern    = regexp.MustCompile(`^cpu[0-9]+$`)
)

type Release struct {
	ID       string
	Like     []string
	Name     string
	Version  string
	Codename string
	Build    string
}

type Kernel struct {
	Name    string
	Release string
	Version string
	Machine string
}

// Hardware is what the machine is made of, each part empty or zero where the
// host does not say: Cores counts the cores the processors have, whatever
// threads each runs, and MHz is the fastest a processor runs as cpufreq says,
// or else the speed procfs reports.
type Hardware struct {
	CPU    string
	Cores  uint32
	MHz    uint32
	Memory uint64
	Vendor string
	Model  string
}

func Distribution() (Release, error) {
	for _, path := range releases {
		content, err := files.Read(path, maxRelease)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return Release{}, fmt.Errorf("%w: %w", ErrUnreadable, err)
		}
		return release(content)
	}
	return Release{}, fmt.Errorf("%w: neither %s is there", ErrUnreadable, strings.Join(releases, " nor "))
}

func release(content []byte) (Release, error) {
	values := map[string]string{}
	scanner := bufio.NewScanner(strings.NewReader(string(content)))
	scanner.Buffer(nil, maxRelease)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, written, assigned := strings.Cut(line, "=")
		value, read := unquoted(written)
		if !assigned || !keyPattern.MatchString(key) || !read {
			return Release{}, fmt.Errorf("%w: os-release holds %s", ErrUnreadable, secrets.Shown(line))
		}
		values[key] = value
	}
	if err := scanner.Err(); err != nil {
		return Release{}, fmt.Errorf("%w: %w", ErrUnreadable, err)
	}
	held := Release{ID: values["ID"], Like: strings.Fields(values["ID_LIKE"]), Name: values["NAME"], Version: values["VERSION_ID"], Codename: values["VERSION_CODENAME"], Build: values["BUILD_ID"]}
	if held.ID == "" {
		held.ID = "linux"
	}
	if held.Name == "" {
		held.Name = "Linux"
	}
	return held, nil
}

func unquoted(written string) (string, bool) {
	switch {
	case len(written) >= 2 && written[0] == '\'' && written[len(written)-1] == '\'':
		inner := written[1 : len(written)-1]
		return inner, !strings.Contains(inner, "'")
	case len(written) >= 2 && written[0] == '"' && written[len(written)-1] == '"':
		var held strings.Builder
		inner := written[1 : len(written)-1]
		for i := 0; i < len(inner); i++ {
			switch character := inner[i]; {
			case character == '\\' && i+1 < len(inner) && strings.ContainsRune("\\\"$`", rune(inner[i+1])):
				held.WriteByte(inner[i+1])
				i++
			case character == '"' || character == '`' || character == '$' || character == '\\':
				return "", false
			default:
				held.WriteByte(character)
			}
		}
		return held.String(), true
	}
	return written, !strings.ContainsAny(written, " \t\"'`$\\")
}

func Described() (Hardware, error) {
	var held Hardware
	cpuinfo, err := files.Read(filepath.Join(proc, "cpuinfo"), maxProc)
	if err != nil {
		return Hardware{}, fmt.Errorf("%w: %w", ErrUnreadable, err)
	}
	var running float64
	for line := range strings.SplitSeq(string(cpuinfo), "\n") {
		key, value, found := strings.Cut(line, ":")
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		switch {
		case !found:
		case key == "model name" && held.CPU == "":
			held.CPU = value
		case key == "cpu MHz" && running == 0:
			if parsed, err := strconv.ParseFloat(value, 64); err == nil && parsed > 0 && parsed < math.MaxUint32 {
				running = parsed
			}
		}
	}
	meminfo, err := files.Read(filepath.Join(proc, "meminfo"), maxProc)
	if err != nil {
		return Hardware{}, fmt.Errorf("%w: %w", ErrUnreadable, err)
	}
	for line := range strings.SplitSeq(string(meminfo), "\n") {
		if amount, found := strings.CutPrefix(line, "MemTotal:"); found {
			kib, err := strconv.ParseUint(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(amount), "kB")), 10, 64)
			if err != nil || kib > math.MaxUint64/1024 {
				return Hardware{}, fmt.Errorf("%w: /proc/meminfo says %s", ErrUnreadable, secrets.Shown(line))
			}
			held.Memory = kib * 1024
		}
	}
	held.MHz = uint32(math.Round(running))
	if fastest, read := value(filepath.Join(sys, "devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq")); read {
		if khz, err := strconv.ParseUint(fastest, 10, 64); err == nil && khz/1000 > 0 && khz/1000 < math.MaxUint32 {
			held.MHz = uint32(khz / 1000)
		}
	}
	held.Cores = cores()
	held.Vendor, _ = value(filepath.Join(sys, "class/dmi/id/sys_vendor"))
	held.Model, _ = value(filepath.Join(sys, "class/dmi/id/product_name"))
	return held, nil
}

func cores() uint32 {
	entries, err := filepath.Glob(filepath.Join(sys, "devices/system/cpu/cpu*"))
	if err != nil {
		return 0
	}
	siblings := map[string]bool{}
	for _, entry := range entries {
		if !cpuPattern.MatchString(filepath.Base(entry)) {
			continue
		}
		shared, read := value(filepath.Join(entry, "topology/core_cpus_list"))
		if !read {
			shared, read = value(filepath.Join(entry, "topology/thread_siblings_list"))
		}
		if read {
			siblings[shared] = true
		}
	}
	return uint32(len(siblings))
}

func value(path string) (string, bool) {
	content, err := files.Read(path, maxValue)
	if err != nil {
		return "", false
	}
	held := strings.TrimSpace(string(content))
	return held, held != ""
}
