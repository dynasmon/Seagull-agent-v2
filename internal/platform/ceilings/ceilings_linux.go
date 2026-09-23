//go:build linux

package ceilings

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path"
	"strconv"
	"strings"
	"syscall"
)

const (
	membership   = "/proc/self/cgroup"
	hierarchy    = "/sys/fs/cgroup"
	maxFileBytes = 4 << 10
	maxShown     = 32
)

func Enforced() (Ceilings, error) {
	var descriptors syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &descriptors); err != nil {
		return Ceilings{}, fmt.Errorf("read how many descriptors the agent may open: %w", err)
	}
	file, err := os.Open(membership)
	if err != nil {
		return Ceilings{}, fmt.Errorf("read which cgroup the agent runs in: %w", err)
	}
	content, err := bounded(file)
	file.Close()
	if err != nil {
		return Ceilings{}, fmt.Errorf("read %s: %w", membership, err)
	}
	root, err := os.OpenRoot(hierarchy)
	if err != nil {
		return Ceilings{}, fmt.Errorf("open the cgroup hierarchy: %w", err)
	}
	defer root.Close()
	found, err := enforced(string(content), root)
	if err != nil {
		return Ceilings{}, err
	}
	if descriptors.Cur <= math.MaxInt64 {
		found.Descriptors = int64(descriptors.Cur)
	}
	return found, nil
}

// A cgroup is bounded by its own limits and by those of every cgroup above it,
// so each ceiling is the tightest one on the way from the agent's cgroup up to
// the root of the hierarchy the agent sees. A limit file a level lacks is a
// controller that level does not use, and bounds nothing there.
func enforced(content string, root *os.Root) (Ceilings, error) {
	leaf, err := member(content)
	if err != nil {
		return Ceilings{}, err
	}
	if _, err := root.Stat("cgroup.controllers"); err != nil {
		return Ceilings{}, fmt.Errorf("%s holds no cgroup v2 hierarchy, so what it enforces is unknown: %w", root.Name(), err)
	}
	var found Ceilings
	for level := leaf; ; level = path.Dir(level) {
		described, err := root.Stat(level)
		switch {
		case err != nil:
			return Ceilings{}, fmt.Errorf("inspect the cgroup %s: %w", shown(level), err)
		case !described.IsDir():
			return Ceilings{}, fmt.Errorf("the cgroup %s is not a directory", shown(level))
		}
		memory, err := quantity(root, level, "memory.max")
		if err != nil {
			return Ceilings{}, err
		}
		tasks, err := quantity(root, level, "pids.max")
		if err != nil {
			return Ceilings{}, err
		}
		cpus, err := processors(root, level)
		if err != nil {
			return Ceilings{}, err
		}
		found.Memory, found.Tasks = tighter(found.Memory, memory), tighter(found.Tasks, tasks)
		if cpus > 0 && (found.CPUs == 0 || cpus < found.CPUs) {
			found.CPUs = cpus
		}
		if level == "." {
			return found, nil
		}
	}
}

func member(content string) (string, error) {
	for line := range strings.Lines(content) {
		written, unified := strings.CutPrefix(strings.TrimSuffix(line, "\n"), "0::")
		if !unified {
			continue
		}
		if !strings.HasPrefix(written, "/") || path.Clean(written) != written {
			return "", fmt.Errorf("%s names the cgroup %s, which is not a path to one", membership, shown(written))
		}
		if written == "/" {
			return ".", nil
		}
		return strings.TrimPrefix(written, "/"), nil
	}
	return "", errors.New("the agent runs in no cgroup of a v2 hierarchy, so what it enforces is unknown")
}

func quantity(root *os.Root, level, name string) (int64, error) {
	written, err := limit(root, level, name)
	if err != nil || written == "" || written == "max" {
		return 0, err
	}
	value, err := strconv.ParseInt(written, 10, 64)
	if err != nil || value < 1 {
		return 0, fmt.Errorf("the cgroup %s says %s is %s", shown(level), name, shown(written))
	}
	return value, nil
}

func processors(root *os.Root, level string) (float64, error) {
	written, err := limit(root, level, "cpu.max")
	if err != nil || written == "" {
		return 0, err
	}
	quota, period, paired := strings.Cut(written, " ")
	if paired && quota == "max" {
		return 0, nil
	}
	allowed, err := strconv.ParseInt(quota, 10, 64)
	each, perr := strconv.ParseInt(period, 10, 64)
	if !paired || err != nil || perr != nil || allowed < 1 || each < 1 {
		return 0, fmt.Errorf("the cgroup %s says cpu.max is %s", shown(level), shown(written))
	}
	return float64(allowed) / float64(each), nil
}

func limit(root *os.Root, level, name string) (string, error) {
	file, err := root.Open(path.Join(level, name))
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read %s of the cgroup %s: %w", name, shown(level), err)
	}
	defer file.Close()
	content, err := bounded(file)
	if err != nil {
		return "", fmt.Errorf("read %s of the cgroup %s: %w", name, shown(level), err)
	}
	return strings.TrimSpace(string(content)), nil
}

func bounded(file *os.File) ([]byte, error) {
	content, err := io.ReadAll(io.LimitReader(file, maxFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(content) > maxFileBytes {
		return nil, fmt.Errorf("it holds more than %d bytes", maxFileBytes)
	}
	return content, nil
}

func tighter(held, found int64) int64 {
	if found > 0 && (held == 0 || found < held) {
		return found
	}
	return held
}

func shown(written string) string {
	if len(written) > maxShown {
		written = written[:maxShown] + "..."
	}
	return strconv.Quote(written)
}
