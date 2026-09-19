//go:build linux

package privileges

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

const (
	status         = "/proc/self/status"
	maxStatusBytes = 16 << 10
	maxCapability  = 64
)

// The capabilities this build knows by name. A kernel that grants one it does
// not know is reported by its number rather than left out of the inventory.
var named = []string{
	"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_FOWNER", "CAP_FSETID",
	"CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_SETPCAP", "CAP_LINUX_IMMUTABLE",
	"CAP_NET_BIND_SERVICE", "CAP_NET_BROADCAST", "CAP_NET_ADMIN", "CAP_NET_RAW", "CAP_IPC_LOCK",
	"CAP_IPC_OWNER", "CAP_SYS_MODULE", "CAP_SYS_RAWIO", "CAP_SYS_CHROOT", "CAP_SYS_PTRACE",
	"CAP_SYS_PACCT", "CAP_SYS_ADMIN", "CAP_SYS_BOOT", "CAP_SYS_NICE", "CAP_SYS_RESOURCE",
	"CAP_SYS_TIME", "CAP_SYS_TTY_CONFIG", "CAP_MKNOD", "CAP_LEASE", "CAP_AUDIT_WRITE",
	"CAP_AUDIT_CONTROL", "CAP_SETFCAP", "CAP_MAC_OVERRIDE", "CAP_MAC_ADMIN", "CAP_SYSLOG",
	"CAP_WAKE_ALARM", "CAP_BLOCK_SUSPEND", "CAP_AUDIT_READ", "CAP_PERFMON", "CAP_BPF",
	"CAP_CHECKPOINT_RESTORE",
}

func capabilities() ([]string, bool, error) {
	file, err := os.Open(status)
	if err != nil {
		return nil, false, fmt.Errorf("read what the agent may do: %w", err)
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, maxStatusBytes))
	if err != nil {
		return nil, false, fmt.Errorf("read %s: %w", status, err)
	}
	held, bounded, err := described(string(content))
	if err != nil {
		return nil, false, fmt.Errorf("read %s: %v", status, err)
	}
	return held, bounded, nil
}

func described(content string) ([]string, bool, error) {
	var granted uint64
	var bounded bool
	read := map[string]bool{}
	for line := range strings.Lines(content) {
		name, written, held := strings.Cut(line, ":")
		if !held {
			continue
		}
		written = strings.TrimSpace(written)
		switch name {
		case "CapPrm", "CapEff":
			mask, err := strconv.ParseUint(written, 16, 64)
			if err != nil {
				return nil, false, fmt.Errorf("%s is %q, and a capability set is 64 bits in hexadecimal", name, written)
			}
			granted, read[name] = granted|mask, true
		case "NoNewPrivs":
			bounded, read[name] = written == "1", true
		}
	}
	for _, name := range []string{"CapPrm", "CapEff", "NoNewPrivs"} {
		if !read[name] {
			return nil, false, fmt.Errorf("it does not say %s, so what the agent may do is unknown", name)
		}
	}
	return names(granted), bounded, nil
}

func names(granted uint64) []string {
	held := []string{}
	for capability := range maxCapability {
		switch {
		case granted&(1<<capability) == 0:
		case capability < len(named):
			held = append(held, named[capability])
		default:
			held = append(held, fmt.Sprintf("cap(%d)", capability))
		}
	}
	return held
}
