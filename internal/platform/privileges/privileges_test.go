package privileges_test

import (
	"os"
	"runtime"
	"slices"
	"testing"

	"github.com/dynasmon/Seagull-agent-v2/internal/platform/privileges"
)

func TestWhatTheProcessMayDoIsWhatTheAccountRunningItMayDo(t *testing.T) {
	held, err := privileges.Held()
	if err != nil {
		t.Fatalf("read what this process may do: %v", err)
	}
	if held.User != os.Geteuid() || held.Group != os.Getegid() {
		t.Fatalf("the process runs as uid %d in gid %d, and it reports uid %d in gid %d",
			os.Geteuid(), os.Getegid(), held.User, held.Group)
	}
	groups, err := os.Getgroups()
	if err != nil {
		t.Fatalf("read the groups of this process: %v", err)
	}
	slices.Sort(groups)
	if !slices.Equal(held.Groups, groups) {
		t.Errorf("the process belongs to %v, and it reports %v", groups, held.Groups)
	}
	if runtime.GOOS == "linux" && os.Geteuid() != 0 && len(held.Capabilities) > 0 {
		t.Errorf("an unprivileged process reports the capabilities %v", held.Capabilities)
	}
	if runtime.GOOS == "linux" && os.Geteuid() == 0 && len(held.Capabilities) == 0 {
		t.Error("the superuser reports no capability at all")
	}
	if held.Seccomp == "" {
		t.Error("the process says nothing of how the kernel filters its system calls")
	}
}

func TestWhatTheAgentMayDoBeyondWhatItNeeds(t *testing.T) {
	cases := map[string]struct {
		held   privileges.Privileges
		needed []string
		beyond []string
	}{
		"an account of its own": {
			held: privileges.Privileges{User: 987, Group: 987},
		},
		"the superuser": {
			held:   privileges.Privileges{User: 0, Group: 0},
			beyond: []string{"superuser"},
		},
		"a capability nothing needs": {
			held:   privileges.Privileges{User: 987, Capabilities: []string{"CAP_DAC_READ_SEARCH", "CAP_NET_RAW"}},
			needed: []string{"CAP_DAC_READ_SEARCH"},
			beyond: []string{"CAP_NET_RAW"},
		},
		"the capability a collector was given": {
			held:   privileges.Privileges{User: 987, Capabilities: []string{"CAP_DAC_READ_SEARCH"}},
			needed: []string{"CAP_DAC_READ_SEARCH"},
		},
		"the superuser holding everything": {
			held:   privileges.Privileges{User: 0, Capabilities: []string{"CAP_SYS_ADMIN"}},
			needed: []string{"CAP_SYS_ADMIN"},
			beyond: []string{"superuser"},
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if beyond := c.held.Beyond(c.needed); !slices.Equal(beyond, c.beyond) {
				t.Fatalf("%v is beyond what the agent needs, want %v", beyond, c.beyond)
			}
		})
	}
}
