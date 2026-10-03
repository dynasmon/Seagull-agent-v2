package privileges

import (
	"errors"
	"fmt"
	"os"
	"slices"
)

var ErrInconsistent = errors.New("the agent runs as more than one account")

// What the process the agent runs in may do: the account it runs as, the
// groups that account belongs to, the Linux capabilities it holds, and how the
// kernel filters the system calls it makes. Every module runs in that process
// and may do all of it; a goroutine bounds a lifecycle and never a privilege.
type Privileges struct {
	User         int
	Group        int
	Groups       []int
	Capabilities []string
	NoNewPrivs   bool
	Seccomp      string
}

// Held describes the running process, and refuses to describe one whose real
// and effective accounts differ: an agent started through a setuid or setgid
// program cannot say which account its state, its keys and its settings belong
// to, and its packaging never starts it that way.
func Held() (Privileges, error) {
	user, group := os.Geteuid(), os.Getegid()
	if started := os.Getuid(); started != user {
		return Privileges{}, fmt.Errorf("%w: uid %d started it and it runs as uid %d", ErrInconsistent, started, user)
	}
	if started := os.Getgid(); started != group {
		return Privileges{}, fmt.Errorf("%w: gid %d started it and it runs in gid %d", ErrInconsistent, started, group)
	}
	groups, err := os.Getgroups()
	if err != nil {
		return Privileges{}, fmt.Errorf("read the groups the agent belongs to: %w", err)
	}
	slices.Sort(groups)
	held, err := granted()
	if err != nil {
		return Privileges{}, err
	}
	held.User, held.Group, held.Groups = user, group, groups
	return held, nil
}

// Beyond names what the process may do that nothing the agent does needs:
// being the superuser, and every capability it holds that needed leaves out.
func (p Privileges) Beyond(needed []string) []string {
	var extra []string
	if p.User == 0 {
		extra = append(extra, "superuser")
	}
	for _, held := range p.Capabilities {
		if !slices.Contains(needed, held) {
			extra = append(extra, held)
		}
	}
	return extra
}
