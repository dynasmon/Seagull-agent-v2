package accounts

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"

	"github.com/dynasmon/Seagull-agent-v2/internal/platform/files"
)

func held(t *testing.T, accounts, groups string) {
	t.Helper()
	directory := t.TempDir()
	heldPasswd, heldGroup := passwd, group
	passwd, group = filepath.Join(directory, "passwd"), filepath.Join(directory, "group")
	t.Cleanup(func() { passwd, group = heldPasswd, heldGroup })
	for path, content := range map[string]string{passwd: accounts, group: groups} {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestTheAccountsAndGroupsTheHostKeepsAreRead(t *testing.T) {
	held(t, "root:x:0:0:root:/root:/bin/bash\n"+
		"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"+
		"seagull-agent:x:997:997:Seagull endpoint agent:/:/usr/sbin/nologin\n"+
		"toor:x:0:0::/root:/bin/sh",
		"root:x:0:\nsudo:x:27:alice, bob,\nsystemd-journal:x:999:seagull-agent\nseagull-agent:x:997:\n")
	read, err := Read()
	if err != nil {
		t.Fatal(err)
	}
	want := Database{
		Accounts: []Account{
			{Name: "root", Home: "/root", Shell: "/bin/bash"},
			{Name: "daemon", UID: 1, GID: 1, Home: "/usr/sbin", Shell: "/usr/sbin/nologin"},
			{Name: "seagull-agent", UID: 997, GID: 997, Home: "/", Shell: "/usr/sbin/nologin"},
			{Name: "toor", Home: "/root", Shell: "/bin/sh"},
		},
		Groups: []Group{
			{Name: "root"},
			{Name: "sudo", GID: 27, Members: []string{"alice", "bob"}},
			{Name: "systemd-journal", GID: 999, Members: []string{"seagull-agent"}},
			{Name: "seagull-agent", GID: 997},
		},
	}
	if !slices.EqualFunc(read.Accounts, want.Accounts, func(a, b Account) bool { return a == b }) ||
		!slices.EqualFunc(read.Groups, want.Groups, func(a, b Group) bool {
			return a.Name == b.Name && a.GID == b.GID && slices.Equal(a.Members, b.Members)
		}) || read.Skipped != 0 {
		t.Errorf("the host keeps\n%+v\nwant\n%+v", read, want)
	}
}

func TestALineThatIsNoAccountIsCountedAndLeftOut(t *testing.T) {
	held(t, "root:x:0:0:root:/root:/bin/bash\n"+
		"# a comment\n"+
		"+@netgroup::::::\n"+
		"-excluded::::::\n"+
		"short:x:1000:1000\n"+
		"long:x:1000:1000:a:b:c:d\n"+
		":x:1001:1001::/home/none:/bin/sh\n"+
		"letters:x:one:1001::/home/letters:/bin/sh\n"+
		"negative:x:-1:1001::/home/negative:/bin/sh\n"+
		"huge:x:4294967296:1001::/home/huge:/bin/sh\n"+
		"nul:x:1002:1002::/home/n\x00ul:/bin/sh\n"+
		"\n   \n"+
		"last:x:4294967295:1003::/home/last:/bin/sh\n",
		"root:x:0:\nbroken:x:\nwords:x:twelve:alice\n")
	read, err := Read()
	if err != nil {
		t.Fatal(err)
	}
	if len(read.Accounts) != 2 || read.Accounts[1] != (Account{Name: "last", UID: 4294967295, GID: 1003, Home: "/home/last", Shell: "/bin/sh"}) ||
		len(read.Groups) != 1 || read.Skipped != 12 {
		t.Errorf("the host keeps %+v", read)
	}
}

func TestAccountFilesThatCannotBeReadAreNoEmptyDatabase(t *testing.T) {
	held(t, "root:x:0:0:root:/root:/bin/bash\n", "root:x:0:\n")
	if err := os.Remove(group); err != nil {
		t.Fatal(err)
	}
	if read, err := Read(); !errors.Is(err, ErrUnreadable) || !errors.Is(err, fs.ErrNotExist) || read.Accounts != nil {
		t.Errorf("a host with no group file was read as %+v and %v", read, err)
	}
	if err := os.WriteFile(group, make([]byte, MaxBytes+1), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(); !errors.Is(err, ErrUnreadable) || !errors.Is(err, files.ErrTooLarge) {
		t.Errorf("a group file over the bound was read as %v", err)
	}
}

func TestTheAccountsOfThisHostAreRead(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the agent reads the account files of linux hosts")
	}
	read, err := Read()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(read.Accounts, func(held Account) bool { return held.Name == "root" && held.UID == 0 }) ||
		!slices.ContainsFunc(read.Groups, func(held Group) bool { return held.Name == "root" && held.GID == 0 }) {
		t.Errorf("this host keeps %+v", read)
	}
}
