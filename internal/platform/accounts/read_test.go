package accounts

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The account database is what root and the programs root lets accounts run,
// chfn among them, wrote: whatever a file holds, every line is read as an
// account or a group or counted as skipped, and what is read is what writing
// it again as such a line reads as.
func FuzzRead(f *testing.F) {
	f.Add([]byte("root:x:0:0:root:/root:/bin/bash\nseagull-agent:x:997:997::/:/usr/sbin/nologin\n+nis\n# a comment\nnathan:x:1000:1000:Nathan,,,:/home/nathan:/bin/bash\n"),
		[]byte("root:x:0:\nsystemd-journal:x:999:seagull-agent, nathan\nbroken:x:-1:\n"))
	f.Add([]byte("toor:x:0:0::/root:/bin/sh\nx:x:4294967296:0::/:/bin/sh\n"), []byte("\x00:x:1:\n::::\n"))
	f.Fuzz(func(t *testing.T, accounts, groups []byte) {
		directory := t.TempDir()
		kept, keptGroup := passwd, group
		t.Cleanup(func() { passwd, group = kept, keptGroup })
		passwd, group = filepath.Join(directory, "passwd"), filepath.Join(directory, "group")
		for path, content := range map[string][]byte{passwd: accounts, group: groups} {
			if err := os.WriteFile(path, content, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		held, err := Read()
		if err != nil {
			t.Fatalf("an account database of %d and %d bytes could not be read: %v", len(accounts), len(groups), err)
		}
		lines := 0
		for _, content := range [][]byte{accounts, groups} {
			for line := range strings.SplitSeq(string(content), "\n") {
				if strings.TrimSpace(line) != "" {
					lines++
				}
			}
		}
		if len(held.Accounts)+len(held.Groups)+held.Skipped != lines {
			t.Fatalf("%d lines were read as %d accounts, %d groups and %d skipped", lines, len(held.Accounts), len(held.Groups), held.Skipped)
		}
		var rewritten, regrouped strings.Builder
		for _, account := range held.Accounts {
			fmt.Fprintf(&rewritten, "%s:x:%d:%d::%s:%s\n", account.Name, account.UID, account.GID, account.Home, account.Shell)
		}
		for _, member := range held.Groups {
			fmt.Fprintf(&regrouped, "%s:x:%d:%s\n", member.Name, member.GID, strings.Join(member.Members, ","))
		}
		for path, content := range map[string]string{passwd: rewritten.String(), group: regrouped.String()} {
			if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		again, err := Read()
		if err != nil || again.Skipped != 0 || !slices.EqualFunc(again.Accounts, held.Accounts, func(a, b Account) bool { return a == b }) ||
			!slices.EqualFunc(again.Groups, held.Groups, func(a, b Group) bool { return a.Name == b.Name && a.GID == b.GID && slices.Equal(a.Members, b.Members) }) {
			t.Fatalf("the accounts read were written again as a database that reads as %+v: %v", again, err)
		}
	})
}
