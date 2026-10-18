package machine

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

func quoted(value string) string {
	var held strings.Builder
	held.WriteByte('"')
	for _, character := range []byte(value) {
		if strings.ContainsRune("\\\"$`", rune(character)) {
			held.WriteByte('\\')
		}
		held.WriteByte(character)
	}
	held.WriteByte('"')
	return held.String()
}

// Whatever os-release holds, what reads as the release of the host is what
// writing it again, each value quoted as os-release(5) quotes it, reads as.
func FuzzRelease(f *testing.F) {
	f.Add([]byte("PRETTY_NAME=\"Ubuntu 24.04.3 LTS\"\nNAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nVERSION_CODENAME=noble\nID=ubuntu\nID_LIKE=debian\n# a comment\n\n"))
	f.Add([]byte("ID='rhel'\nID_LIKE=\"fedora centos\"\nNAME=\"Red Hat \\\"Enterprise\\\" \\$Linux\"\nBUILD_ID=rolling\n"))
	f.Add([]byte("ID=$(reboot)\n"))
	f.Add([]byte("NAME=\"unterminated\n"))
	f.Fuzz(func(t *testing.T, content []byte) {
		held, err := release(content)
		if err != nil {
			if !errors.Is(err, ErrUnreadable) || len(err.Error()) > 1<<10 {
				t.Fatalf("os-release was refused for no reason it names, or a long one: %.200v", err)
			}
			return
		}
		if strings.ContainsRune(held.ID+held.Name+held.Version+held.Codename+held.Build+strings.Join(held.Like, " "), '\n') {
			t.Fatalf("a value read holds a line break: %+v", held)
		}
		written := strings.Join([]string{"ID=" + quoted(held.ID), "ID_LIKE=" + quoted(strings.Join(held.Like, " ")), "NAME=" + quoted(held.Name),
			"VERSION_ID=" + quoted(held.Version), "VERSION_CODENAME=" + quoted(held.Codename), "BUILD_ID=" + quoted(held.Build)}, "\n")
		again, err := release([]byte(written))
		if err != nil || again.ID != held.ID || again.Name != held.Name || again.Version != held.Version || again.Codename != held.Codename ||
			again.Build != held.Build || !slices.Equal(again.Like, held.Like) {
			t.Fatalf("a release read as %+v was written as %q, which reads as %+v: %v", held, written, again, err)
		}
	})
}
