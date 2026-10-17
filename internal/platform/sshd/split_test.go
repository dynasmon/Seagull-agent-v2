package sshd

import (
	"slices"
	"strings"
	"testing"
)

func written(argument string) string {
	var held strings.Builder
	held.WriteByte('"')
	for _, character := range []byte(argument) {
		if character == '"' || character == '\\' {
			held.WriteByte('\\')
		}
		held.WriteByte(character)
	}
	held.WriteByte('"')
	return held.String()
}

// Whatever a line of the configuration holds, the keyword and the arguments
// read from it are what writing them again, each argument quoted, reads as.
func FuzzSplit(f *testing.F) {
	for _, seed := range []string{"PermitRootLogin no", "  Match User \"svc account\" Address 10.0.0.0/8 # comment", "AllowUsers=alice 'bob smith' carol\\ dee",
		"Banner \"unterminated", "#PasswordAuthentication yes", "KbdInteractiveAuthentication", "Subsystem\tsftp\t/usr/lib/openssh/sftp-server\r"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, line string) {
		keyword, arguments, err := split(line)
		if err != nil || keyword == "" {
			return
		}
		if strings.ContainsAny(keyword, " \t=") || strings.HasPrefix(keyword, "#") || len(arguments) == 0 {
			t.Fatalf("%q was read as keyword %q with %q", line, keyword, arguments)
		}
		quoted := make([]string, len(arguments))
		for i, argument := range arguments {
			if strings.ContainsAny(argument, "\n") {
				return
			}
			quoted[i] = written(argument)
		}
		again := keyword + " " + strings.Join(quoted, " ")
		rekeyword, reargued, err := split(again)
		if err != nil || rekeyword != keyword || !slices.Equal(reargued, arguments) {
			t.Fatalf("%q was read as %q %q, written again as %q, which reads as %q %q: %v", line, keyword, arguments, again, rekeyword, reargued, err)
		}
	})
}
