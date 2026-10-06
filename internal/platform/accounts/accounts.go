// Package accounts reads the accounts and groups the host keeps in its own
// files, /etc/passwd and /etc/group, laid out as passwd(5) and group(5) say.
// An account that a directory service such as LDAP holds is not in them, and
// neither are the passwords: /etc/shadow is not read.
package accounts

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/dynasmon/Seagull-agent-v2/internal/platform/files"
)

const MaxBytes = 16 << 20

var (
	passwd = "/etc/passwd"
	group  = "/etc/group"
)

var ErrUnreadable = errors.New("the host's account files cannot be read")

type Account struct {
	Name  string
	UID   uint32
	GID   uint32
	Home  string
	Shell string
}

type Group struct {
	Name    string
	GID     uint32
	Members []string
}

// What the two files hold, and how many of their lines are no account or
// group as the C library reads them: a comment, a reference to NIS, or a line
// whose fields do not read.
type Database struct {
	Accounts []Account
	Groups   []Group
	Skipped  int
}

func Read() (Database, error) {
	var held Database
	accounts, skipped, err := lines(passwd, 7, func(fields []string) (Account, bool) {
		uid, readUID := identifier(fields[2])
		gid, readGID := identifier(fields[3])
		return Account{Name: fields[0], UID: uid, GID: gid, Home: fields[5], Shell: fields[6]}, readUID && readGID
	})
	if err != nil {
		return Database{}, err
	}
	held.Accounts, held.Skipped = accounts, skipped
	groups, skipped, err := lines(group, 4, func(fields []string) (Group, bool) {
		gid, read := identifier(fields[2])
		var members []string
		for member := range strings.SplitSeq(fields[3], ",") {
			if member = strings.TrimSpace(member); member != "" {
				members = append(members, member)
			}
		}
		return Group{Name: fields[0], GID: gid, Members: members}, read
	})
	if err != nil {
		return Database{}, err
	}
	held.Groups, held.Skipped = groups, held.Skipped+skipped
	return held, nil
}

func lines[T any](path string, count int, read func([]string) (T, bool)) ([]T, int, error) {
	content, err := files.Read(path, MaxBytes)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %w", ErrUnreadable, err)
	}
	held, skipped := []T{}, 0
	for line := range strings.SplitSeq(string(content), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Split(line, ":")
		if strings.HasPrefix(strings.TrimSpace(line), "#") || line[0] == '+' || line[0] == '-' || len(fields) != count || fields[0] == "" || strings.ContainsRune(line, 0) {
			skipped++
			continue
		}
		found, ok := read(fields)
		if !ok {
			skipped++
			continue
		}
		held = append(held, found)
	}
	return held, skipped, nil
}

func identifier(written string) (uint32, bool) {
	if written == "" || strings.TrimLeft(written, "0123456789") != "" {
		return 0, false
	}
	parsed, err := strconv.ParseUint(written, 10, 32)
	return uint32(parsed), err == nil
}
