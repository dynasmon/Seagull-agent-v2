package diagnostics

import (
	"math"
	"slices"
	"strconv"
	"time"
)

const (
	MaxEntries  = 2000
	maxLogBytes = 4 << 20
	maxMessage  = 4 << 10
	information = 6
)

// Logged is an entry of the system journal as a bundle keeps it, read from the
// fields journald wrote down: when, at which priority, which process, account,
// login and command wrote it, and its message, cut to maxMessage bytes as it
// is read so that an entry the journal holds whole costs no more than that.
func Logged(cursor string, at time.Time, fields map[string]string) Entry {
	entry := Entry{At: at.UTC(), Priority: information, Command: Text(fields["_COMM"]), Message: bounded(fields["MESSAGE"], maxMessage), cursor: cursor}
	if priority, err := strconv.Atoi(fields["PRIORITY"]); err == nil && priority >= 0 && priority <= 7 {
		entry.Priority = priority
	}
	if process, err := strconv.Atoi(fields["_PID"]); err == nil && process > 0 {
		entry.Process = process
	}
	if user, err := strconv.ParseUint(fields["_UID"], 10, 32); err == nil {
		held := int(user)
		entry.User = &held
	}
	if login, err := strconv.ParseUint(fields["_AUDIT_LOGINUID"], 10, 32); err == nil && login != math.MaxUint32 {
		held := int(login)
		entry.Login = &held
	}
	return entry
}

// Kept orders entries as journald wrote them, keeps one of each the journal
// returned twice, and keeps the latest of them that fit in a bundle: at most
// MaxEntries, with maxLogBytes of messages. The second result says whether it
// kept every one.
func Kept(entries []Entry) ([]Entry, bool) {
	held := slices.Clone(entries)
	slices.SortStableFunc(held, func(a, b Entry) int { return a.At.Compare(b.At) })
	seen := make(map[string]bool, len(held))
	held = slices.DeleteFunc(held, func(entry Entry) bool {
		if entry.cursor == "" {
			return false
		}
		repeated := seen[entry.cursor]
		seen[entry.cursor] = true
		return repeated
	})
	first, spent := len(held), 0
	for first > 0 && len(held)-first < MaxEntries && spent+len(held[first-1].Message) <= maxLogBytes {
		first--
		spent += len(held[first].Message)
	}
	return held[first:], first == 0
}
