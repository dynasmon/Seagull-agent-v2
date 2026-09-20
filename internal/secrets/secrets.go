// Package secrets decides what the agent writes down about what it reads. Text
// that came out of a file, a URL or an answer reaches a log, an error or the
// terminal only through here: cut to what one message may carry, escaped where
// it is not printable, and without whatever credentials it happened to hold.
package secrets

import (
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	maxShownBytes = 96
	cut           = "..."
	withheld      = "(redacted)"
)

// Bounded is text the agent read as a message may carry it.
func Bounded(text string) string {
	held, bounded := hold(text)
	if !printable(held) {
		held = strconv.Quote(held)
	}
	if bounded {
		return held + cut
	}
	return held
}

// Shown is a value the agent read as a message may carry it, quoted so that
// what it holds, and where it ends, belong to the message.
func Shown(value string) string {
	held, bounded := hold(value)
	quoted := strconv.Quote(held)
	if bounded {
		return quoted + cut
	}
	return quoted
}

// Address is a URL the agent read as a message may carry it: whoever wrote a
// user and a password into it wrote a credential, and the address a message
// names is a listener alone.
func Address(raw string) string { return Shown(withoutCredentials(raw)) }

func hold(text string) (string, bool) {
	if len(text) <= maxShownBytes {
		return text, false
	}
	held := text[:maxShownBytes]
	for range utf8.UTFMax - 1 {
		if last, width := utf8.DecodeLastRuneInString(held); last != utf8.RuneError || width > 1 {
			break
		}
		held = held[:len(held)-1]
	}
	return held, true
}

func printable(held string) bool {
	return utf8.ValidString(held) && strings.IndexFunc(held, func(held rune) bool { return !unicode.IsPrint(held) }) < 0
}

func withoutCredentials(raw string) string {
	scheme, rest, found := strings.Cut(raw, "//")
	if !found {
		return raw
	}
	authority := rest
	if ends := strings.IndexAny(rest, "/?#"); ends >= 0 {
		authority = rest[:ends]
	}
	written := strings.LastIndex(authority, "@")
	if written < 0 {
		return raw
	}
	return scheme + "//" + withheld + "@" + rest[written+1:]
}
