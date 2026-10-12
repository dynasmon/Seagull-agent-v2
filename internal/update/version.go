package update

import (
	"strconv"
	"strings"
)

// A release as the agent binary names itself: a semantic version with Go's
// leading `v`, ordered by semantic version precedence, where build metadata
// orders nothing.
type Version struct {
	major, minor, patch uint64
	prerelease          []string
	text                string
}

func ParseVersion(text string) (Version, bool) {
	if len(text) > MaxVersionLength || !strings.HasPrefix(text, "v") {
		return Version{}, false
	}
	rest, build, built := strings.Cut(text[1:], "+")
	if built && !identifiers(build, false) {
		return Version{}, false
	}
	core, prerelease, released := strings.Cut(rest, "-")
	if released && !identifiers(prerelease, true) {
		return Version{}, false
	}
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return Version{}, false
	}
	var numbers [3]uint64
	for index, part := range parts {
		number, ok := numeric(part)
		if !ok {
			return Version{}, false
		}
		numbers[index] = number
	}
	parsed := Version{major: numbers[0], minor: numbers[1], patch: numbers[2], text: text}
	if released {
		parsed.prerelease = strings.Split(prerelease, ".")
	}
	return parsed, true
}

func (v Version) String() string { return v.text }

func (v Version) Compare(other Version) int {
	for _, pair := range [][2]uint64{{v.major, other.major}, {v.minor, other.minor}, {v.patch, other.patch}} {
		if pair[0] != pair[1] {
			return compareNumbers(pair[0], pair[1])
		}
	}
	switch {
	case len(v.prerelease) == 0 && len(other.prerelease) == 0:
		return 0
	case len(v.prerelease) == 0:
		return 1
	case len(other.prerelease) == 0:
		return -1
	}
	for index := range min(len(v.prerelease), len(other.prerelease)) {
		if order := compareIdentifiers(v.prerelease[index], other.prerelease[index]); order != 0 {
			return order
		}
	}
	return compareNumbers(uint64(len(v.prerelease)), uint64(len(other.prerelease)))
}

func compareIdentifiers(left, right string) int {
	leftNumber, leftNumeric := numeric(left)
	rightNumber, rightNumeric := numeric(right)
	switch {
	case leftNumeric && rightNumeric:
		return compareNumbers(leftNumber, rightNumber)
	case leftNumeric:
		return -1
	case rightNumeric:
		return 1
	}
	return strings.Compare(left, right)
}

func compareNumbers(left, right uint64) int {
	switch {
	case left < right:
		return -1
	case left > right:
		return 1
	}
	return 0
}

func numeric(part string) (uint64, bool) {
	if part == "" || (len(part) > 1 && part[0] == '0') || strings.TrimLeft(part, "0123456789") != "" {
		return 0, false
	}
	number, err := strconv.ParseUint(part, 10, 64)
	return number, err == nil
}

func identifiers(dotted string, ordered bool) bool {
	for identifier := range strings.SplitSeq(dotted, ".") {
		if identifier == "" || strings.TrimLeft(identifier, "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-") != "" {
			return false
		}
		if ordered && len(identifier) > 1 && identifier[0] == '0' && strings.TrimLeft(identifier, "0123456789") == "" {
			return false
		}
	}
	return true
}
