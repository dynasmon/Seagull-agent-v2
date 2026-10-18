package deb

import (
	"regexp"
	"strings"
	"testing"

	"github.com/dynasmon/Seagull-agent-v2/internal/update"
)

func rank(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return 0
	case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z':
		return int(c)
	case c == '~':
		return -1
	}
	return int(c) + 256
}

func digit(text string) bool { return text != "" && text[0] >= '0' && text[0] <= '9' }

// compared orders two Debian versions of one revision and no epoch as dpkg's
// verrevcmp orders them.
func compared(a, b string) int {
	a, b = a[:strings.LastIndexByte(a, '-')], b[:strings.LastIndexByte(b, '-')]
	for a != "" || b != "" {
		first := 0
		for a != "" && !digit(a) || b != "" && !digit(b) {
			left, right := 0, 0
			if a != "" {
				left, a = rank(a[0]), a[1:]
			}
			if b != "" {
				right, b = rank(b[0]), b[1:]
			}
			if left != right {
				return left - right
			}
		}
		a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
		for digit(a) && digit(b) {
			if first == 0 {
				first = int(a[0]) - int(b[0])
			}
			a, b = a[1:], b[1:]
		}
		switch {
		case digit(a):
			return 1
		case digit(b):
			return -1
		case first != 0:
			return first
		}
	}
	return 0
}

func sign(order int) int { return min(max(order, -1), 1) }

var pseudo = regexp.MustCompile(`^(.*)\.?([0-9]{14})-[0-9a-f]{12}$`)

// Where dpkg is known to order two releases as their letters run: two commits
// of one second, which Go orders by their hashes, and stage words one of which
// begins the other, such as rc and rcx.
func unordered(left, right string) bool {
	_, first, _ := strings.Cut(left, "-")
	_, second, _ := strings.Cut(right, "-")
	if held, other := pseudo.FindStringSubmatch(first), pseudo.FindStringSubmatch(second); held != nil && other != nil && held[1] == other[1] && held[2] == other[2] {
		return true
	}
	firsts, seconds := strings.Split(first, "."), strings.Split(second, ".")
	for i := range min(len(firsts), len(seconds)) {
		if firsts[i] == seconds[i] {
			continue
		}
		words := strings.Trim(firsts[i]+seconds[i], "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz") == ""
		return words && (strings.HasPrefix(firsts[i], seconds[i]) || strings.HasPrefix(seconds[i], firsts[i]))
	}
	return false
}

// Whatever two releases an agent is built as and packaged, dpkg orders their
// packages as the agent orders the releases, so an upgrade is never taken for a
// downgrade, and two releases never share a package version.
func FuzzVersion(f *testing.F) {
	for _, seed := range [][2]string{{"v0.1.0-rc.1", "v0.1.0"}, {"v0.1.0-rc.2", "v0.1.0-rc.10"}, {"v1.0.0-alpha", "v1.0.0-alpha.1"},
		{"v0.0.0-20260101000000-aaaaaaaaaaaa", "v0.0.0-20260201000000-000000000000"}, {"v1.0.0-rc.1", "v1.0.0-rc-1"}, {"v1.0.0-Beta", "v1.0.0-alpha"},
		{"v0.1.0-rc.1.0.20261017163000-4fe17642b9c1", "v0.1.0-rc.2"}, {"v0.1.1-0.20261017163000-4fe17642b9c1", "v0.1.0"}, {"v1.999.0-gate", "v1.999.1-gate"}} {
		f.Add(seed[0], seed[1])
	}
	f.Fuzz(func(t *testing.T, left, right string) {
		first, firstErr := Version(left)
		second, secondErr := Version(right)
		if firstErr != nil || secondErr != nil {
			return
		}
		older, olderRead := update.ParseVersion(left)
		newer, newerRead := update.ParseVersion(right)
		if !olderRead || !newerRead {
			t.Fatalf("%q or %q is packaged and is no release the agent reads", left, right)
		}
		agent, packaged := sign(older.Compare(newer)), sign(compared(first, second))
		switch {
		case left != right && first == second:
			t.Fatalf("%s and %s are both packaged as %s", left, right, first)
		case agent != packaged && !unordered(left, right):
			t.Fatalf("the agent orders %s %+d against %s, and dpkg orders %s %+d against %s", left, agent, right, first, packaged, second)
		}
	})
}
