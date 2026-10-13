package update_test

import (
	"strings"
	"testing"

	"github.com/dynasmon/Seagull-agent-v2/internal/update"
)

func TestAVersionIsASemanticVersionWithALeadingV(t *testing.T) {
	for _, text := range []string{
		"v0.2.0",
		"v1.0.0-rc.1",
		"v1.0.0-alpha.beta+exp.sha.5114f85",
		"v0.0.0-20261012161112-03c12793b25f",
		"v0.2.1-0.20261012161112-03c12793b25f",
		"v18446744073709551615.0.0",
	} {
		if _, valid := update.ParseVersion(text); !valid {
			t.Errorf("%s was refused", text)
		}
	}
	for _, text := range []string{
		"",
		"0.2.0",
		"v0.2",
		"v1",
		"v01.2.3",
		"v1.02.3",
		"v1.2.3-",
		"v1.2.3-01",
		"v1.2.3-a..b",
		"v1.2.3+",
		"v1.2.3+a_b",
		"v1.2.3-ä",
		"v18446744073709551616.0.0",
		"v1.2.3-" + strings.Repeat("a", update.MaxVersionLength),
	} {
		if _, valid := update.ParseVersion(text); valid {
			t.Errorf("%s was taken", text)
		}
	}
}

func TestVersionsAreOrderedBySemanticVersionPrecedence(t *testing.T) {
	ascending := []string{
		"v0.0.0-20261011173026-7976df66d929",
		"v0.0.0-20261012161112-03c12793b25f",
		"v0.0.1",
		"v0.2.0",
		"v0.2.1-0.20261012161112-03c12793b25f",
		"v0.2.1",
		"v1.0.0-alpha",
		"v1.0.0-alpha.1",
		"v1.0.0-alpha.beta",
		"v1.0.0-beta",
		"v1.0.0-beta.2",
		"v1.0.0-beta.11",
		"v1.0.0-rc.1",
		"v1.0.0",
		"v1.10.0",
		"v2.0.0",
	}
	for index := range ascending {
		for other := range ascending {
			left, _ := update.ParseVersion(ascending[index])
			right, _ := update.ParseVersion(ascending[other])
			want := 0
			switch {
			case index < other:
				want = -1
			case index > other:
				want = 1
			}
			if got := left.Compare(right); got != want {
				t.Errorf("%s against %s: %d, want %d", ascending[index], ascending[other], got, want)
			}
		}
	}
}

func TestBuildMetadataOrdersNothing(t *testing.T) {
	left, _ := update.ParseVersion("v1.0.0+build.1")
	right, _ := update.ParseVersion("v1.0.0+build.2")
	if left.Compare(right) != 0 {
		t.Error("two builds of one version were ordered")
	}
}
