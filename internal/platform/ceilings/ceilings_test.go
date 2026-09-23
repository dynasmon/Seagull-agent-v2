package ceilings_test

import (
	"slices"
	"testing"

	"github.com/dynasmon/Seagull-agent-v2/internal/platform/ceilings"
)

func TestWhatNothingEnforcesIsNamed(t *testing.T) {
	cases := []struct {
		held ceilings.Ceilings
		want []string
	}{
		{held: ceilings.Ceilings{}, want: []string{"memory", "cpu", "tasks", "descriptors"}},
		{held: ceilings.Ceilings{Memory: 96 << 20, CPUs: 0.5, Tasks: 64, Descriptors: 1024}, want: []string{}},
		{held: ceilings.Ceilings{Tasks: 16720, Descriptors: 1 << 20}, want: []string{"memory", "cpu"}},
	}
	for _, c := range cases {
		if found := c.held.Unenforced(); !slices.Equal(found, c.want) {
			t.Errorf("%+v leaves %q unenforced, want %q", c.held, found, c.want)
		}
	}
}
