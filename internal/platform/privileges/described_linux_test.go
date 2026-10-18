//go:build linux

package privileges

import (
	"slices"
	"strconv"
	"strings"
	"testing"
)

// Whatever the status of the process says, the capabilities read from it are
// named once each, in the order of their numbers.
func FuzzDescribed(f *testing.F) {
	f.Add("Name:\tseagull-agent\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:\t2\n")
	f.Add("CapPrm:\t000001ffffffffff\nCapEff:\t000001ffffffffff\nNoNewPrivs:\t0\nSeccomp:\t0\n")
	f.Add("CapPrm:\tffffffffffffffff\nCapEff:\t0\nNoNewPrivs:\t1\n")
	f.Add("CapPrm:\tzz\nCapEff:\t0\nNoNewPrivs:\t1\n")
	f.Fuzz(func(t *testing.T, content string) {
		held, err := described(content)
		if err != nil {
			return
		}
		numbers := make([]int, 0, len(held.Capabilities))
		for _, name := range held.Capabilities {
			if index := slices.Index(named, name); index >= 0 {
				numbers = append(numbers, index)
				continue
			}
			number, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(name, "cap("), ")"))
			if err != nil || number < len(named) || number >= maxCapability {
				t.Fatalf("a capability is named %q", name)
			}
			numbers = append(numbers, number)
		}
		if !slices.IsSorted(numbers) || len(slices.Compact(slices.Clone(numbers))) != len(numbers) || held.Seccomp == "" {
			t.Fatalf("the process holds %v under seccomp %q", held.Capabilities, held.Seccomp)
		}
	})
}
