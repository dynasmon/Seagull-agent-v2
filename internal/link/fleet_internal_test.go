package link

import (
	"math/rand/v2"
	"slices"
	"testing"
	"time"
)

const fleet = 10000

// A fleet of agents that lost the platform at the same instant, each drawing
// its waits on its own as every agent draws from a generator seeded apart:
// when each of them tried the platform again while it stayed down, and when
// each came back once it returned.
func TestAFleetThatLosesThePlatformAtOnceComesBackSpreadOut(t *testing.T) {
	policy, err := Policy{}.Settled()
	if err != nil {
		t.Fatalf("settle the documented policy: %v", err)
	}
	draw := rand.New(rand.NewPCG(14, 2026)).Float64
	outage := 30 * time.Minute
	var attempts, returns []time.Duration
	for range fleet {
		at := time.Duration(0)
		for failures := 1; ; failures++ {
			at += policy.wait(failures, false, 0, draw)
			if at >= outage {
				returns = append(returns, at)
				break
			}
			attempts = append(attempts, at)
		}
	}
	slices.Sort(attempts)
	slices.Sort(returns)
	for _, window := range []struct {
		from, to time.Duration
		share    float64
	}{
		{from: 10 * time.Second, to: time.Minute, share: 0.2},
		{from: time.Minute, to: 10 * time.Minute, share: 0.05},
		{from: 10 * time.Minute, to: outage, share: 0.01},
	} {
		if most := busiest(attempts, window.from, window.to, time.Second); float64(most) > window.share*fleet {
			t.Errorf("between %s and %s into the outage, %d of %d agents tried the platform within the same second", window.from, window.to, most, fleet)
		}
	}
	if most := busiest(returns, outage, 2*outage, time.Second); most > fleet/100 {
		t.Errorf("%d of %d agents came back within the same second once the platform returned", most, fleet)
	}
	if last := returns[len(returns)-1] - outage; last > policy.RetryLongest*3/2 {
		t.Errorf("the last agent came back %s after the platform returned, and none waits more than %s", last, policy.RetryLongest*3/2)
	}
}

func TestAFleetToldToComeBackLaterDoesNotComeBackAtOnce(t *testing.T) {
	policy, err := Policy{}.Settled()
	if err != nil {
		t.Fatalf("settle the documented policy: %v", err)
	}
	draw := rand.New(rand.NewPCG(29, 9)).Float64
	for _, asked := range []time.Duration{time.Second, 5 * time.Second} {
		var returns []time.Duration
		for range fleet {
			returns = append(returns, policy.wait(1, false, asked, draw))
		}
		slices.Sort(returns)
		if returns[0] < asked || returns[len(returns)-1] > 2*asked {
			t.Fatalf("asked to come back in %s, the fleet came back between %s and %s", asked, returns[0], returns[len(returns)-1])
		}
		if most := busiest(returns, 0, 3*asked, asked/10); most > fleet/5 {
			t.Errorf("asked to come back in %s, %d of %d agents came back within the same tenth of it", asked, most, fleet)
		}
	}
}

func busiest(sorted []time.Duration, from, to, window time.Duration) int {
	most, first := 0, 0
	for last, at := range sorted {
		if at < from || at >= to {
			continue
		}
		for sorted[first] < from || at-sorted[first] >= window {
			first++
		}
		most = max(most, last-first+1)
	}
	return most
}
