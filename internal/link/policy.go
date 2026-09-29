package link

import (
	"fmt"
	"math"
	"math/rand/v2"
	"time"
)

const spread = 0.5

// A Policy bounds how soon the platform is tried again after it failed: Retry
// after the first failure the network or a busy platform explains, doubling up
// to RetryLongest, and Hold after the first one that waits on somebody to act,
// doubling up to HoldLongest. A zero field takes the documented value.
type Policy struct {
	Retry        time.Duration
	RetryLongest time.Duration
	Hold         time.Duration
	HoldLongest  time.Duration
}

func (p Policy) Settled() (Policy, error) {
	fields := []struct {
		held  *time.Duration
		value time.Duration
	}{{&p.Retry, time.Second}, {&p.RetryLongest, 5 * time.Minute}, {&p.Hold, time.Minute}, {&p.HoldLongest, time.Hour}}
	for _, field := range fields {
		switch {
		case *field.held < 0:
			return Policy{}, fmt.Errorf("a retry policy of %+v waits a negative time", p)
		case *field.held == 0:
			*field.held = field.value
		}
	}
	if p.RetryLongest < p.Retry || p.HoldLongest < p.Hold {
		return Policy{}, fmt.Errorf("a retry policy of %+v waits less after failing again than it waits first", p)
	}
	return p, nil
}

// Wait draws how long to wait after the failures-th failure in a row, lasting
// or not: the first wait of its kind, doubled for every failure before it up to
// the longest, and drawn anywhere between half and one and a half times that,
// so a fleet that failed at the same moment does not come back at the same
// moment. A wait the platform asked for is honoured up to the longest, never
// cut short, and drawn anywhere up to twice as long.
func (p Policy) Wait(failures int, lasting bool, asked time.Duration) time.Duration {
	return p.wait(failures, lasting, asked, rand.Float64)
}

func (p Policy) wait(failures int, lasting bool, asked time.Duration, draw func() float64) time.Duration {
	first, longest := p.Retry, p.RetryLongest
	if lasting {
		first, longest = p.Hold, p.HoldLongest
	}
	base := min(float64(first)*math.Pow(2, float64(max(failures, 1)-1)), float64(longest))
	wait := base * (1 - spread + 2*spread*draw())
	if asked > 0 {
		wait = max(wait, float64(min(asked, longest))*(1+draw()))
	}
	return time.Duration(wait)
}
