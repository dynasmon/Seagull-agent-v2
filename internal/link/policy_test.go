package link_test

import (
	"strings"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/link"
)

func TestAWaitDoublesUpToTheLongestAndIsDrawnAcrossHalfOfItEitherWay(t *testing.T) {
	policy, err := link.Policy{}.Settled()
	if err != nil {
		t.Fatalf("settle the documented policy: %v", err)
	}
	if policy != (link.Policy{Retry: time.Second, RetryLongest: 5 * time.Minute, Hold: time.Minute, HoldLongest: time.Hour}) {
		t.Fatalf("the documented policy is %+v", policy)
	}
	for _, lasting := range []bool{false, true} {
		first, longest := policy.Retry, policy.RetryLongest
		if lasting {
			first, longest = policy.Hold, policy.HoldLongest
		}
		for failures := 0; failures <= 64; failures++ {
			base := first
			for range failures - 1 {
				base = min(2*base, longest)
			}
			lowest, highest, total := time.Duration(1<<62), time.Duration(0), time.Duration(0)
			const draws = 2000
			for range draws {
				wait := policy.Wait(failures, lasting, 0)
				lowest, highest, total = min(lowest, wait), max(highest, wait), total+wait/draws
			}
			if lowest < base/2 || highest > base*3/2 || lowest > base*6/10 || highest < base*14/10 {
				t.Fatalf("after %d failures, lasting %t, the waits ran from %s to %s around %s", failures, lasting, lowest, highest, base)
			}
			if total < base*95/100 || total > base*105/100 {
				t.Fatalf("after %d failures, lasting %t, the waits averaged %s around %s", failures, lasting, total, base)
			}
		}
	}
}

func TestAWaitThePlatformAskedForIsHonouredUpToTheLongest(t *testing.T) {
	policy, _ := link.Policy{}.Settled()
	for _, c := range []struct {
		asked     time.Duration
		failures  int
		at, until time.Duration
	}{
		{asked: time.Second, failures: 1, at: time.Second, until: 2 * time.Second},
		{asked: 5 * time.Second, failures: 1, at: 5 * time.Second, until: 10 * time.Second},
		{asked: time.Second, failures: 5, at: 8 * time.Second, until: 24 * time.Second},
		{asked: 24 * time.Hour, failures: 1, at: policy.RetryLongest, until: 2 * policy.RetryLongest},
		{asked: -time.Minute, failures: 1, at: policy.Retry / 2, until: policy.Retry * 3 / 2},
	} {
		for range 1000 {
			if wait := policy.Wait(c.failures, false, c.asked); wait < c.at || wait > c.until {
				t.Fatalf("asked to wait %s after %d failures, the agent waits %s, outside %s to %s", c.asked, c.failures, wait, c.at, c.until)
			}
		}
	}
}

func TestAPolicyTakesTheDocumentedValuesAndRefusesWhatCannotBe(t *testing.T) {
	settled, err := link.Policy{Retry: 5 * time.Millisecond, HoldLongest: 2 * time.Hour}.Settled()
	if err != nil || settled != (link.Policy{Retry: 5 * time.Millisecond, RetryLongest: 5 * time.Minute, Hold: time.Minute, HoldLongest: 2 * time.Hour}) {
		t.Fatalf("a policy that names two waits settles as %+v: %v", settled, err)
	}
	for _, c := range []struct {
		policy link.Policy
		says   string
	}{
		{policy: link.Policy{Hold: -time.Second}, says: "negative"},
		{policy: link.Policy{Retry: time.Hour}, says: "less after failing again"},
		{policy: link.Policy{Hold: time.Minute, HoldLongest: time.Second}, says: "less after failing again"},
	} {
		if _, err := c.policy.Settled(); err == nil || !strings.Contains(err.Error(), c.says) {
			t.Errorf("%+v settled with %v", c.policy, err)
		}
	}
}
