package transport

import (
	"net/http"
	"strconv"
	"testing"
	"time"
)

// Whatever a listener answers in Retry-After, the agent waits no less than
// nothing and no more than a day, and as long as the header says when it says
// a number of seconds or a moment it can read.
func FuzzAsked(f *testing.F) {
	answered := time.Date(2026, time.October, 17, 12, 0, 0, 0, time.UTC)
	for _, seed := range []string{"120", "0", "99999999999999999999", "Sat, 17 Oct 2026 12:05:00 GMT", "Sat, 17 Oct 2026 11:00:00 GMT", "-5", " 30 ", "soon"} {
		f.Add(seed, answered.Unix())
	}
	f.Fuzz(func(t *testing.T, header string, date int64) {
		at := time.Unix(date, 0).UTC()
		wait := asked(header, at)
		if wait < 0 || wait > longestAsked {
			t.Fatalf("Retry-After %q makes the agent wait %s", header, wait)
		}
		if seconds, err := strconv.ParseUint(header, 10, 63); err == nil && seconds <= uint64(longestAsked/time.Second) && wait != time.Duration(seconds)*time.Second {
			t.Fatalf("Retry-After %q makes the agent wait %s", header, wait)
		}
		if moment, err := http.ParseTime(header); err == nil && wait != min(max(moment.Sub(at), 0), longestAsked) {
			t.Fatalf("Retry-After %q, answered at %s, makes the agent wait %s", header, at, wait)
		}
	})
}
