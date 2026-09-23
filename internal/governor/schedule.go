package governor

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

const shortest = time.Second

// A Schedule is when periodic work runs: once every interval, at a phase of it
// drawn from the installation and the task. Installations draw their
// identifiers at random, so a fleet started at the same moment spreads each
// task across its interval, and an installation keeps its phase however often
// it restarts. A Schedule belongs to the goroutine that waits on it.
type Schedule struct {
	every time.Duration
	phase time.Duration
	last  time.Time
}

func (g *Governor) Periodic(task string, every time.Duration) (*Schedule, error) {
	if task == "" {
		return nil, errors.New("periodic work names its task")
	}
	if every < shortest {
		return nil, fmt.Errorf("%s runs every %s, and periodic work runs at most once every %s", task, every, shortest)
	}
	digest := sha256.Sum256([]byte(g.installation + "\x00" + task))
	phase := time.Duration(binary.BigEndian.Uint64(digest[:8]) % uint64(every))
	return &Schedule{every: every, phase: phase}, nil
}

// Next is the first run due after the moment given. Runs fall at the same
// points of the clock whenever the agent started, so neither a restart nor a
// reload runs the work sooner than its turn.
func (s *Schedule) Next(after time.Time) time.Time {
	since := after.UnixNano() - int64(s.phase)
	periods := since / int64(s.every)
	if since%int64(s.every) < 0 {
		periods--
	}
	return time.Unix(0, int64(s.phase)+(periods+1)*int64(s.every)).UTC()
}

// Wait returns when the next run is due, with the moment it was due. A run the
// work kept waiting past the one after it is not made up, and a clock set back
// does not bring back a run that already happened.
func (s *Schedule) Wait(ctx context.Context) (time.Time, error) {
	now := time.Now()
	due := s.Next(now)
	if !s.last.IsZero() && !due.After(s.last) {
		due = s.Next(s.last)
	}
	timer := time.NewTimer(due.Sub(now))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return time.Time{}, ctx.Err()
	case <-timer.C:
	}
	s.last = due
	return due, nil
}
