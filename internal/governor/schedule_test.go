package governor_test

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/governor"
)

var started = time.Date(2026, 9, 23, 3, 0, 0, 0, time.UTC)

func TestPeriodicWorkRunsOnceAnIntervalAtItsOwnPhase(t *testing.T) {
	daily := schedule(t, "8a4a6c52-3a3b-4f0e-9c38-1f2d7f0c9b11", "inventory", 24*time.Hour)
	first := daily.Next(started)
	if !first.After(started) || first.Sub(started) > 24*time.Hour {
		t.Fatalf("a daily task started at %s first runs at %s", started, first)
	}
	for run, at := 1, first; run < 5; run++ {
		next := daily.Next(at)
		if next.Sub(at) != 24*time.Hour {
			t.Fatalf("run %d of a daily task came %s after the one before", run, next.Sub(at))
		}
		at = next
	}
	if daily.Next(first.Add(-time.Nanosecond)) != first || daily.Next(first) != first.Add(24*time.Hour) {
		t.Fatal("a run is due after the moment asked about, and never at it")
	}

	for _, restarted := range []time.Time{started, started.Add(7 * time.Hour), started.Add(30*time.Hour + 17*time.Minute)} {
		again := schedule(t, "8a4a6c52-3a3b-4f0e-9c38-1f2d7f0c9b11", "inventory", 24*time.Hour).Next(restarted)
		if offset := again.Sub(first) % (24 * time.Hour); offset != 0 {
			t.Fatalf("restarted at %s, the installation runs %s off the phase it had", restarted, offset)
		}
	}
	for _, other := range []*governor.Schedule{
		schedule(t, "8a4a6c52-3a3b-4f0e-9c38-1f2d7f0c9b11", "fim", 24*time.Hour),
		schedule(t, "0c9b1f2d-7f0c-4f0e-9c38-8a4a6c523a3b", "inventory", 24*time.Hour),
	} {
		if other.Next(started) == first {
			t.Fatal("another task or another installation runs at the very same moment")
		}
	}
}

func TestAFleetStartedAtOnceSpreadsEachTaskAcrossItsInterval(t *testing.T) {
	const fleet, bins = 10000, 100
	for _, every := range []time.Duration{time.Minute, time.Hour, 24 * time.Hour} {
		spread := make([]int, bins)
		together := 0
		for range fleet {
			installation := rand.Text()
			inventory := schedule(t, installation, "inventory", every).Next(started)
			fim := schedule(t, installation, "fim", every).Next(started)
			spread[min(int(inventory.Sub(started)*bins/every), bins-1)]++
			if gap := (inventory.Sub(fim) + every) % every; gap < every/bins || gap > every-every/bins {
				together++
			}
		}
		for bin, runs := range spread {
			if runs < fleet/bins/2 || runs > fleet/bins*3/2 {
				t.Fatalf("every %s, %d of %d installations run in the same hundredth of the interval (bin %d): %v", every, runs, fleet, bin, spread)
			}
		}
		if together > fleet*4/bins {
			t.Fatalf("every %s, %d of %d installations run inventory and fim within a hundredth of the interval of each other", every, together, fleet)
		}
	}
}

func TestWaitingOnAScheduleReturnsAtEachRunAndSkipsWhatWasMissed(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		hourly := schedule(t, "8a4a6c52-3a3b-4f0e-9c38-1f2d7f0c9b11", "inventory", time.Hour)
		due, err := hourly.Wait(t.Context())
		if err != nil || !time.Now().Equal(due) || due != hourly.Next(due.Add(-time.Hour)) {
			t.Fatalf("waited until %s for a run due at %s: %v", time.Now(), due, err)
		}
		next, err := hourly.Wait(t.Context())
		if err != nil || next.Sub(due) != time.Hour || !time.Now().Equal(next) {
			t.Fatalf("the run after %s came at %s: %v", due, next, err)
		}

		time.Sleep(150 * time.Minute)
		late, err := hourly.Wait(t.Context())
		if err != nil || late.Sub(next) != 3*time.Hour {
			t.Fatalf("after work that ran for 150 minutes, the next run was due %s later, want the first run after it ended", late.Sub(next))
		}

		ctx, stop := context.WithCancel(t.Context())
		waited := make(chan error, 1)
		go func() {
			_, err := hourly.Wait(ctx)
			waited <- err
		}()
		synctest.Wait()
		stop()
		if err := <-waited; !errors.Is(err, context.Canceled) {
			t.Fatalf("a wait the agent stopped returned %v", err)
		}
	})
}

func TestPeriodicWorkNamesItsTaskAndRunsNoMoreThanOnceASecond(t *testing.T) {
	governed, _ := compose(t, ample)
	for _, c := range []struct {
		task  string
		every time.Duration
		says  string
	}{
		{every: time.Hour, says: "names its task"},
		{task: "inventory", every: 500 * time.Millisecond, says: "at most once every 1s"},
		{task: "inventory", every: -time.Hour, says: "at most once every 1s"},
	} {
		if held, err := governed.Periodic(c.task, c.every); held != nil || err == nil || !strings.Contains(err.Error(), c.says) {
			t.Errorf("a task %q every %s returned %v, %v", c.task, c.every, held, err)
		}
	}
}

func schedule(t *testing.T, installation, task string, every time.Duration) *governor.Schedule {
	t.Helper()
	governed, err := governor.New(slog.New(slog.DiscardHandler), installation, ample)
	if err != nil {
		t.Fatalf("compose the governor: %v", err)
	}
	periodic, err := governed.Periodic(task, every)
	if err != nil {
		t.Fatal(fmt.Errorf("schedule %s: %w", task, err))
	}
	return periodic
}
