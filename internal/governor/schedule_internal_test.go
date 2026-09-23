package governor

import (
	"testing"
	"testing/synctest"
	"time"
)

func TestAClockSetBackDoesNotBringBackARunThatHappened(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		hourly := &Schedule{every: time.Hour, phase: 17 * time.Minute}
		ran := hourly.Next(time.Now().Add(2 * time.Hour))
		hourly.last = ran
		due, err := hourly.Wait(t.Context())
		if err != nil || due != ran.Add(time.Hour) || !time.Now().Equal(due) {
			t.Fatalf("with the clock set back to before the run at %s, the next one came at %s: %v", ran, due, err)
		}
	})
}
