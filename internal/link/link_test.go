package link_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/link"
	"github.com/dynasmon/Seagull-agent-v2/internal/transport"
)

var measured = link.Policy{Retry: time.Second, RetryLongest: 8 * time.Second, Hold: time.Minute, HoldLongest: time.Hour}

func TestEveryRequestHasItsTurnAtOnceWhileTheListenerAnswers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		connected, _ := compose(t, measured)
		began := time.Now()
		var turns []*link.Turn
		for range 8 {
			turn, err := connected.Take(t.Context())
			if err != nil {
				t.Fatalf("take a turn: %v", err)
			}
			turns = append(turns, turn)
		}
		for _, turn := range turns {
			turn.Answered()
		}
		state := connected.State()
		if !time.Now().Equal(began) || state.Listener != "ingest" || !state.Answered.Equal(began) || !state.Failing.IsZero() || state.Attempts != 0 {
			t.Fatalf("eight requests to a listener that answers waited %s and left %+v", time.Since(began), state)
		}
	})
}

func TestAListenerThatFailsIsTriedByOneRequestAtATimeUntilItAnswers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		connected, written := compose(t, measured)
		began := time.Now()
		first, _ := connected.Take(t.Context())
		next := first.Failed(link.Transport, 0, fmt.Errorf("%w: connection refused", transport.ErrUnreachable))
		if wait := next.Sub(began); wait < measured.Retry/2 || wait > measured.Retry*3/2 {
			t.Fatalf("the first failure is tried again %s later, with a first wait of %s", wait, measured.Retry)
		}

		turns := make(chan *link.Turn, 3)
		for range 3 {
			go func() {
				turn, err := connected.Take(t.Context())
				if err != nil {
					t.Errorf("take a turn: %v", err)
				}
				turns <- turn
			}()
		}
		synctest.Wait()
		if len(turns) != 0 {
			t.Fatalf("%d requests had their turn before the next attempt was due", len(turns))
		}
		time.Sleep(time.Until(next))
		synctest.Wait()
		if len(turns) != 1 {
			t.Fatalf("%d requests had their turn once the next attempt was due", len(turns))
		}
		again := (<-turns).Failed(link.Transport, 0, fmt.Errorf("%w: connection refused", transport.ErrUnreachable))
		if wait := time.Until(again); wait < measured.Retry || wait > measured.Retry*3 {
			t.Fatalf("the second failure is tried again %s later, with a first wait of %s", wait, measured.Retry)
		}
		state := connected.State()
		if !state.Failing.Equal(began) || state.Failure != link.Transport || state.Attempts != 2 || !state.Next.Equal(again) ||
			!strings.Contains(state.Reason, "connection refused") || !state.Answered.IsZero() {
			t.Fatalf("after two failed attempts the link holds %+v", state)
		}
		synctest.Wait()
		if len(turns) != 0 {
			t.Fatalf("%d requests had their turn after the attempt failed again", len(turns))
		}
		time.Sleep(time.Until(again))
		synctest.Wait()
		if len(turns) != 1 {
			t.Fatalf("%d requests had their turn once the third attempt was due", len(turns))
		}
		(<-turns).Answered()
		synctest.Wait()
		if len(turns) != 1 {
			t.Fatalf("%d of the requests left had their turn once the listener answered", len(turns))
		}
		(<-turns).Answered()
		if state := connected.State(); !state.Failing.IsZero() || state.Attempts != 0 || !state.Answered.Equal(again) {
			t.Fatalf("once the listener answered the link holds %+v", state)
		}

		failing, restored := written.entries(t, "connection_failing"), written.entries(t, "connection_restored")
		if len(failing) != 1 || failing[0]["level"] != "WARN" || failing[0]["failure"] != "transport" || failing[0]["listener"] != "ingest" || failing[0]["attempt"] != float64(1) {
			t.Fatalf("logged %v as the listener failed", failing)
		}
		if len(restored) != 1 || restored[0]["attempts"] != float64(2) || restored[0]["failing"] != float64(again.Sub(began)) || restored[0]["failure"] != "transport" {
			t.Fatalf("logged %v as the listener answered again", restored)
		}
	})
}

func TestAnOutageSeveralRequestsRanIntoIsCountedOnceAndAnAnswerSinceStands(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		connected, _ := compose(t, measured)
		var turns []*link.Turn
		for range 3 {
			turn, _ := connected.Take(t.Context())
			turns = append(turns, turn)
		}
		next := turns[0].Failed(link.Capacity, 0, errors.New("the gateway is holding as much work as it was bounded to"))
		if later := turns[1].Failed(link.Capacity, 0, errors.New("the same outage")); !later.Equal(next) || connected.State().Attempts != 1 {
			t.Fatalf("a second request into the same outage moved the next attempt from %s to %s and counts %d attempts", next, later, connected.State().Attempts)
		}
		turns[2].Answered()
		if state := connected.State(); !state.Failing.IsZero() {
			t.Fatalf("an answer that came after the failure left %+v", state)
		}
		if now := turns[1].Failed(link.Transport, 0, errors.New("once more")); !now.Equal(time.Now()) || !connected.State().Failing.IsZero() {
			t.Fatalf("a request settled twice moved the link to %+v", connected.State())
		}
		turn, _ := connected.Take(t.Context())
		turn.Failed(link.Transport, 0, errors.New("a new outage"))
		if state := connected.State(); state.Attempts != 1 || !state.Failing.Equal(time.Now()) {
			t.Fatalf("an outage after the listener answered again starts at %+v", state)
		}
	})
}

func TestATurnTakenBeforeTheListenerFailedNoLongerStands(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		connected, _ := compose(t, measured)
		early, _ := connected.Take(t.Context())
		failing, _ := connected.Take(t.Context())
		if !early.Stands() || !failing.Stands() {
			t.Fatal("a turn taken while the listener answers does not stand")
		}
		time.Sleep(time.Until(failing.Failed(link.Transport, 0, errors.New("connection refused"))))
		if early.Stands() || failing.Stands() {
			t.Fatal("a turn stands after the listener failed, or after it was settled")
		}
		probe, _ := connected.Take(t.Context())
		if !probe.Stands() {
			t.Fatal("the turn to try a failing listener again does not stand")
		}
		probe.Answered()
		late, _ := connected.Take(t.Context())
		if !late.Stands() || !early.Stands() {
			t.Fatal("a turn does not stand once the listener answers again")
		}
	})
}

func TestAFailureThatWaitsOnSomebodyIsHeldLongerAndSaysWhatToDo(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		connected, written := compose(t, measured)
		turn, _ := connected.Take(t.Context())
		next := turn.Failed(link.Capacity, 0, errors.New("rate_limited"))
		time.Sleep(time.Until(next))
		turn, _ = connected.Take(t.Context())
		held := turn.Failed(link.Authorization, 0, errors.New("agent_not_admitted"))
		if wait := time.Until(held); wait < measured.Hold || wait > measured.Hold*3 {
			t.Fatalf("an agent the platform no longer admits is tried again %s later, with a first hold of %s", wait, measured.Hold)
		}
		failing := written.entries(t, "connection_failing")
		if len(failing) != 2 || failing[0]["level"] != "WARN" || failing[1]["level"] != "ERROR" || failing[1]["failure"] != "authorization" ||
			failing[1]["recovery"] != "recover from agent_not_admitted" || failing[1]["attempt"] != float64(2) {
			t.Fatalf("logged %v as the failure changed", failing)
		}
	})
}

func TestAPlatformThatAsksTheAgentToWaitIsNotTriedSooner(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		connected, _ := compose(t, measured)
		for _, asked := range []time.Duration{3 * time.Second, 5 * time.Second, 5 * time.Second} {
			turn, _ := connected.Take(t.Context())
			began := time.Now()
			next := turn.Failed(link.Capacity, asked, errors.New("backbone_unavailable"))
			if wait := next.Sub(began); wait < asked || wait > max(2*asked, 3*measured.RetryLongest/2) {
				t.Fatalf("asked to wait %s, the next attempt is due %s later", asked, wait)
			}
			time.Sleep(time.Until(next))
		}
	})
}

func TestAStoppedRequestReleasesItsTurnAndAStoppedWaitReturns(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		connected, _ := compose(t, measured)
		turn, _ := connected.Take(t.Context())
		time.Sleep(time.Until(turn.Failed(link.Transport, 0, errors.New("connection refused"))))
		probe, _ := connected.Take(t.Context())

		turns := make(chan *link.Turn, 2)
		for range 2 {
			go func() {
				turn, _ := connected.Take(t.Context())
				turns <- turn
			}()
		}
		synctest.Wait()
		if len(turns) != 0 {
			t.Fatalf("%d requests had their turn while another tried the listener", len(turns))
		}
		probe.Abandoned()
		synctest.Wait()
		if len(turns) != 1 {
			t.Fatalf("%d requests had their turn once the one trying the listener stopped", len(turns))
		}
		(<-turns).Answered()
		<-turns

		turn, _ = connected.Take(t.Context())
		turn.Failed(link.TLS, 0, errors.New("unknown authority"))
		ctx, stop := context.WithCancel(t.Context())
		waited := make(chan error, 1)
		go func() {
			_, err := connected.Take(ctx)
			waited <- err
		}()
		synctest.Wait()
		stop()
		if err := <-waited; !errors.Is(err, context.Canceled) {
			t.Fatalf("a wait the agent stopped returned %v", err)
		}
	})
}

func TestAFailureIsClassifiedByWhatTheTransportReported(t *testing.T) {
	for _, c := range []struct {
		err   error
		class link.Class
	}{
		{err: fmt.Errorf("%w: dial tcp: connection refused", transport.ErrUnreachable), class: link.Transport},
		{err: fmt.Errorf("%w: context deadline exceeded", transport.ErrUnanswered), class: link.Transport},
		{err: fmt.Errorf("%w: x509: certificate signed by unknown authority", transport.ErrUntrusted), class: link.TLS},
		{err: fmt.Errorf("%w: remote error: tls: bad certificate", transport.ErrRefused), class: link.Authorization},
		{err: fmt.Errorf("%w: the certificate expired", transport.ErrUnauthenticated), class: link.Authorization},
		{err: fmt.Errorf("%w: 70000 bytes", transport.ErrReplyTooLarge)},
		{err: context.Canceled},
	} {
		class, classified := link.Of(fmt.Errorf("deliver events: %w", c.err))
		if class != c.class || classified != (c.class != 0) {
			t.Errorf("%v is classified as %v, %t", c.err, class, classified)
		}
	}
	for class, lasting := range map[link.Class]bool{link.Transport: false, link.TLS: true, link.Authorization: true, link.Capacity: false} {
		if class.Lasting() != lasting {
			t.Errorf("a %s failure is lasting: %t", class, class.Lasting())
		}
	}
}

func TestComposingTheLinkRefusesWhatItCannotKeep(t *testing.T) {
	for name, options := range map[string]link.Options{
		"no listener":           {Logger: slog.New(slog.DiscardHandler)},
		"no logger":             {Listener: "ingest"},
		"a negative wait":       {Listener: "ingest", Logger: slog.New(slog.DiscardHandler), Policy: link.Policy{Retry: -time.Second}},
		"a wait that shrinks":   {Listener: "ingest", Logger: slog.New(slog.DiscardHandler), Policy: link.Policy{Retry: time.Hour, RetryLongest: time.Minute}},
		"a hold that shrinks":   {Listener: "ingest", Logger: slog.New(slog.DiscardHandler), Policy: link.Policy{Hold: time.Hour, HoldLongest: time.Minute}},
		"a longest with no end": {Listener: "ingest", Logger: slog.New(slog.DiscardHandler), Policy: link.Policy{HoldLongest: -time.Hour}},
	} {
		if connected, err := link.New(options); connected != nil || err == nil {
			t.Errorf("%s: composed %v, %v", name, connected, err)
		}
	}
}

func compose(t *testing.T, policy link.Policy) (*link.Link, *logs) {
	t.Helper()
	written := &logs{}
	connected, err := link.New(link.Options{
		Listener: "ingest",
		Policy:   policy,
		Logger:   slog.New(slog.NewJSONHandler(written, nil)),
		Recovery: func(err error) string { return "recover from " + err.Error() },
	})
	if err != nil {
		t.Fatalf("compose the link: %v", err)
	}
	return connected, written
}

type logs struct {
	mu      sync.Mutex
	written bytes.Buffer
}

func (l *logs) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.written.Write(p)
}

func (l *logs) entries(t *testing.T, message string) []map[string]any {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	var found []map[string]any
	for line := range strings.Lines(l.written.String()) {
		entry := map[string]any{}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("decode the log line %q: %v", line, err)
		}
		if entry["msg"] == message {
			found = append(found, entry)
		}
	}
	return found
}
