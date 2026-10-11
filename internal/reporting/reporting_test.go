package reporting_test

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-agent-v2/internal/link"
	"github.com/dynasmon/Seagull-agent-v2/internal/protocol"
	"github.com/dynasmon/Seagull-agent-v2/internal/reporting"
	"github.com/dynasmon/Seagull-agent-v2/internal/transport"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	ingestv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/ingest/v1"
)

type platform struct {
	mu       sync.Mutex
	answers  []func() (transport.Reply, error)
	received []*agentv1.StatusBatch
	bodies   [][]byte
	urls     []string
}

func (p *platform) Post(_ context.Context, request transport.Request) (transport.Reply, error) {
	body, err := io.ReadAll(request.Body)
	if err != nil {
		return transport.Reply{}, err
	}
	var batch agentv1.StatusBatch
	if err := proto.Unmarshal(body, &batch); err != nil {
		return transport.Reply{}, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.received, p.bodies, p.urls = append(p.received, &batch), append(p.bodies, body), append(p.urls, request.URL)
	if len(p.answers) == 0 {
		return acknowledged(), nil
	}
	answer := p.answers[0]
	p.answers = p.answers[1:]
	return answer()
}

func (p *platform) sequences() []uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	var held []uint64
	for _, batch := range p.received {
		held = append(held, batch.GetReports()[0].GetSequence())
	}
	return held
}

func answered(status int, message proto.Message) func() (transport.Reply, error) {
	return func() (transport.Reply, error) {
		body, _ := proto.Marshal(message)
		return transport.Reply{Status: status, ContentType: protocol.ContentType, Body: body}, nil
	}
}

func acknowledged() transport.Reply {
	reply, _ := answered(200, &ingestv1.BatchAck{Accepted: true, Durable: true, Received: 1})()
	return reply
}

func report(stopping bool) *agentv1.Status {
	condition := agentv1.Status_CONDITION_RUNNING
	if stopping {
		condition = agentv1.Status_CONDITION_STOPPED
	}
	return &agentv1.Status{
		SchemaVersion:  protocol.StatusSchemaVersion,
		InstallationId: "2f1d6c1e-6b0a-4f4e-9b8e-6d1c2a3b4c5d",
		Origin:         &eventv1.Origin{Host: &eventv1.Host{Hostname: "web-01", Os: "linux", Architecture: "amd64"}},
		Run:            &agentv1.Status_Run{StartedAt: timestamppb.New(time.Now()), PreviousEnding: agentv1.Status_ENDING_NONE},
		Build:          &agentv1.Status_Build{Version: "(devel)"},
		Condition:      condition,
		Spool:          &agentv1.Status_Spool{},
		Configuration:  &agentv1.Status_Configuration{DigestSha256: strings.Repeat("ab", 32)},
		Privileges:     &agentv1.Status_Privileges{User: "997"},
	}
}

func directory(t *testing.T) *os.Root {
	t.Helper()
	path := filepath.Join(t.TempDir(), "reporting")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	return root
}

func reporter(t *testing.T, client reporting.Client, root *os.Root, logs io.Writer) *reporting.Reporter {
	t.Helper()
	built, err := reporting.New(reporting.Options{
		Client:    client,
		URL:       "https://gateway.example:8443",
		Directory: root,
		Report:    report,
		Every:     func() time.Duration { return time.Minute },
		Policy:    link.Policy{Retry: time.Second, RetryLongest: 10 * time.Second, Hold: 5 * time.Minute, HoldLongest: time.Hour},
		Logger:    slog.New(slog.NewJSONHandler(logs, nil)),
	})
	if err != nil {
		t.Fatalf("compose the reporter: %v", err)
	}
	return built
}

func TestEveryReportTakesTheNextSequenceAcrossRestartsAndGoesToTheStatusRoute(t *testing.T) {
	root, sent := directory(t), &platform{}
	first := reporter(t, sent, root, io.Discard)
	first.Report(t.Context())
	first.Report(t.Context())
	again := reporter(t, sent, root, io.Discard)
	again.Report(t.Context())

	if got := sent.sequences(); len(got) != 3 || got[0] != 1 || got[1] != 2 || got[2] != 3 {
		t.Fatalf("the reports carried sequences %v", got)
	}
	if sent.urls[0] != "https://gateway.example:8443/v1/status" || sent.received[0].GetBatchId() != "2f1d6c1e-6b0a-4f4e-9b8e-6d1c2a3b4c5d.1" {
		t.Errorf("the first report went to %s as batch %s", sent.urls[0], sent.received[0].GetBatchId())
	}
	held := sent.received[2].GetReports()[0]
	if held.GetInterval().AsDuration() != time.Minute || !held.GetReportedAt().IsValid() || held.GetCondition() != agentv1.Status_CONDITION_RUNNING {
		t.Errorf("a report says %+v", held)
	}
	if state := again.State(); state.Sequence != 3 || state.Attempts != 0 || state.Reported.IsZero() {
		t.Errorf("after reporting, the reporter holds %+v", state)
	}
}

func TestAReportWhoseAnswerWasLostIsSentAgainAsTheSameBytes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sent := &platform{answers: []func() (transport.Reply, error){
			answered(503, &ingestv1.Rejection{Code: "backbone_unavailable", EventIndex: -1}),
			func() (transport.Reply, error) { return transport.Reply{}, transport.ErrUnanswered },
		}}
		var logs bytes.Buffer
		held := reporter(t, sent, directory(t), &logs)
		held.Report(t.Context())
		if got := sent.sequences(); len(got) != 3 || got[0] != 1 || got[1] != 1 || got[2] != 1 {
			t.Fatalf("a report that was not taken was sent as %v", got)
		}
		if !bytes.Equal(sent.bodies[0], sent.bodies[2]) {
			t.Error("a report sent again changed on the way")
		}
		if state := held.State(); state.Attempts != 0 || !strings.Contains(logs.String(), "status_reported_again") {
			t.Errorf("once taken, the reporter holds %+v and logged %s", state, logs.String())
		}
	})
}

func TestARefusedReportIsNotSentAgainAndTheNextOneTakesTheNextSequence(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sent := &platform{answers: []func() (transport.Reply, error){
			answered(422, &ingestv1.Rejection{Code: "invalid_report", Field: "interval", EventIndex: 0, Detail: "must be between 10s and 1h0m0s"}),
			answered(422, &ingestv1.Rejection{Code: "invalid_report", Field: "reported_at", EventIndex: 0, Detail: "is more than 5m0s ahead of the platform clock"}),
		}}
		var logs bytes.Buffer
		held := reporter(t, sent, directory(t), &logs)
		for round, outcome := range []string{"record_refused", "disputed"} {
			wait := held.Report(t.Context())
			if got := sent.sequences(); len(got) != round+1 || got[round] != uint64(round+1) || wait > time.Minute || wait < 50*time.Second {
				t.Fatalf("a refused report was sent as %v, and the next waits %s", got, wait)
			}
			if state := held.State(); state.Attempts != round+1 || state.Outcome != outcome || state.Sequence != uint64(round+1) {
				t.Errorf("after a refusal the reporter holds %+v", state)
			}
		}
		held.Report(t.Context())
		if got := sent.sequences(); len(got) != 3 || got[2] != 3 || held.State().Attempts != 0 {
			t.Errorf("after two refusals, reports carried %v and the reporter holds %+v", got, held.State())
		}
		if strings.Count(logs.String(), `"msg":"status_not_reported"`) != 2 {
			t.Errorf("the refusals were logged as:\n%s", logs.String())
		}
	})
}

func TestAPlatformThatRefusesTheAgentIsAskedAgainOnlyAsItsHoldAllows(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sent := &platform{answers: []func() (transport.Reply, error){
			answered(403, &ingestv1.Rejection{Code: "agent_not_admitted", EventIndex: -1}),
			func() (transport.Reply, error) {
				return transport.Reply{Status: 404, ContentType: "text/plain", Body: []byte("404 page not found")}, nil
			},
		}}
		held := reporter(t, sent, directory(t), io.Discard)
		for range 2 {
			if wait := held.Report(t.Context()); wait < 2*time.Minute {
				t.Fatalf("a platform that refused the agent is asked again in %s", wait)
			}
		}
		if state := held.State(); state.Attempts != 2 || state.Outcome != "unexpected" || len(sent.sequences()) != 2 {
			t.Errorf("after two lasting refusals the reporter holds %+v", state)
		}
	})
}

func TestTheLastReportOfARunSaysTheAgentIsStoppingUnlessReportsAlreadyFail(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sent := &platform{}
		held := reporter(t, sent, directory(t), io.Discard)
		ctx, stop := context.WithCancel(t.Context())
		stopped := make(chan error, 1)
		go func() { stopped <- held.Run(ctx) }()
		synctest.Wait()
		stop()
		if err := <-stopped; err != nil {
			t.Fatalf("the reporter stopped with %v", err)
		}
		if len(sent.received) != 2 || sent.received[1].GetReports()[0].GetCondition() != agentv1.Status_CONDITION_STOPPED || sent.received[1].GetReports()[0].GetSequence() != 2 {
			t.Fatalf("as the agent stopped the platform received %d reports", len(sent.received))
		}

		failing := &platform{answers: []func() (transport.Reply, error){
			func() (transport.Reply, error) { return transport.Reply{}, transport.ErrUnreachable },
			func() (transport.Reply, error) { return transport.Reply{}, transport.ErrUnreachable },
			func() (transport.Reply, error) { return transport.Reply{}, transport.ErrUnreachable },
			func() (transport.Reply, error) { return transport.Reply{}, transport.ErrUnreachable },
			func() (transport.Reply, error) { return transport.Reply{}, transport.ErrUnreachable },
		}}
		unreached := reporter(t, failing, directory(t), io.Discard)
		ctx, stop = context.WithCancel(t.Context())
		go func() { stopped <- unreached.Run(ctx) }()
		time.Sleep(5 * time.Second)
		synctest.Wait()
		stop()
		<-stopped
		for _, batch := range failing.received {
			if batch.GetReports()[0].GetCondition() == agentv1.Status_CONDITION_STOPPED {
				t.Fatal("a reporter whose reports fail held the stop up to say it was stopping")
			}
		}
	})
}

func TestASequenceThatCannotBeReadBackIsTakenUpFromTheClock(t *testing.T) {
	root := directory(t)
	if err := root.WriteFile("sequence.json", []byte("not what the agent writes"), 0o600); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	sent := &platform{}
	before := uint64(time.Now().Unix())
	reporter(t, sent, root, &logs).Report(t.Context())
	if got := sent.sequences(); len(got) != 1 || got[0] <= before {
		t.Fatalf("after losing its count the reporter sent %v", got)
	}
	if !strings.Contains(logs.String(), "status_sequence_lost") {
		t.Errorf("the lost count was not reported:\n%s", logs.String())
	}
}

func TestAReportThePlatformWouldRefuseIsNeverSent(t *testing.T) {
	sent := &platform{}
	held, err := reporting.New(reporting.Options{
		Client:    sent,
		URL:       "https://gateway.example:8443",
		Directory: directory(t),
		Report: func(bool) *agentv1.Status {
			broken := report(false)
			broken.Privileges.User = ""
			return broken
		},
		Every:  func() time.Duration { return time.Minute },
		Logger: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	held.Report(t.Context())
	if len(sent.received) != 0 || held.State().Outcome != "unwritten" {
		t.Fatalf("a report missing its account was sent %d times, the reporter holds %+v", len(sent.received), held.State())
	}
}
