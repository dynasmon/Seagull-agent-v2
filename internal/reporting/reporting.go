// Package reporting tells the platform how the agent runs: a status report
// every interval, on a stream of its own beside what the agent delivers, and a
// last one as it stops. A report stands on its own, so the agent sends its
// newest and keeps no backlog of older ones, and never makes the telemetry it
// describes wait.
package reporting

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/bits"
	"math/rand/v2"
	"net/url"
	"os"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-agent-v2/internal/link"
	"github.com/dynasmon/Seagull-agent-v2/internal/protocol"
	"github.com/dynasmon/Seagull-agent-v2/internal/secrets"
	"github.com/dynasmon/Seagull-agent-v2/internal/transport"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

const defaultStop = 5 * time.Second

type Client interface {
	Post(ctx context.Context, request transport.Request) (transport.Reply, error)
}

type Options struct {
	Client    Client
	URL       string
	Directory *os.Root
	Report    func(stopping bool) *agentv1.Status
	Every     func() time.Duration
	Policy    link.Policy
	Logger    *slog.Logger
	Recovery  func(error) string
	Now       func() time.Time
	Stop      time.Duration
}

type State struct {
	Reported time.Time
	Sequence uint64
	Failing  time.Time
	Attempts int
	Outcome  string
	Reason   string
	Recovery string
	Next     time.Time
}

type Reporter struct {
	options  Options
	target   string
	sequence *sequence

	mu    sync.Mutex
	state State
}

func New(options Options) (*Reporter, error) {
	var problems []error
	if options.Client == nil || options.Directory == nil || options.Report == nil || options.Every == nil || options.Logger == nil {
		problems = append(problems, errors.New("a transport, a directory, what to report, an interval and a logger are all needed to report the status"))
	}
	base, err := url.Parse(options.URL)
	if err != nil || base.Scheme != "https" || base.Host == "" {
		problems = append(problems, fmt.Errorf("the listener %s is not an https address", secrets.Address(options.URL)))
	}
	settled, err := options.Policy.Settled()
	if err != nil {
		problems = append(problems, err)
	}
	if len(problems) > 0 {
		return nil, fmt.Errorf("report the status: %w", errors.Join(problems...))
	}
	if options.Recovery == nil {
		options.Recovery = func(error) string { return "" }
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Stop <= 0 {
		options.Stop = defaultStop
	}
	options.Policy = settled
	counted, err := openSequence(options.Directory, options.Now())
	if err != nil {
		return nil, fmt.Errorf("report the status: %w", err)
	}
	if counted.lost != nil {
		options.Logger.Warn("status_sequence_lost", slog.Any("error", counted.lost), slog.Uint64("sequence", counted.last),
			slog.String("recovery", "nothing: the agent counts its reports on from the clock, past any it could have sent"))
	}
	return &Reporter{options: options, target: base.JoinPath(protocol.Status.Path()).String(), sequence: counted, state: State{Sequence: counted.last}}, nil
}

func (r *Reporter) Run(ctx context.Context) error {
	for {
		wait := r.Report(ctx)
		r.mu.Lock()
		r.state.Next = r.options.Now().Add(wait)
		r.mu.Unlock()
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			r.last()
			return nil
		case <-timer.C:
		}
	}
}

func (r *Reporter) State() State {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.state
}

// Report sends the newest report and returns how long to wait before the next
// one. A report the platform has not taken yet is sent again, the same bytes
// under the same sequence, until it is taken, refused, or due to be replaced:
// the next report says everything it said.
func (r *Reporter) Report(ctx context.Context) time.Duration {
	every := r.options.Every()
	due := r.options.Now().Add(time.Duration(float64(every) * (0.9 + 0.1*rand.Float64())))
	batch, sequence, err := r.write(false)
	if err != nil {
		r.failed("unwritten", false, 0, err)
		return every
	}
	for {
		outcome, lasting, asked, err := r.send(ctx, batch)
		if ctx.Err() != nil {
			return 0
		}
		now := r.options.Now()
		switch {
		case err == nil:
			r.reported(now, sequence)
			return max(due.Sub(now), 0)
		case outcome == protocol.RecordRefused, outcome == protocol.Disputed, outcome == protocol.BatchTooLarge, outcome == protocol.BatchUndecodable:
			r.failed(outcome.String(), false, 0, err)
			return max(due.Sub(now), 0)
		}
		wait := r.failed(outcome.String(), lasting, asked, err)
		if lasting || !now.Add(wait).Before(due) {
			return max(wait, due.Sub(now))
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return 0
		case <-timer.C:
		}
	}
}

// The last report of a run says the agent is stopping, so the platform tells
// an agent somebody stopped from one that went quiet. It is sent once, within
// a budget of its own, and not at all while reports already fail.
func (r *Reporter) last() {
	if r.State().Attempts > 0 {
		return
	}
	batch, _, err := r.write(true)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), r.options.Stop)
	defer cancel()
	if _, _, _, err := r.send(ctx, batch); err != nil {
		r.options.Logger.Debug("status_not_reported", slog.Bool("stopping", true), slog.Any("error", err))
	}
}

type batched struct {
	body     []byte
	encoded  []byte
	reported time.Time
}

func (r *Reporter) write(stopping bool) (batched, uint64, error) {
	report := r.options.Report(stopping)
	if report == nil {
		return batched{}, 0, errors.New("the agent has nothing to report yet")
	}
	sequence, err := r.sequence.next()
	if err != nil {
		return batched{}, 0, err
	}
	r.mu.Lock()
	r.state.Sequence = sequence
	r.mu.Unlock()
	reported := r.options.Now().UTC()
	report.Sequence, report.ReportedAt, report.Interval = sequence, timestamppb.New(reported), durationpb.New(r.options.Every())
	if err := protocol.CheckStatus(report); err != nil {
		return batched{}, 0, fmt.Errorf("the report the agent wrote is one the platform refuses: %w", err)
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(report)
	if err != nil {
		return batched{}, 0, fmt.Errorf("encode the report: %w", err)
	}
	id := fmt.Sprintf("%s.%d", report.GetInstallationId(), sequence)
	return batched{body: protocol.Status.Batch(id, [][]byte{encoded}), encoded: encoded, reported: reported}, sequence, nil
}

func (r *Reporter) send(ctx context.Context, batch batched) (protocol.Outcome, bool, time.Duration, error) {
	reply, err := r.options.Client.Post(ctx, transport.Request{
		URL:         r.target,
		ContentType: protocol.ContentType,
		Body:        bytes.NewReader(batch.body),
		Length:      int64(len(batch.body)),
	})
	if err != nil {
		class, known := link.Of(err)
		return protocol.Unconfirmed, known && class.Lasting(), 0, err
	}
	verdict := protocol.Status.Judge([]protocol.Sent{{Record: batch.encoded, Admitted: batch.reported}},
		protocol.Answer{Status: reply.Status, ContentType: reply.ContentType, Body: reply.Body, Date: reply.Date})
	switch verdict.Outcome {
	case protocol.Durable:
		return verdict.Outcome, false, 0, nil
	case protocol.Unconfirmed, protocol.Busy:
		return verdict.Outcome, false, reply.RetryAfter, verdict.Reason
	}
	return verdict.Outcome, true, reply.RetryAfter, verdict.Reason
}

func (r *Reporter) reported(now time.Time, sequence uint64) {
	r.mu.Lock()
	failing := r.state.Attempts > 0
	r.state = State{Reported: now, Sequence: sequence, Next: r.state.Next}
	r.mu.Unlock()
	if failing {
		r.options.Logger.Info("status_reported_again", slog.Uint64("sequence", sequence))
	}
}

// A failure is logged at its first attempt and each time the attempts double,
// as delivery does, so an outage of a day writes a handful of lines.
func (r *Reporter) failed(outcome string, lasting bool, asked time.Duration, err error) time.Duration {
	now, hint := r.options.Now(), r.options.Recovery(err)
	r.mu.Lock()
	if r.state.Attempts == 0 {
		r.state.Failing = now
	}
	r.state.Attempts++
	r.state.Outcome, r.state.Reason, r.state.Recovery = outcome, err.Error(), hint
	attempts := r.state.Attempts
	r.mu.Unlock()
	if bits.OnesCount(uint(attempts)) == 1 {
		r.options.Logger.Warn("status_not_reported", slog.Int("attempt", attempts), slog.String("outcome", outcome),
			slog.Any("error", err), slog.String("recovery", hint))
	}
	return r.options.Policy.Wait(attempts, lasting, asked)
}
