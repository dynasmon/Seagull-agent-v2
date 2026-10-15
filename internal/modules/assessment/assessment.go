// Package assessment runs the checks of the signed policy the agent runs on
// against its host, and admits what they found to the spool as one
// assessment: every check of the policy revision answered once, in its order.
// It assesses as it starts, every interval, and as soon as the policy in force
// changes, and admits an assessment when what the checks found changed, or
// once the one the platform holds is a day old, give or take half an interval.
package assessment

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/governor"
	"github.com/dynasmon/Seagull-agent-v2/internal/protocol"
	"github.com/dynasmon/Seagull-agent-v2/internal/spool"
	assessmentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/assessment/v1"
)

const (
	everyHour  = time.Hour
	roundTime  = 5 * time.Minute
	refresh    = 24 * time.Hour
	frameBytes = 64
	mostLogged = 100
)

var (
	ErrBeyondBatch = errors.New("one batch carries no assessment this large")
	ErrClockBehind = errors.New("the clock is behind the last assessment the agent admitted")
)

type Spool interface {
	Admit(stream spool.Stream, records ...spool.Record) (spool.Receipt, error)
	Room(stream spool.Stream) int64
}

type Options struct {
	Installation string
	Spool        Spool
	Governor     *governor.Governor
	Directory    *os.Root
	Logger       *slog.Logger
	Asked        func() Asked
	Interval     func() time.Duration
	Within       time.Duration
	Largest      func() int64
	Host         Host
	Now          func() time.Time
}

type Stats struct {
	PolicyID string
	Revision uint64
	Checks   int
	Counts   Counts
	Assessed time.Time
	Sent     time.Time
	Waiting  time.Time
	Idle     string
	Failure  error
}

type Collector struct {
	options Options
	logger  *slog.Logger
	again   chan struct{}

	mu       sync.Mutex
	stats    Stats
	previous map[string]assessmentv1.Outcome
}

func New(options Options) (*Collector, error) {
	if options.Installation == "" || options.Spool == nil || options.Governor == nil || options.Directory == nil || options.Logger == nil || options.Asked == nil {
		return nil, fmt.Errorf("compose the %s module: an installation, a spool, a governor, a directory, a logger and the checks asked for are all needed to assess", Name)
	}
	if options.Interval == nil {
		options.Interval = func() time.Duration { return everyHour }
	}
	if options.Within <= 0 {
		options.Within = roundTime
	}
	if options.Largest == nil {
		options.Largest = func() int64 { return spool.MaxPayloadBytes }
	}
	if options.Host == nil {
		options.Host = System()
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	return &Collector{options: options, logger: options.Logger.With(slog.String("module", Name)), again: make(chan struct{}, 1)}, nil
}

// Collect assesses as it starts, then every interval, phased by the
// installation so a fleet does not assess at once, and whenever Again, which
// never waits, asks for an assessment out of turn, as when the policy in force
// changed, until ctx ends. It returns early only when what it admitted cannot
// be written down, or the spool takes nothing.
func (c *Collector) Collect(ctx context.Context) error {
	held, err := c.begin()
	if err != nil {
		return err
	}
	var schedule *governor.Schedule
	var every time.Duration
	for {
		select {
		case <-c.again:
		default:
		}
		if err := c.assess(ctx, &held); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if wanted := c.interval(); schedule == nil || wanted != every {
			if schedule, err = c.options.Governor.Periodic(Name, wanted); err != nil {
				return err
			}
			every = wanted
		}
		if _, err := schedule.Until(ctx, c.again); err != nil {
			return nil
		}
	}
}

func (c *Collector) Again() {
	select {
	case c.again <- struct{}{}:
	default:
	}
}

func (c *Collector) Stats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stats
}

func (c *Collector) begin() (baseline, error) {
	if err := discard(c.options.Directory); err != nil {
		return baseline{}, err
	}
	held, err := load(c.options.Directory)
	switch {
	case err == nil:
		c.mu.Lock()
		c.stats.Sent = held.AssessedAt
		c.mu.Unlock()
		return held, nil
	case errors.Is(err, errUnwritten):
		return baseline{Format: format}, nil
	case errors.Is(err, ErrDamaged):
		c.logger.Warn("assessment_baseline_lost", slog.Any("error", err),
			slog.String("reason", "the module cannot tell what it last admitted, so it admits its next assessment, which the platform keeps beside an equal one"),
			slog.String("recovery", "none"))
		return baseline{Format: format}, nil
	}
	return baseline{}, err
}

func (c *Collector) interval() time.Duration {
	if every := c.options.Interval(); every > 0 {
		return every
	}
	return everyHour
}

func (c *Collector) assess(ctx context.Context, held *baseline) error {
	asked := c.options.Asked()
	switch {
	case asked.PolicyID == "":
		c.idle("no policy is in force, so nothing asks for checks")
		return nil
	case len(asked.Checks) == 0 && held.Checks == 0:
		c.idle(fmt.Sprintf("revision %d of %s asks for no checks", asked.Revision, asked.PolicyID))
		return nil
	}
	began := time.Now()
	var results []*assessmentv1.Result
	err := c.options.Governor.Scan(ctx, governor.Scan{Module: Name, Room: c.room, Needs: held.needs()}, func(ctx context.Context, meter *governor.Meter) error {
		within, cancel := context.WithTimeout(ctx, c.options.Within)
		defer cancel()
		round := newRound(within, c.options.Host, asked.Checks)
		for _, check := range asked.Checks {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			results = append(results, round.answer(check))
		}
		return nil
	})
	if err != nil {
		return err
	}
	at := c.options.Now().UTC()
	hostname, _ := c.options.Host.Hostname()
	made, err := Make(c.options.Installation, asked, results, at, hostname)
	if err == nil {
		if largest := c.options.Largest(); int64(len(made.Encoded)) > largest {
			err = fmt.Errorf("%w: it encodes to %d bytes, and a batch of transport.max_batch_bytes carries %d of one", ErrBeyondBatch, len(made.Encoded), largest)
		}
	}
	why := ""
	if err == nil {
		why, err = c.judge(made, *held, at)
	}
	c.noted(asked, results, made, err, at)
	if err != nil || why == "" {
		c.logger.Debug("assessment_made", slog.Int("checks", len(results)), slog.Duration("took", time.Since(began)), slog.Bool("admitted", false))
		return nil
	}
	if err := c.admit(ctx, made); err != nil {
		return err
	}
	*held = baseline{Format: format, AssessedAt: at, AssessmentID: made.Record.GetAssessmentId(), PolicyID: asked.PolicyID, Revision: asked.Revision,
		Checks: len(results), Bytes: len(made.Encoded), Digest: made.Digest}
	if err := save(c.options.Directory, *held); err != nil {
		return err
	}
	c.mu.Lock()
	c.stats.Sent = at
	c.mu.Unlock()
	c.logger.Info("assessment_admitted", slog.String("assessment_id", made.Record.GetAssessmentId()), slog.String("policy_id", asked.PolicyID),
		slog.Uint64("revision", asked.Revision), slog.Int("checks", len(results)), slog.Int("passed", made.Counts.Passed), slog.Int("failed", made.Counts.Failed),
		slog.Int("errors", made.Counts.Errors), slog.Int("unsupported", made.Counts.Unsupported), slog.Int("not_applicable", made.Counts.NotApplicable),
		slog.Int("bytes", len(made.Encoded)), slog.Time("assessed_at", at), slog.String("because", why), slog.Duration("took", time.Since(began)))
	return nil
}

// judge says why an assessment is admitted, or nothing when it is not. The
// platform takes the newest assessment of an agent by when it was made, to the
// millisecond, so one made no later than the last the agent admitted would
// not be its posture: the agent waits for its clock to pass that one, unless
// that one was further ahead than any platform admits an assessment.
func (c *Collector) judge(made Assessment, last baseline, at time.Time) (string, error) {
	ahead := last.AssessmentID != "" && last.AssessedAt.Sub(at) > protocol.MaxClockSkew
	why := ""
	switch {
	case last.AssessmentID == "":
		return "first", nil
	case ahead:
		why = "the clock went back"
	case made.Digest != last.Digest:
		why = "changed"
	case !at.Before(last.AssessedAt.Add(refresh - c.interval()/2)):
		why = "refreshed"
	default:
		return "", nil
	}
	switch {
	case ahead:
		c.logger.Warn("assessment_clock_regressed", slog.Time("assessed_at", at), slog.Time("last", last.AssessedAt),
			slog.String("reason", "the last assessment the agent admitted was made further ahead than any platform admits, so the agent admits this one at the time its clock reads"),
			slog.String("recovery", "keep the clock of this host in time with the platform's"))
	case !at.Truncate(time.Millisecond).After(last.AssessedAt.Truncate(time.Millisecond)):
		return "", fmt.Errorf("%w: the clock reads %s, and the last assessment the agent admitted was made at %s", ErrClockBehind,
			at.Format(time.RFC3339Nano), last.AssessedAt.Format(time.RFC3339Nano))
	}
	return why, nil
}

// noted keeps what the round found for the status, and logs every check whose
// outcome changed since the round before, or that did not pass in the first
// round of this run, a bounded number of lines a round.
func (c *Collector) noted(asked Asked, results []*assessmentv1.Result, made Assessment, failed error, at time.Time) {
	c.mu.Lock()
	before, previous := c.stats.Failure, c.previous
	c.stats.PolicyID, c.stats.Revision, c.stats.Checks, c.stats.Counts = asked.PolicyID, asked.Revision, len(results), counted(results)
	c.stats.Assessed, c.stats.Idle, c.stats.Failure = at, "", failed
	c.previous = make(map[string]assessmentv1.Outcome, len(results))
	for _, result := range results {
		c.previous[result.GetCheckId()] = result.GetOutcome()
	}
	c.mu.Unlock()

	changed := 0
	for _, result := range results {
		was, held := previous[result.GetCheckId()]
		switch {
		case previous != nil && held && was == result.GetOutcome():
			continue
		case previous == nil && result.GetOutcome() == assessmentv1.Outcome_OUTCOME_PASS:
			continue
		}
		changed++
		if changed > mostLogged {
			continue
		}
		level := slog.LevelInfo
		if result.GetOutcome() == assessmentv1.Outcome_OUTCOME_FAIL || result.GetOutcome() == assessmentv1.Outcome_OUTCOME_ERROR {
			level = slog.LevelWarn
		}
		c.logger.Log(context.Background(), level, "assessment_check", slog.String("check_id", result.GetCheckId()),
			slog.String("outcome", outcomeName(result.GetOutcome())), slog.String("evidence", result.GetEvidence()),
			slog.String("policy_id", asked.PolicyID), slog.Uint64("revision", asked.Revision))
	}
	if changed > mostLogged {
		c.logger.Warn("assessment_checks_not_logged", slog.Int("checks", changed-mostLogged),
			slog.String("reason", fmt.Sprintf("a round logs at most %d checks whose outcome changed", mostLogged)),
			slog.String("recovery", "none: the assessment the agent admits answers every check"))
	}
	switch {
	case failed != nil && (before == nil || before.Error() != failed.Error()):
		message := "assessment_not_admitted"
		if errors.Is(failed, ErrClockBehind) {
			message = "assessment_deferred"
		}
		c.logger.Warn(message, slog.Any("error", failed), slog.String("recovery", Recovery(failed)))
	case failed == nil && before != nil:
		c.logger.Info("assessment_admissible_again")
	}
}

func (c *Collector) idle(reason string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stats.Idle != reason {
		c.logger.Info("assessment_idle", slog.String("reason", reason))
	}
	c.stats.Idle, c.stats.Failure = reason, nil
}

func Recovery(failed error) string {
	switch {
	case errors.Is(failed, ErrBeyondBatch):
		return "raise transport.max_batch_bytes, up to the 8MiB the platform takes, or sign a policy with fewer checks"
	case errors.Is(failed, ErrClockBehind):
		return "none: the agent admits its assessment once its clock passes the last one it admitted"
	}
	var inadmissible *protocol.Inadmissible
	if errors.As(failed, &inadmissible) {
		return "none: the platform would refuse the assessment, and the agent assesses again at its next round"
	}
	return "none: the agent assesses again at its next round"
}

func outcomeName(outcome assessmentv1.Outcome) string {
	switch outcome {
	case assessmentv1.Outcome_OUTCOME_PASS:
		return "pass"
	case assessmentv1.Outcome_OUTCOME_FAIL:
		return "fail"
	case assessmentv1.Outcome_OUTCOME_ERROR:
		return "error"
	case assessmentv1.Outcome_OUTCOME_UNSUPPORTED:
		return "unsupported"
	case assessmentv1.Outcome_OUTCOME_NOT_APPLICABLE:
		return "not_applicable"
	}
	return "unspecified"
}

func (r *round) answer(check *assessmentv1.Check) *assessmentv1.Result {
	outcome, evidence := assessmentv1.Outcome_OUTCOME_UNSUPPORTED, ""
	if err := unread(check); err != nil {
		evidence = err.Error()
	} else if r.ctx.Err() != nil {
		outcome, evidence = assessmentv1.Outcome_OUTCOME_ERROR, "the round ran out of the time it is given before this check: a source of the host took too long to read"
	} else {
		switch test := check.GetTest().(type) {
		case *assessmentv1.Check_File:
			outcome, evidence = r.file(test.File)
		case *assessmentv1.Check_Account:
			outcome, evidence = r.account(test.Account)
		case *assessmentv1.Check_KernelParameter:
			outcome, evidence = r.parameter(test.KernelParameter)
		case *assessmentv1.Check_KernelModule:
			outcome, evidence = r.module(test.KernelModule)
		case *assessmentv1.Check_Package:
			outcome, evidence = r.installed(test.Package)
		case *assessmentv1.Check_Service:
			outcome, evidence = r.service(test.Service)
		case *assessmentv1.Check_Directive:
			outcome, evidence = r.directive(test.Directive)
		}
	}
	return &assessmentv1.Result{CheckId: check.GetCheckId(), Outcome: outcome, Evidence: protocol.Cut(evidence, protocol.MaxAssessmentEvidence)}
}

func (c *Collector) room() int64 { return c.options.Spool.Room(spool.Assessments) }

func (c *Collector) admit(ctx context.Context, made Assessment) error {
	record := spool.Record{ID: made.Record.GetAssessmentId(), Payload: made.Encoded}
	need := int64(frameBytes + len(record.ID) + len(record.Payload))
	for {
		_, err := c.options.Spool.Admit(spool.Assessments, record)
		if !errors.Is(err, spool.ErrFull) {
			if err != nil {
				return fmt.Errorf("admit the assessment: %w", err)
			}
			return nil
		}
		c.wait(time.Now())
		err = c.options.Governor.Room(ctx, c.room, need)
		c.wait(time.Time{})
		if err != nil {
			return err
		}
	}
}

func (c *Collector) wait(since time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stats.Waiting = since
}
