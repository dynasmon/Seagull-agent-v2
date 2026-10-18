package policy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/bits"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/link"
	"github.com/dynasmon/Seagull-agent-v2/internal/protocol"
	"github.com/dynasmon/Seagull-agent-v2/internal/secrets"
	"github.com/dynasmon/Seagull-agent-v2/internal/transport"
	controlv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/control/v1"
)

type Client interface {
	Get(ctx context.Context, request transport.Request) (transport.Reply, error)
}

type Answer string

const (
	Unasked     Answer = "unasked"
	Served      Answer = "served"
	Unchanged   Answer = "unchanged"
	NoPolicy    Answer = "no_policy"
	Unknown     Answer = "unknown_agent"
	NotAdmitted Answer = "agent_not_admitted"
	Failing     Answer = "failing"
	Unexpected  Answer = "unexpected"
)

type Options struct {
	Client   Client
	URL      string
	Tag      func() string
	Offered  func(ctx context.Context, served []byte) error
	Every    func() time.Duration
	Policy   link.Policy
	Logger   *slog.Logger
	Recovery func(error) string
	Now      func() time.Time
}

type State struct {
	Answer    Answer
	Asked     time.Time
	Since     time.Time
	Attempts  int
	Failure   string
	Next      time.Time
	Refused   string
	RefusedAt time.Time
}

// A Follower asks the platform for the policy that names the agent, every
// interval, naming the envelope the agent last judged so an unchanged policy
// costs a 304 and nothing else. Whatever it is handed goes to whoever applies
// it; what the platform answers otherwise is reported, and changes nothing the
// agent runs on.
type Follower struct {
	options Options
	target  string

	mu    sync.Mutex
	state State
}

func New(options Options) (*Follower, error) {
	var problems []error
	if options.Client == nil || options.Tag == nil || options.Offered == nil || options.Every == nil || options.Logger == nil {
		problems = append(problems, errors.New("a transport, what the agent holds, whoever applies a policy, an interval and a logger are all needed to follow a policy"))
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
		return nil, fmt.Errorf("follow the policy: %w", errors.Join(problems...))
	}
	if options.Recovery == nil {
		options.Recovery = func(error) string { return "" }
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	options.Policy = settled
	return &Follower{options: options, target: base.JoinPath(Path).String(), state: State{Answer: Unasked}}, nil
}

func (f *Follower) Run(ctx context.Context) error {
	for {
		wait := f.Ask(ctx)
		f.mu.Lock()
		f.state.Next = f.options.Now().Add(wait)
		f.mu.Unlock()
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

func (f *Follower) State() State {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.state
}

// Ask asks once and returns how long to wait before asking again: the interval
// drawn within a fifth of it either way while the platform answers, and a
// backoff while it does not.
func (f *Follower) Ask(ctx context.Context) time.Duration {
	request := transport.Request{URL: f.target, Most: MaxEnvelopeBytes}
	if tag := f.options.Tag(); tag != "" {
		request.Unchanged = strconv.Quote(tag)
	}
	reply, err := f.options.Client.Get(ctx, request)
	if ctx.Err() != nil {
		return 0
	}
	now := f.options.Now()
	if err != nil {
		class, known := link.Of(err)
		return f.failed(now, known && class.Lasting(), 0, err)
	}

	switch reply.Status {
	case http.StatusOK:
		f.answered(now, Served)
		if err := f.options.Offered(ctx, reply.Body); err != nil {
			f.refused(now, err)
		}
	case http.StatusNotModified:
		f.answered(now, Unchanged)
	case http.StatusNotFound, http.StatusForbidden, http.StatusUnauthorized:
		said := refusal(reply)
		answer := map[string]Answer{"no_policy": NoPolicy, "unknown_agent": Unknown, "agent_not_admitted": NotAdmitted}[said.GetCode()]
		if answer == "" {
			return f.failed(now, true, reply.RetryAfter, fmt.Errorf("the platform answered %d %s", reply.Status, secrets.Shown(said.GetCode())))
		}
		f.unserved(now, answer, said)
	case http.StatusTooManyRequests, http.StatusRequestTimeout:
		return f.failed(now, false, reply.RetryAfter, fmt.Errorf("the platform answered %d", reply.Status))
	default:
		if reply.Status >= http.StatusInternalServerError {
			return f.failed(now, false, reply.RetryAfter, fmt.Errorf("the platform answered %d %s", reply.Status, secrets.Shown(refusal(reply).GetCode())))
		}
		return f.failed(now, true, reply.RetryAfter, fmt.Errorf("the platform answered %d, which says nothing of a policy", reply.Status))
	}
	every := f.options.Every()
	return time.Duration(float64(every) * (0.8 + 0.4*rand.Float64()))
}

func refusal(reply transport.Reply) *controlv1.Refusal {
	var said controlv1.Refusal
	if protocol.Decode(reply.Body, &said, protocol.MaxAnswerValues) != nil {
		return &controlv1.Refusal{}
	}
	return &said
}

func (f *Follower) answered(now time.Time, answer Answer) {
	f.mu.Lock()
	defer f.mu.Unlock()
	recovered := f.state.Answer == Failing
	if f.state.Answer != answer {
		f.state.Since = now
	}
	f.state.Answer, f.state.Asked, f.state.Attempts, f.state.Failure = answer, now, 0, ""
	if recovered {
		f.options.Logger.Info("policy_asked_again", slog.String("answer", string(answer)))
	}
}

func (f *Follower) unserved(now time.Time, answer Answer, said *controlv1.Refusal) {
	f.mu.Lock()
	changed := f.state.Answer != answer
	f.mu.Unlock()
	f.answered(now, answer)
	if changed {
		f.options.Logger.Warn("policy_not_served", slog.String("answer", string(answer)),
			slog.String("detail", secrets.Bounded(said.GetDetail())))
	}
}

func (f *Follower) refused(now time.Time, err error) {
	f.mu.Lock()
	f.state.Refused, f.state.RefusedAt = secrets.Bounded(err.Error()), now
	f.mu.Unlock()
	f.options.Logger.Warn("policy_refused", slog.Any("error", err), slog.String("recovery", f.options.Recovery(err)))
}

func (f *Follower) failed(now time.Time, lasting bool, asked time.Duration, err error) time.Duration {
	f.mu.Lock()
	if f.state.Answer != Failing {
		f.state.Since = now
	}
	f.state.Answer, f.state.Asked = Failing, now
	f.state.Attempts++
	f.state.Failure = secrets.Bounded(err.Error())
	attempts := f.state.Attempts
	f.mu.Unlock()
	if bits.OnesCount(uint(attempts)) == 1 {
		f.options.Logger.Warn("policy_not_asked", slog.Int("attempt", attempts), slog.Any("error", err),
			slog.String("recovery", f.options.Recovery(err)))
	}
	return f.options.Policy.Wait(attempts, lasting, asked)
}
