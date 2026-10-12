package update

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/bits"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-agent-v2/internal/link"
	"github.com/dynasmon/Seagull-agent-v2/internal/secrets"
	"github.com/dynasmon/Seagull-agent-v2/internal/transport"
	controlv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/control/v1"
	updatev1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/update/v1"
)

const (
	transferRate  = 256 << 10
	transferGrace = 30 * time.Second
)

type Client interface {
	Get(ctx context.Context, request transport.Request) (transport.Reply, error)
}

type Options struct {
	Client   Client
	URL      string
	Anchor   *Root
	Store    *Store
	Staging  *Staging
	Journal  func() (Journal, bool, error)
	Running  Running
	Every    func() time.Duration
	Policy   link.Policy
	Logger   *slog.Logger
	Recovery func(error) string
	Now      func() time.Time
}

// Where the newest update the platform asked of the agent stands, as the agent
// knows it, and when it last asked.
type State struct {
	Stage    Stage
	Version  string
	Catalog  uint64
	Root     uint64
	Since    time.Time
	Failure  Failure
	Reason   string
	Asked    time.Time
	Asking   string
	Attempts int
	Next     time.Time
}

type Follower struct {
	options  Options
	base     *url.URL
	tag      string
	offered  []byte
	stagedAs string

	mu    sync.Mutex
	state State
}

func NewFollower(options Options) (*Follower, error) {
	var problems []error
	if options.Client == nil || options.Anchor == nil || options.Store == nil || options.Staging == nil ||
		options.Journal == nil || options.Every == nil || options.Logger == nil {
		problems = append(problems, errors.New("a transport, the provisioned root, a store, a staging area, the installer's journal, an interval and a logger are all needed to follow updates"))
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
		return nil, fmt.Errorf("follow updates: %w", errors.Join(problems...))
	}
	if options.Recovery == nil {
		options.Recovery = func(error) string { return "" }
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	options.Policy = settled
	return &Follower{options: options, base: base}, nil
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

// Ask asks once whether to update, acts on the answer, and returns how long to
// wait before asking again.
func (f *Follower) Ask(ctx context.Context) time.Duration {
	request := transport.Request{URL: f.base.JoinPath(Path).String(), Most: MaxOfferBytes}
	if f.tag != "" {
		request.Unchanged = f.tag
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
	switch {
	case reply.Status == http.StatusOK:
		f.tag, f.offered = reply.Tag, reply.Body
	case reply.Status == http.StatusNotModified:
	case reply.Status == http.StatusNotFound || reply.Status == http.StatusForbidden:
		f.tag, f.offered = "", nil
	case reply.Status == http.StatusTooManyRequests || reply.Status == http.StatusRequestTimeout || reply.Status >= http.StatusInternalServerError:
		return f.failed(now, false, reply.RetryAfter, fmt.Errorf("the platform answered %d %s", reply.Status, secrets.Shown(refusal(reply).GetCode())))
	default:
		return f.failed(now, true, reply.RetryAfter, fmt.Errorf("the platform answered %d, which says nothing of an update", reply.Status))
	}
	f.mu.Lock()
	f.state.Asked, f.state.Asking, f.state.Attempts = now, strconv.Itoa(reply.Status), 0
	f.mu.Unlock()
	f.consider(ctx, now)
	every := f.options.Every()
	return time.Duration(float64(every) * (0.8 + 0.4*rand.Float64()))
}

func (f *Follower) consider(ctx context.Context, now time.Time) {
	journal, found, err := f.options.Journal()
	if err != nil {
		f.options.Logger.Warn("update_journal_unread", slog.Any("error", err))
		found = false
	}
	switch {
	case found && !journal.Done():
		f.reported(journal.state())
		return
	case f.options.Staging.Ready():
		f.mu.Lock()
		staged := f.state.Stage == Staged
		f.mu.Unlock()
		if !staged {
			f.reported(State{Stage: Staged, Since: now})
		}
		return
	case f.offered == nil:
		f.settled(journal, found)
		return
	}

	var offer updatev1.Offer
	if err := proto.Unmarshal(f.offered, &offer); err != nil {
		f.reported(State{Stage: Failed, Since: now, Failure: Unverified, Reason: "the platform's offer is not one the agent reads"})
		return
	}
	held, err := f.options.Store.Held(f.options.Anchor, now)
	if err != nil {
		f.options.Logger.Warn("update_trust_unread", slog.Any("error", err), slog.String("recovery", f.options.Recovery(err)))
	}
	judged, err := Judge(&offer, held, f.options.Running, now)
	if progressed := judged.Held(); progressed.Root.Version() > held.Root.Version() || progressed.Catalog > held.Catalog {
		if kept := f.options.Store.Keep(progressed); kept != nil {
			f.options.Logger.Warn("update_trust_unkept", slog.Any("error", kept))
		}
	}
	about := State{Version: offer.GetVersion(), Root: judged.Root.Version(), Since: now}
	if judged.Catalog != nil {
		about.Catalog = judged.Catalog.Version()
	}
	if err != nil {
		about.Stage, about.Failure, about.Reason = Failed, failureOf(err), explained(err.Error())
		f.reported(about)
		return
	}
	if judged.Target == nil {
		f.settled(journal, found)
		return
	}
	if found && journal.Stage != Installed && journal.Version == judged.Target.GetVersion() && journal.Catalog == about.Catalog {
		f.reported(journal.state())
		return
	}

	attempt := judged.Target.GetVersion() + "@" + strconv.FormatUint(about.Catalog, 10)
	if f.stagedAs != attempt {
		if err := f.options.Staging.Clear(); err != nil {
			f.options.Logger.Warn("update_staging_uncleared", slog.Any("error", err))
		}
		f.stagedAs = attempt
	}
	about.Stage = Downloading
	f.reported(about)
	for _, release := range []*updatev1.Release{judged.Target, judged.Current} {
		if err := f.options.Staging.Fetch(release, func(into io.Writer) error { return f.download(ctx, release, into) }); err != nil {
			about.Failure, about.Reason = Unreachable, explained(err.Error())
			if errors.Is(err, ErrUnverified) {
				about.Stage, about.Failure = Failed, Unverified
			}
			f.reported(about)
			return
		}
	}
	if err := f.options.Staging.Hand(f.offered); err != nil {
		about.Stage, about.Failure, about.Reason = Failed, Installation, explained(err.Error())
		f.reported(about)
		return
	}
	about.Stage, about.Since = Staged, f.options.Now()
	f.reported(about)
}

func (f *Follower) download(ctx context.Context, release *updatev1.Release, into io.Writer) error {
	size := release.GetPayload().GetSize()
	reply, err := f.options.Client.Get(ctx, transport.Request{
		URL:    f.base.JoinPath(PackagesPath, hex.EncodeToString(release.GetPayload().GetSha256())).String(),
		Most:   int64(size),
		Into:   into,
		Within: transferGrace + time.Duration(size/transferRate)*time.Second,
	})
	switch {
	case err != nil:
		return err
	case reply.Status != http.StatusOK:
		return fmt.Errorf("the platform answered %d %s for the package of %s", reply.Status, secrets.Shown(refusal(reply).GetCode()), release.GetVersion())
	}
	return nil
}

// What the agent reports once nothing is asked of it: how the last update the
// installer took ended, or nothing.
func (f *Follower) settled(journal Journal, found bool) {
	if found {
		f.reported(journal.state())
		return
	}
	f.reported(State{})
}

func (f *Follower) reported(next State) {
	f.mu.Lock()
	before := f.state
	changed := before.Stage != next.Stage || before.Version != next.Version || before.Failure != next.Failure || before.Catalog != next.Catalog
	f.state.Stage, f.state.Version, f.state.Catalog, f.state.Root = next.Stage, next.Version, next.Catalog, next.Root
	f.state.Failure, f.state.Reason = next.Failure, next.Reason
	if changed {
		f.state.Since = next.Since
	}
	f.mu.Unlock()
	if !changed || next.Stage == "" {
		return
	}
	attributes := []any{slog.String("stage", string(next.Stage)), slog.String("version", next.Version),
		slog.Uint64("catalog", next.Catalog), slog.Uint64("root", next.Root)}
	if next.Failure != "" {
		attributes = append(attributes, slog.String("failure", string(next.Failure)), slog.String("reason", next.Reason))
		f.options.Logger.Warn("update_"+string(next.Stage), attributes...)
		return
	}
	f.options.Logger.Info("update_"+string(next.Stage), attributes...)
}

func (f *Follower) failed(now time.Time, lasting bool, asked time.Duration, err error) time.Duration {
	f.mu.Lock()
	f.state.Asked, f.state.Asking = now, "failing"
	f.state.Attempts++
	attempts := f.state.Attempts
	f.mu.Unlock()
	if bits.OnesCount(uint(attempts)) == 1 {
		f.options.Logger.Warn("update_not_asked", slog.Int("attempt", attempts), slog.Any("error", err),
			slog.String("recovery", f.options.Recovery(err)))
	}
	return f.options.Policy.Wait(attempts, lasting, asked)
}

func (j Journal) state() State {
	return State{Stage: j.Stage, Version: j.Version, Catalog: j.Catalog, Root: j.Root, Since: j.Since, Failure: j.Failure, Reason: j.Reason}
}

func failureOf(err error) Failure {
	if errors.Is(err, ErrUnsigned) || errors.Is(err, ErrMalformed) || errors.Is(err, ErrUnverified) {
		return Unverified
	}
	return Refused
}

func refusal(reply transport.Reply) *controlv1.Refusal {
	var said controlv1.Refusal
	if proto.Unmarshal(reply.Body, &said) != nil {
		return &controlv1.Refusal{}
	}
	return &said
}
