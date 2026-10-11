package policy_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-agent-v2/internal/link"
	"github.com/dynasmon/Seagull-agent-v2/internal/policy"
	"github.com/dynasmon/Seagull-agent-v2/internal/transport"
	controlv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/control/v1"
)

type answering struct {
	mu      sync.Mutex
	asked   []transport.Request
	replies []transport.Reply
	failure error
}

func (a *answering) Get(_ context.Context, request transport.Request) (transport.Reply, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.asked = append(a.asked, request)
	if a.failure != nil {
		return transport.Reply{}, a.failure
	}
	reply := a.replies[0]
	if len(a.replies) > 1 {
		a.replies = a.replies[1:]
	}
	return reply, nil
}

func refusing(t *testing.T, status int, code string) transport.Reply {
	t.Helper()
	body, err := proto.Marshal(&controlv1.Refusal{Code: code, Detail: "said the platform"})
	if err != nil {
		t.Fatal(err)
	}
	return transport.Reply{Status: status, Body: body}
}

type following struct {
	follower *policy.Follower
	client   *answering
	offered  [][]byte
	refuse   error
	tag      string
	log      *bytes.Buffer
}

func follow(t *testing.T, replies ...transport.Reply) *following {
	t.Helper()
	held := &following{client: &answering{replies: replies}, log: &bytes.Buffer{}}
	follower, err := policy.New(policy.Options{
		Client: held.client,
		URL:    "https://control.example:8446",
		Tag:    func() string { return held.tag },
		Offered: func(_ context.Context, served []byte) error {
			held.offered = append(held.offered, served)
			return held.refuse
		},
		Every:  func() time.Duration { return 10 * time.Minute },
		Policy: link.Policy{Retry: time.Second, RetryLongest: time.Minute, Hold: time.Minute, HoldLongest: time.Hour},
		Logger: slog.New(slog.NewJSONHandler(held.log, nil)),
		Now:    func() time.Time { return written },
	})
	if err != nil {
		t.Fatalf("follow: %v", err)
	}
	held.follower = follower
	return held
}

func TestTheAgentAsksForItsPolicyNamingWhatItHolds(t *testing.T) {
	held := follow(t, transport.Reply{Status: http.StatusOK, Body: []byte("an envelope")}, transport.Reply{Status: http.StatusNotModified})

	wait := held.follower.Ask(t.Context())
	if wait < 8*time.Minute || wait > 12*time.Minute {
		t.Fatalf("after a policy was handed the agent waits %s", wait)
	}
	if len(held.offered) != 1 || string(held.offered[0]) != "an envelope" || held.follower.State().Answer != policy.Served {
		t.Fatalf("what the platform handed was offered as %q and the follower says %+v", held.offered, held.follower.State())
	}
	held.tag = "4f1d"
	held.follower.Ask(t.Context())
	if state := held.follower.State(); state.Answer != policy.Unchanged || len(held.offered) != 1 {
		t.Fatalf("an unchanged policy was answered %+v and offered %d times", state, len(held.offered))
	}
	asked := held.client.asked
	switch {
	case asked[0].URL != "https://control.example:8446"+policy.Path || asked[0].Unchanged != "" || asked[0].Most != policy.MaxEnvelopeBytes:
		t.Fatalf("the agent first asked %+v", asked[0])
	case asked[1].Unchanged != `"4f1d"`:
		t.Fatalf("the agent asked again naming %q", asked[1].Unchanged)
	}
}

func TestWhatThePlatformAnswersBesidesAPolicyChangesNothing(t *testing.T) {
	for name, c := range map[string]struct {
		reply transport.Reply
		want  policy.Answer
	}{
		"no policy names the agent":      {reply: refusing(t, http.StatusNotFound, "no_policy"), want: policy.NoPolicy},
		"the agent is not registered":    {reply: refusing(t, http.StatusNotFound, "unknown_agent"), want: policy.Unknown},
		"the platform stopped listening": {reply: refusing(t, http.StatusForbidden, "agent_not_admitted"), want: policy.NotAdmitted},
	} {
		t.Run(name, func(t *testing.T) {
			held := follow(t, c.reply)
			for range 3 {
				if wait := held.follower.Ask(t.Context()); wait < 8*time.Minute {
					t.Fatalf("an answer the platform means is waited on for %s", wait)
				}
			}
			if state := held.follower.State(); state.Answer != c.want || len(held.offered) != 0 {
				t.Fatalf("the follower says %+v and offered %d", state, len(held.offered))
			}
			if logged := strings.Count(held.log.String(), `"policy_not_served"`); logged != 1 {
				t.Fatalf("the same answer was logged %d times", logged)
			}
		})
	}
}

func TestAPlatformThatDoesNotAnswerIsAskedAgainSooner(t *testing.T) {
	held := follow(t, transport.Reply{Status: http.StatusServiceUnavailable}, transport.Reply{Status: http.StatusServiceUnavailable}, transport.Reply{Status: http.StatusNotModified})
	first, second := held.follower.Ask(t.Context()), held.follower.Ask(t.Context())
	if state := held.follower.State(); state.Answer != policy.Failing || state.Attempts != 2 || first > 2*time.Second || second > 4*time.Second {
		t.Fatalf("a busy platform was waited on for %s then %s, and the follower says %+v", first, second, state)
	}
	held.follower.Ask(t.Context())
	if state := held.follower.State(); state.Answer != policy.Unchanged || state.Attempts != 0 {
		t.Fatalf("a platform answering again left %+v", state)
	}

	unreachable := follow(t)
	unreachable.client.failure = errors.Join(transport.ErrUntrusted, errors.New("a certificate nobody trusts"))
	if wait := unreachable.follower.Ask(t.Context()); wait < 30*time.Second {
		t.Fatalf("a platform the agent cannot authenticate is asked again after %s", wait)
	}
	if strings.Count(unreachable.log.String(), `"policy_not_asked"`) != 1 {
		t.Fatalf("a failure was not reported: %s", unreachable.log)
	}
}

func TestAPolicyTheAgentRefusesIsReportedAndChangesNothing(t *testing.T) {
	held := follow(t, transport.Reply{Status: http.StatusOK, Body: []byte("an envelope")})
	held.refuse = policy.ErrOlder
	held.follower.Ask(t.Context())
	state := held.follower.State()
	if state.Refused == "" || !state.RefusedAt.Equal(written) || !strings.Contains(held.log.String(), `"policy_refused"`) {
		t.Fatalf("a refused policy left %+v and logged %s", state, held.log)
	}
}

func TestFollowingStopsWhenTheAgentDoes(t *testing.T) {
	held := follow(t, transport.Reply{Status: http.StatusNotModified})
	ctx, cancel := context.WithCancel(t.Context())
	stopped := make(chan error, 1)
	go func() { stopped <- held.follower.Run(ctx) }()
	cancel()
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatalf("following stopped with %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("following did not stop")
	}
}
