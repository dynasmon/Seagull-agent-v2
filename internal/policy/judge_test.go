package policy_test

import (
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-agent-v2/internal/policy"
	policyv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/policy/v1"
)

var judged = written.Add(time.Hour)

func TestAPolicyIsAppliedOnlyByAnAgentItNamesAndOnlyForward(t *testing.T) {
	held := policy.Holding{Revision: 5, Digest: "applied"}
	for name, c := range map[string]struct {
		change  func(*policyv1.Policy)
		digest  string
		holding policy.Holding
		want    error
	}{
		"a newer revision naming the agent":          {change: func(*policyv1.Policy) {}, holding: held},
		"the policy the agent already applied":       {change: func(p *policyv1.Policy) { p.Revision = 5 }, digest: "applied", holding: held},
		"the first policy an agent is handed":        {change: func(*policyv1.Policy) {}},
		"a policy naming other agents":               {change: func(p *policyv1.Policy) { p.Targets.AgentIds = []string{"web-02"} }, want: policy.ErrNotNamed},
		"an older revision":                          {change: func(p *policyv1.Policy) { p.Revision = 4 }, holding: held, want: policy.ErrOlder},
		"another policy under the applied revision":  {change: func(p *policyv1.Policy) { p.Revision = 5 }, digest: "other", holding: held, want: policy.ErrOlder},
		"a policy that expired":                      {change: func(p *policyv1.Policy) { p.ExpiresAt = timestamppb.New(judged) }, want: policy.ErrExpired},
		"a newer schema":                             {change: func(p *policyv1.Policy) { p.SchemaVersion = 2 }, want: policy.ErrMalformed},
		"a policy id that is not one":                {change: func(p *policyv1.Policy) { p.PolicyId = "linux web" }, want: policy.ErrMalformed},
		"revision zero":                              {change: func(p *policyv1.Policy) { p.Revision = 0 }, want: policy.ErrMalformed},
		"no target":                                  {change: func(p *policyv1.Policy) { p.Targets = nil }, want: policy.ErrMalformed},
		"no issue time":                              {change: func(p *policyv1.Policy) { p.IssuedAt = nil }, want: policy.ErrMalformed},
		"no expiry":                                  {change: func(p *policyv1.Policy) { p.ExpiresAt = nil }, want: policy.ErrMalformed},
		"written well ahead of the agent's clock":    {change: func(p *policyv1.Policy) { p.IssuedAt = timestamppb.New(judged.Add(time.Hour)) }, want: policy.ErrMalformed},
		"an expiry before it was written":            {change: func(p *policyv1.Policy) { p.ExpiresAt = timestamppb.New(written.Add(-time.Hour)) }, want: policy.ErrMalformed},
		"vouched for longer than a signer may vouch": {change: func(p *policyv1.Policy) { p.ExpiresAt = timestamppb.New(written.Add(policy.MaxLifetime + time.Second)) }, want: policy.ErrMalformed},
	} {
		t.Run(name, func(t *testing.T) {
			held := named(6, "web-01", "web-03")
			c.change(held)
			digest := c.digest
			if digest == "" {
				digest = "newer"
			}
			err := policy.Judge(policy.Verified{Policy: held, Digest: digest}, "web-01", c.holding, judged)
			if !errors.Is(err, c.want) || (c.want == nil) != (err == nil) {
				t.Fatalf("the policy was judged %v, and %v was expected", err, c.want)
			}
		})
	}
}
