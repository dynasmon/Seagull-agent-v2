package policy

import (
	"fmt"
	"math"
	"regexp"
	"slices"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/secrets"
)

const (
	MaxTargets   = 10_000
	MaxLifetime  = 366 * 24 * time.Hour
	MaxClockSkew = 5 * time.Minute
)

var identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

type Holding struct {
	Revision uint64
	Digest   string
}

// Whether a verified policy is one this agent applies, checked against the
// contract again rather than taken from the platform that checked it: it names
// the agent, its signer still vouches for it, and it is newer than the policy
// the agent holds — or that very policy, which the agent already runs on.
func Judge(verified Verified, agentID string, holding Holding, now time.Time) error {
	held := verified.Policy
	switch {
	case held.GetSchemaVersion() != SchemaVersion:
		return fmt.Errorf("%w: it is written to schema %d, and this agent reads %d", ErrMalformed, held.GetSchemaVersion(), SchemaVersion)
	case !identifier.MatchString(held.GetPolicyId()):
		return fmt.Errorf("%w: its policy_id %s is not an identifier", ErrMalformed, secrets.Shown(held.GetPolicyId()))
	case held.GetRevision() == 0 || held.GetRevision() > math.MaxInt64:
		return fmt.Errorf("%w: its revision is %d", ErrMalformed, held.GetRevision())
	}

	targets := held.GetTargets().GetAgentIds()
	switch {
	case len(targets) == 0 || len(targets) > MaxTargets:
		return fmt.Errorf("%w: it names %d agents, and a policy names between 1 and %d", ErrMalformed, len(targets), MaxTargets)
	case !slices.Contains(targets, agentID):
		return fmt.Errorf("%w: revision %d names %d agents, and %s is not one of them", ErrNotNamed, held.GetRevision(), len(targets), agentID)
	}

	issued, expires := held.GetIssuedAt(), held.GetExpiresAt()
	if issued == nil || issued.CheckValid() != nil || expires == nil || expires.CheckValid() != nil {
		return fmt.Errorf("%w: it does not say both when it was written and until when it holds", ErrMalformed)
	}
	written, ending := issued.AsTime(), expires.AsTime()
	switch {
	case written.After(now.Add(MaxClockSkew)):
		return fmt.Errorf("%w: it was written at %s, more than %s ahead of the agent's clock", ErrMalformed, written.UTC().Format(time.RFC3339), MaxClockSkew)
	case !ending.After(written):
		return fmt.Errorf("%w: it expires no later than it was written", ErrMalformed)
	case ending.Sub(written) > MaxLifetime:
		return fmt.Errorf("%w: its signer vouches for it for %s, and for at most %s", ErrMalformed, ending.Sub(written), MaxLifetime)
	case !ending.After(now):
		return fmt.Errorf("%w: revision %d expired at %s", ErrExpired, held.GetRevision(), ending.UTC().Format(time.RFC3339))
	}

	switch {
	case held.GetRevision() < holding.Revision:
		return fmt.Errorf("%w: it is revision %d, and the agent applied revision %d", ErrOlder, held.GetRevision(), holding.Revision)
	case held.GetRevision() == holding.Revision && verified.Digest != holding.Digest:
		return fmt.Errorf("%w: it is another policy under revision %d, which the agent already applied", ErrOlder, holding.Revision)
	}
	return nil
}
