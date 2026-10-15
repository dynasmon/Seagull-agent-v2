package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/config"
	"github.com/dynasmon/Seagull-agent-v2/internal/identity"
	"github.com/dynasmon/Seagull-agent-v2/internal/modules/assessment"
	"github.com/dynasmon/Seagull-agent-v2/internal/policy"
	"github.com/dynasmon/Seagull-agent-v2/internal/status"
)

const policyDirectory = "policy"

// What the agent holds of the policies the platform hands it. The envelope it
// last applied is kept, in force or not, so it is verified again whenever the
// keys the agent accepts change, and its revision is the floor no policy the
// agent applies later may go below.
type policies struct {
	store    *policy.Store
	agentID  string
	verifier *policy.Verifier

	envelope  []byte
	held      policy.Holding
	applied   *policy.Verified
	appliedAt time.Time
	kept      []policy.Kept
	withdrawn error
	judged    string
	refused   error
	refusedAt time.Time
	expired   bool
}

type offering struct {
	served []byte
	answer chan error
}

func (c *configuration) hold(installation *identity.Installation, agentID string, now time.Time) error {
	directory, err := installation.Directory(policyDirectory)
	if err != nil {
		return err
	}
	store, err := policy.Open(directory)
	if err != nil {
		return err
	}
	keys, err := c.local.Policy.Keys()
	if err != nil {
		return err
	}
	verifier, err := policy.NewVerifier(keys)
	if err != nil {
		return err
	}
	held := &policies{store: store, agentID: agentID, verifier: verifier}
	c.policies = held

	stored, found, err := store.Read()
	switch {
	case errors.Is(err, policy.ErrDamaged), errors.Is(err, policy.ErrNewer):
		c.logger.Warn("policy_not_read_back", slog.Any("error", err), slog.String("recovery", recovery(c.path, "", err)))
		return nil
	case err != nil:
		return err
	case !found:
		return nil
	}
	held.envelope, held.held, held.judged = stored.Envelope, stored.Holding, stored.Digest
	verified, candidate, kept, err := c.lay(verifier, stored.Envelope, c.local, now)
	if err != nil {
		held.withdrawn = err
		c.logger.Warn("policy_not_applied", slog.Uint64("revision", stored.Revision), slog.Any("error", err),
			slog.String("running_on", "the configuration file alone"), slog.String("recovery", recovery(c.path, "", err)))
		return nil
	}
	if err := c.active.Reload(candidate); err != nil {
		return err
	}
	held.applied, held.appliedAt, held.kept = &verified, stored.AppliedAt, kept
	c.applying(verified, kept, "held", candidate)
	apply(candidate, c.level)
	resources(c.logger, candidate)
	return nil
}

// A policy the agent applied stays in force once it expires, until a newer one
// replaces it: whatever else would have to decide what the agent runs on is a
// configuration nobody signed.
func (c *configuration) lay(verifier *policy.Verifier, envelope []byte, local config.Config, now time.Time) (policy.Verified, config.Config, []policy.Kept, error) {
	verified, err := verifier.Verify(envelope)
	if err != nil {
		return policy.Verified{}, config.Config{}, nil, err
	}
	if err := policy.Judge(verified, c.policies.agentID, policy.Holding{}, now); err != nil && !errors.Is(err, policy.ErrExpired) {
		return policy.Verified{}, config.Config{}, nil, err
	}
	candidate, kept, err := policy.Overlay(local, verified.Policy.GetSettings())
	if err != nil {
		return policy.Verified{}, config.Config{}, nil, err
	}
	return verified, candidate, kept, nil
}

// What the platform handed is applied by the goroutine that applies the
// configuration file, so the two never interleave. A refusal is answered to
// whoever asked and changes nothing; a configuration the agent cannot apply
// once it decided to is an error of the agent's own, as a reload's is.
func (c *configuration) adopt(served []byte) (refused error, failed error) {
	held, now := c.policies, time.Now()
	verified, err := held.verifier.Verify(served)
	if err == nil {
		err = policy.Judge(verified, held.agentID, held.held, now)
	}
	if err == nil && held.applied != nil && verified.Digest == held.applied.Digest {
		return nil, nil
	}
	var candidate config.Config
	var kept []policy.Kept
	if err == nil {
		candidate, kept, err = policy.Overlay(c.local, verified.Policy.GetSettings())
	}
	if err == nil {
		_, err = held.store.Keep(verified, now)
	}
	if err != nil {
		sum := sha256.Sum256(served)
		c.mu.Lock()
		held.judged, held.refused, held.refusedAt = hex.EncodeToString(sum[:]), err, now
		c.mu.Unlock()
		return err, nil
	}
	if err := c.active.Reload(candidate); err != nil {
		return nil, fmt.Errorf("apply revision %d of the policy: %w", verified.Policy.GetRevision(), err)
	}
	c.mu.Lock()
	held.envelope, held.held = verified.Envelope, policy.Holding{Revision: verified.Policy.GetRevision(), Digest: verified.Digest}
	held.applied, held.appliedAt, held.kept, held.judged = &verified, now, kept, verified.Digest
	held.withdrawn, held.refused, held.expired = nil, nil, false
	c.mu.Unlock()
	c.applying(verified, kept, "handed", candidate)
	if err := c.activate(candidate); err != nil {
		return nil, err
	}
	resources(c.logger, candidate)
	return nil, nil
}

// Reading the configuration file again reads the keys a policy is accepted
// under again too: a policy no key the agent now accepts signed is withdrawn,
// and one that verifies again is put back in force. A file the policy in force
// cannot be laid over is refused, as a file the agent does not run on is.
func (c *configuration) over(local config.Config) (config.Config, func(), error) {
	held, now := c.policies, time.Now()
	keys, err := local.Policy.Keys()
	if err != nil {
		return config.Config{}, nil, err
	}
	verifier, err := policy.NewVerifier(keys)
	if err != nil {
		return config.Config{}, nil, err
	}
	if len(held.envelope) == 0 {
		return local, func() { held.verifier, held.judged = verifier, "" }, nil
	}
	verified, candidate, kept, err := c.lay(verifier, held.envelope, local, now)
	switch {
	case err == nil:
		return candidate, func() {
			if held.applied == nil {
				c.applying(verified, kept, "verified again", candidate)
				held.appliedAt = now
			}
			held.verifier, held.applied, held.kept, held.withdrawn, held.judged = verifier, &verified, kept, nil, held.held.Digest
		}, nil
	case held.applied != nil && errors.Is(err, policy.ErrInapplicable):
		return config.Config{}, nil, fmt.Errorf("revision %d of the policy, which the agent runs on, cannot be laid over it: %w", held.held.Revision, err)
	}
	return local, func() {
		if held.applied != nil {
			c.logger.Warn("policy_withdrawn", slog.Uint64("revision", held.held.Revision), slog.Any("error", err),
				slog.String("running_on", "the configuration file alone"), slog.String("recovery", recovery(c.path, "", err)))
		}
		held.verifier, held.applied, held.kept, held.withdrawn, held.judged = verifier, nil, nil, err, held.held.Digest
	}, nil
}

func (c *configuration) applying(verified policy.Verified, kept []policy.Kept, how string, candidate config.Config) {
	c.level.Set(min(c.level.Level(), candidate.Logging.Severity()))
	attributes := []any{
		slog.String("how", how),
		slog.Uint64("revision", verified.Policy.GetRevision()),
		slog.String("policy_id", verified.Policy.GetPolicyId()),
		slog.Any("signed_by", verified.SignedBy),
		slog.Time("expires_at", verified.Policy.GetExpiresAt().AsTime()),
	}
	for _, own := range kept {
		attributes = append(attributes, slog.String("kept_"+strings.ReplaceAll(own.Setting, ".", "_"), own.Own))
	}
	c.logger.Info("policy_applied", attributes...)
}

func (c *configuration) asking() string {
	held := c.policies
	c.mu.Lock()
	defer c.mu.Unlock()
	if held.applied != nil && !held.expired && !held.applied.Policy.GetExpiresAt().AsTime().After(time.Now()) {
		held.expired = true
		c.logger.Warn("policy_expired", slog.Uint64("revision", held.held.Revision),
			slog.Time("expired_at", held.applied.Policy.GetExpiresAt().AsTime()),
			slog.String("running_on", "the policy that expired, until a newer one is handed"),
			slog.String("recovery", recovery(c.path, "", policy.ErrExpired)))
	}
	return held.judged
}

func (c *configuration) policied(follower *policy.Follower, now time.Time) status.Component {
	if c.policies == nil {
		return status.Component{Name: "policy", State: status.Disabled, Reason: "the agent asks for no policy: it is not enrolled, or policy.signers names no key"}
	}
	c.mu.Lock()
	held := *c.policies
	c.mu.Unlock()
	asked := policy.State{Answer: policy.Unasked}
	if follower != nil {
		asked = follower.State()
	}
	component := status.Component{Name: "policy", State: status.Running, Since: held.appliedAt.UTC()}
	switch {
	case held.applied != nil:
		component.Reason = status.Text(fmt.Sprintf("the agent runs on revision %d of %s, signed by %s, until %s%s",
			held.held.Revision, held.applied.Policy.GetPolicyId(), strings.Join(held.applied.SignedBy, ", "),
			held.applied.Policy.GetExpiresAt().AsTime().UTC().Format(time.RFC3339), keeping(held.kept)))
	case asked.Answer == policy.NoPolicy:
		component.Since, component.Reason = asked.Since.UTC(), "no policy names this agent: it runs on its configuration file alone"
	default:
		component.Since, component.Reason = asked.Since.UTC(), "no policy is in force: the agent runs on its configuration file alone"
	}
	expiry := time.Time{}
	if held.applied != nil {
		expiry = held.applied.Policy.GetExpiresAt().AsTime()
	}
	switch {
	case held.withdrawn != nil:
		component.State, component.Reason = status.Degraded, status.Text(fmt.Sprintf("revision %d of the policy is not in force: %v", held.held.Revision, held.withdrawn))
		component.Recovery = status.Text(recovery(c.path, "", held.withdrawn))
	case held.applied != nil && !expiry.After(now):
		component.State, component.Since = status.Degraded, expiry.UTC()
		component.Reason = status.Text(fmt.Sprintf("revision %d of the policy expired at %s, and the agent keeps it until it is handed a newer one", held.held.Revision, expiry.UTC().Format(time.RFC3339)))
		component.Recovery = status.Text(recovery(c.path, "", policy.ErrExpired))
	case held.refused != nil:
		component.State, component.Since = status.Degraded, held.refusedAt.UTC()
		component.Reason = status.Text(fmt.Sprintf("the agent refused the policy it was handed last: %v", held.refused))
		component.Recovery = status.Text(recovery(c.path, "", held.refused))
	case asked.Answer == policy.Failing:
		component.State, component.Since = status.Degraded, asked.Since.UTC()
		component.Reason = status.Text("the agent cannot ask for its policy, and keeps the one it holds: " + asked.Failure)
		component.Recovery = "none while the platform is unreachable: the agent asks again"
	case slices.Contains([]policy.Answer{policy.Unknown, policy.NotAdmitted}, asked.Answer):
		component.State, component.Since = status.Degraded, asked.Since.UTC()
		component.Reason = status.Text(fmt.Sprintf("the platform answers %s when the agent asks for its policy, and the agent keeps the one it holds", asked.Answer))
		component.Recovery = "an operator registers and admits the agent the platform issued this installation's certificate for"
	}
	return component
}

func keeping(kept []policy.Kept) string {
	if len(kept) == 0 {
		return ""
	}
	written := make([]string, 0, len(kept))
	for _, own := range kept {
		written = append(written, fmt.Sprintf("%s at %s rather than %s", own.Setting, own.Own, own.Asked))
	}
	return "; its own configuration keeps " + strings.Join(written, ", ")
}

func (c *configuration) checklist() assessment.Asked {
	if c.policies == nil {
		return assessment.Asked{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.policies.applied == nil {
		return assessment.Asked{}
	}
	applied := c.policies.applied.Policy
	return assessment.Asked{PolicyID: applied.GetPolicyId(), Revision: applied.GetRevision(), Checks: applied.GetSettings().GetAssessment().GetChecks()}
}

func (c *configuration) inForce() (string, uint64, time.Time) {
	if c.policies == nil {
		return "", 0, time.Time{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.policies.applied == nil {
		return "", 0, time.Time{}
	}
	applied := c.policies.applied.Policy
	return applied.GetPolicyId(), applied.GetRevision(), applied.GetExpiresAt().AsTime()
}
