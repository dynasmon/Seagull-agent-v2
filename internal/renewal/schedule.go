package renewal

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/identity"
	"github.com/dynasmon/Seagull-agent-v2/internal/link"
)

// When the next certificate is asked for, as a share of the lifetime of the
// active one: between seven and nine twelfths, drawn from the installation and
// the certificate, so a fleet issued its certificates at once does not renew
// them at once, and a restart does not move the moment.
const (
	earliest = 7.0 / 12
	spread   = 2.0 / 12
)

// A Policy bounds how often the agent asks: Retry after the first failure,
// doubling up to Longest, which is also the wait after a failure that needs
// somebody to act; and Recheck, the longest the agent waits before it looks at
// the clock again. A zero field takes the documented value.
type Policy struct {
	Retry   time.Duration
	Longest time.Duration
	Recheck time.Duration
}

func (p Policy) settled() (Policy, error) {
	if p.Retry < 0 || p.Longest < 0 || p.Recheck < 0 {
		return Policy{}, fmt.Errorf("a renewal policy of %+v waits a negative time", p)
	}
	for _, field := range []struct {
		held  *time.Duration
		value time.Duration
	}{{&p.Retry, time.Minute}, {&p.Longest, time.Hour}, {&p.Recheck, time.Hour}} {
		if *field.held == 0 {
			*field.held = field.value
		}
	}
	if p.Longest < p.Retry {
		return Policy{}, fmt.Errorf("a renewal policy waits at most %s after failing, less than the %s it waits first", p.Longest, p.Retry)
	}
	return p, nil
}

type State struct {
	RenewsAt time.Time
	Renewed  time.Time
	Failing  time.Time
	Attempts int
	Failure  link.Class
	Reason   string
	Recovery string
	Next     time.Time
}

func (r *Renewer) State() State {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.state
}

func (r *Renewer) note(change func(*State)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	change(&r.state)
}

func (p Policy) wait(failures int, lasting bool) time.Duration {
	return link.Policy{Retry: p.Retry, RetryLongest: p.Longest, Hold: p.Longest, HoldLongest: p.Longest}.Wait(failures, lasting, 0)
}

func (r *Renewer) Due(active identity.Enrollment) time.Time {
	digest := sha256.Sum256([]byte(r.options.Installation.ID() + "\x00" + active.Certificate.FingerprintSHA256))
	share := float64(binary.BigEndian.Uint64(digest[:8])) / math.MaxUint64
	lifetime := active.Certificate.NotAfter.Sub(active.Certificate.NotBefore)
	return active.Certificate.NotBefore.Add(time.Duration(float64(lifetime) * (earliest + spread*share)))
}

// Lasting says whether a failure needs somebody to act before a renewal can
// succeed: the platform refused it, or the credential, the answer or what the
// agent trusts is wrong. The network and a platform that is busy or down are
// not, and are retried sooner.
func Lasting(err error) bool {
	var refused *Refusal
	if errors.As(err, &refused) {
		return refused.Status < http.StatusInternalServerError && refused.Status != http.StatusTooManyRequests && refused.Status != http.StatusRequestTimeout
	}
	class, classified := link.Of(err)
	return !classified || class.Lasting()
}

func failure(err error) (link.Class, bool) {
	var refused *Refusal
	if !errors.As(err, &refused) {
		return link.Of(err)
	}
	switch refused.Status {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusUnprocessableEntity:
		return link.Authorization, true
	case http.StatusTooManyRequests:
		return link.Capacity, true
	}
	return link.Capacity, refused.Status >= http.StatusInternalServerError
}

func (r *Renewer) Run(ctx context.Context) error {
	logger := r.options.Logger
	var (
		failures int
		retry    time.Time
		said     string
		planned  string
	)
	for {
		active, enrolled := r.options.Installation.Enrollment()
		if !enrolled {
			return ErrNotEnrolled
		}
		now, certificate := time.Now(), active.Certificate
		switch {
		case now.Before(certificate.NotBefore):
			if said != "early" {
				said = "early"
				logger.Warn("credential_not_valid_yet", slog.String("agent_id", active.AgentID), slog.Uint64("credential_generation", active.Generation),
					slog.Time("not_before", certificate.NotBefore), slog.String("recovery", "correct the clock of this host, which is behind the platform's"))
			}
			if !r.sleep(ctx, r.options.Policy.Recheck) {
				return nil
			}
			continue
		case !now.Before(certificate.NotAfter):
			if said != "expired" {
				said = "expired"
				logger.Error("credential_expired", slog.String("agent_id", active.AgentID), slog.Uint64("credential_generation", active.Generation),
					slog.Time("not_after", certificate.NotAfter), slog.String("recovery", r.options.Recovery(ErrExpired)))
			}
			if !r.sleep(ctx, r.options.Policy.Recheck) {
				return nil
			}
			continue
		}
		said = ""
		due := r.Due(active)
		r.note(func(state *State) { state.RenewsAt = due })
		if planned != certificate.FingerprintSHA256 {
			planned = certificate.FingerprintSHA256
			logger.Info("credential_renewal_scheduled", slog.String("agent_id", active.AgentID), slog.Uint64("credential_generation", active.Generation),
				slog.Time("not_after", certificate.NotAfter), slog.Time("renews_at", due))
		}
		if retry.After(due) {
			due = retry
		}
		if now.Before(due) {
			if !r.sleep(ctx, min(due.Sub(now), r.options.Policy.Recheck)) {
				return nil
			}
			continue
		}
		renewed, err := r.Renew(ctx)
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			failures++
			lasting := Lasting(err)
			now := time.Now()
			retry = now.Add(r.options.Policy.wait(failures, lasting))
			class, _ := failure(err)
			recovery := r.options.Recovery(err)
			r.note(func(state *State) {
				if failures == 1 {
					state.Failing = now
				}
				state.Attempts, state.Failure, state.Reason, state.Recovery, state.Next = failures, class, err.Error(), recovery, retry
			})
			level := slog.LevelWarn
			if lasting {
				level = slog.LevelError
			}
			attributes := []any{slog.String("agent_id", active.AgentID), slog.Uint64("credential_generation", active.Generation)}
			if class != 0 {
				attributes = append(attributes, slog.String("failure", class.String()))
			}
			logger.Log(ctx, level, "credential_not_renewed", append(attributes, slog.Any("error", err), slog.Int("attempt", failures),
				slog.Time("next_attempt", retry), slog.Time("not_after", certificate.NotAfter), slog.String("recovery", recovery))...)
			continue
		}
		failures, retry = 0, time.Time{}
		r.note(func(state *State) { *state = State{RenewsAt: r.Due(renewed.Enrollment), Renewed: time.Now()} })
		r.report(renewed)
	}
}

func (r *Renewer) report(renewed Renewed) {
	logger, next := r.options.Logger, renewed.Enrollment
	key, authorities := "kept", "unchanged"
	if renewed.Rotated {
		key = "rotated"
	}
	switch {
	case renewed.Adopted:
		authorities = "adopted"
	case renewed.Kept != nil:
		authorities = "kept"
	}
	logger.Info("credential_renewed", slog.String("agent_id", next.AgentID), slog.Uint64("credential_generation", next.Generation),
		slog.String("key", key), slog.String("key_id", next.KeyID), slog.String("serial", next.Certificate.Serial),
		slog.Time("not_after", next.Certificate.NotAfter), slog.Time("renews_at", r.Due(next)),
		slog.String("authorities", authorities), slog.Int("trusted", len(renewed.Authorities)))
	if renewed.Kept != nil {
		logger.Warn("authorities_not_adopted", slog.String("agent_id", next.AgentID), slog.Any("error", renewed.Kept),
			slog.String("recovery", r.options.Recovery(renewed.Kept)))
	}
}

func (r *Renewer) sleep(ctx context.Context, wait time.Duration) bool {
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
