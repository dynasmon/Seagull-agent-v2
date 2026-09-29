package renewal_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/enrollment"
	"github.com/dynasmon/Seagull-agent-v2/internal/identity"
	"github.com/dynasmon/Seagull-agent-v2/internal/pki"
	"github.com/dynasmon/Seagull-agent-v2/internal/renewal"
	"github.com/dynasmon/Seagull-agent-v2/internal/transport"
)

const month = 720 * time.Hour

func TestARenewalKeepsAKeyYoungerThanItsLifetime(t *testing.T) {
	signing := authorityNamed(t, "Seagull agents")
	serving := listen(t, signing)
	held := enrolled(t, signing, "web-01", time.Hour)
	first := held.active(t)
	renewed, err := renewerFor(t, held, serving, []*x509.Certificate{signing.certificate}, month, renewal.Policy{}).renewer.Renew(t.Context())
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	next := held.active(t)
	if renewed.Rotated || next.Generation != 2 || next.KeyID != first.KeyID || !next.KeyDrawnAt.Equal(first.KeyDrawnAt) ||
		next.Certificate.FingerprintSHA256 == first.Certificate.FingerprintSHA256 {
		t.Fatalf("renewed %+v into %+v", first, next)
	}
	seen := serving.renewals()
	if len(seen) != 1 || seen[0].agent != "web-01" || seen[0].presented != first.KeyID || seen[0].requested != first.KeyID {
		t.Fatalf("the platform saw %+v", seen)
	}
	if pending, ok := held.installation.Pending(); ok {
		t.Fatalf("a renewal that was answered left the request %+v", pending)
	}
	if adopted, ok := held.installation.Trust(); ok || renewed.Adopted || renewed.Kept != nil {
		t.Fatalf("publishing the authorities the agent trusts already was adopted as %+v", adopted)
	}
}

func TestARenewalRotatesAKeyAsOldAsItsLifetime(t *testing.T) {
	signing := authorityNamed(t, "Seagull agents")
	serving := listen(t, signing)
	held := enrolled(t, signing, "web-01", time.Hour)
	first := held.active(t)
	renewed, err := renewerFor(t, held, serving, []*x509.Certificate{signing.certificate}, time.Nanosecond, renewal.Policy{}).renewer.Renew(t.Context())
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	next := held.active(t)
	if !renewed.Rotated || next.KeyID == first.KeyID || !next.KeyDrawnAt.After(first.KeyDrawnAt) {
		t.Fatalf("renewed %+v into %+v", first, next)
	}
	if seen := serving.renewals(); len(seen) != 1 || seen[0].presented != first.KeyID || seen[0].requested != next.KeyID {
		t.Fatalf("the platform saw %+v", seen)
	}
	if _, err := held.keys.Open(first.KeyID); err != nil {
		t.Fatalf("the key of the first generation is gone: %v", err)
	}
}

func TestARenewalInterruptedBeforeItsAnswerIsResumedWithTheSameKey(t *testing.T) {
	signing := authorityNamed(t, "Seagull agents")
	serving := listen(t, signing)
	held := enrolled(t, signing, "web-01", time.Hour)
	first := held.active(t)
	renewing := renewerFor(t, held, serving, []*x509.Certificate{signing.certificate}, time.Nanosecond, renewal.Policy{})
	serving.change(func(p *platform) { p.lose = true })
	if _, err := renewing.renewer.Renew(t.Context()); !errors.Is(err, transport.ErrUnreachable) || renewal.Lasting(err) {
		t.Fatalf("a renewal whose answer was lost returned %v", err)
	}
	pending, asked := held.installation.Pending()
	if active := held.active(t); active.Generation != 1 || !asked || pending.KeyID == first.KeyID {
		t.Fatalf("after a lost answer the installation holds %+v and asks for %+v (%t)", active, pending, asked)
	}

	serving.change(func(p *platform) { p.lose = false })
	if _, err := renewing.renewer.Renew(t.Context()); err != nil {
		t.Fatalf("renew again: %v", err)
	}
	seen := serving.renewals()
	if next := held.active(t); next.Generation != 2 || next.KeyID != pending.KeyID || len(seen) != 2 || seen[0].requested != seen[1].requested {
		t.Fatalf("after resuming, generation %d holds key %s; the platform saw %+v", next.Generation, next.KeyID, seen)
	}
}

func TestARenewalThePlatformRefusesChangesNothing(t *testing.T) {
	cases := []struct {
		name    string
		refuse  func(*platform)
		status  int
		code    string
		lasting bool
	}{
		{name: "a revoked agent", refuse: func(p *platform) { p.state = "revoked" }, status: http.StatusUnprocessableEntity, code: "illegal_move", lasting: true},
		{name: "a disabled agent", refuse: func(p *platform) { p.state = "disabled" }, status: http.StatusUnprocessableEntity, code: "illegal_move", lasting: true},
		{name: "an agent renewing too often", refuse: func(p *platform) { p.throttled = true }, status: http.StatusTooManyRequests, code: "rate_limited"},
		{name: "a platform that cannot sign", refuse: func(p *platform) { p.failures = 1 }, status: http.StatusServiceUnavailable, code: "certificate_not_signed"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			signing := authorityNamed(t, "Seagull agents")
			serving := listen(t, signing)
			held := enrolled(t, signing, "web-01", time.Hour)
			first := held.active(t)
			serving.change(c.refuse)
			_, err := renewerFor(t, held, serving, []*x509.Certificate{signing.certificate}, month, renewal.Policy{}).renewer.Renew(t.Context())
			var refused *renewal.Refusal
			if !errors.As(err, &refused) || refused.Status != c.status || refused.Code != c.code || renewal.Lasting(err) != c.lasting {
				t.Fatalf("the refusal read as %v", err)
			}
			if active := held.active(t); active.Generation != first.Generation || active.Certificate != first.Certificate {
				t.Fatalf("a refused renewal left %+v active", active)
			}
			if _, adopted := held.installation.Trust(); adopted {
				t.Fatal("a refused renewal adopted authorities")
			}
		})
	}
}

func TestAnAnswerThatIsNotTheCertificateAskedForIsNotActivated(t *testing.T) {
	signing := authorityNamed(t, "Seagull agents")
	serving := listen(t, signing)
	held := enrolled(t, signing, "web-01", time.Hour)
	first := held.active(t)
	stranger, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("draw a key: %v", err)
	}
	serving.change(func(p *platform) { p.foreign = stranger.Public() })
	_, err = renewerFor(t, held, serving, []*x509.Certificate{signing.certificate}, month, renewal.Policy{}).renewer.Renew(t.Context())
	if !errors.Is(err, enrollment.ErrMismatched) || !renewal.Lasting(err) {
		t.Fatalf("an answer for another key returned %v", err)
	}
	if active := held.active(t); active.Generation != first.Generation {
		t.Fatalf("an answer for another key activated %+v", active)
	}
}

// The authorities a platform rotating its own publishes: first the next one
// beside the current, then, once its listeners and agents moved, the next one
// alone. The agent trusts each set from the renewal that brought it, and a
// set that would not authenticate the listener it came from is not adopted.
func TestTheAuthoritiesThePlatformPublishesReplaceTheOnesTheAgentTrusts(t *testing.T) {
	current, next := authorityNamed(t, "Seagull agents 2026"), authorityNamed(t, "Seagull agents 2027")
	serving := listen(t, current)
	held := enrolled(t, current, "web-01", time.Hour)
	renewing := renewerFor(t, held, serving, []*x509.Certificate{current.certificate}, month, renewal.Policy{})
	retiring, moved := listen(t, current), listen(t, next)
	reaches := func(listener *platform) error {
		_, err := renewing.client.Check(t.Context(), listener.URL)
		return err
	}

	serving.change(func(p *platform) { p.published = []*x509.Certificate{current.certificate, next.certificate} })
	overlap, err := renewing.renewer.Renew(t.Context())
	if err != nil || !overlap.Adopted || overlap.Kept != nil || len(overlap.Authorities) != 2 {
		t.Fatalf("renewing while both authorities are published returned %+v, %v", overlap, err)
	}
	if err := reaches(moved); err != nil {
		t.Fatalf("a listener of the next authority was not authenticated once it was published: %v", err)
	}
	adopted, _ := held.installation.Trust()
	if kept, err := held.authorities.Open(adopted.Authorities); err != nil || len(kept) != 2 || adopted.Configured != pki.Digest([]*x509.Certificate{current.certificate}) {
		t.Fatalf("the installation adopted %+v holding %d authorities: %v", adopted, len(kept), err)
	}

	serving.change(func(p *platform) {
		p.published = []*x509.Certificate{next.certificate}
		p.agents = []*authority{current, next}
		p.signing = next
	})
	early, err := renewing.renewer.Renew(t.Context())
	if err != nil || early.Adopted || !errors.Is(early.Kept, renewal.ErrNotAdoptable) || len(early.Authorities) != 2 {
		t.Fatalf("renewing from a listener the published authorities would not authenticate returned %+v, %v", early, err)
	}
	if err := reaches(retiring); err != nil {
		t.Fatalf("the authorities were dropped although the listener that published them still needs them: %v", err)
	}

	serving.change(func(p *platform) { p.serving = next.server(t) })
	removed, err := renewing.renewer.Renew(t.Context())
	if err != nil || !removed.Adopted || len(removed.Authorities) != 1 || !removed.Authorities[0].Equal(next.certificate) {
		t.Fatalf("renewing once the previous authority is removed returned %+v, %v", removed, err)
	}
	if active := held.active(t); !strings.Contains(removed.Issuer, "2027") || active.Generation != 4 {
		t.Fatalf("the certificate of generation %d was issued by %s", active.Generation, removed.Issuer)
	}
	if err := reaches(retiring); !errors.Is(err, transport.ErrUntrusted) {
		t.Fatalf("a listener of the removed authority was still authenticated: %v", err)
	}
	if _, err := renewing.renewer.Renew(t.Context()); err != nil {
		t.Fatalf("renew under the next authority alone: %v", err)
	}
}

// Renewing hands the agent a new certificate and says nothing of the one it
// replaced: the platform honours it until it expires, and the agent keeps it
// with its key rather than assume either was revoked.
func TestTheGenerationARenewalReplacedIsKeptAndStillAuthenticates(t *testing.T) {
	signing := authorityNamed(t, "Seagull agents")
	serving := listen(t, signing)
	held := enrolled(t, signing, "web-01", time.Hour)
	first := held.active(t)
	if _, err := renewerFor(t, held, serving, []*x509.Certificate{signing.certificate}, time.Nanosecond, renewal.Policy{}).renewer.Renew(t.Context()); err != nil {
		t.Fatalf("renew: %v", err)
	}
	replaced, err := pki.OpenCredential(held.keys, held.certificates, first.KeyID, first.Certificate.FingerprintSHA256)
	if err != nil {
		t.Fatalf("the generation the renewal replaced is gone: %v", err)
	}
	client, err := transport.New(transport.Options{
		Authorities:      []*x509.Certificate{signing.certificate},
		Credentials:      fixed{credential: transport.Credential{Chain: replaced.Chain, Signer: replaced.Key}},
		ConnectTimeout:   time.Second,
		RequestTimeout:   2 * time.Second,
		MaxResponseBytes: 64 << 10,
		MaxConnections:   1,
	})
	if err != nil {
		t.Fatalf("compose a transport with the replaced generation: %v", err)
	}
	defer client.Close()
	if reply, err := client.Post(t.Context(), transport.Request{URL: serving.URL + renewal.Path, ContentType: "application/x-protobuf"}); err != nil || reply.Status == http.StatusUnauthorized {
		t.Fatalf("the replaced generation no longer authenticates: %+v, %v", reply, err)
	}
}

type fixed struct{ credential transport.Credential }

func (f fixed) Credential() (transport.Credential, error) { return f.credential, nil }

func TestAnEnrolledAgentRenewsWithoutAnOperator(t *testing.T) {
	signing := authorityNamed(t, "Seagull agents")
	signing.backdate = 0
	serving := listen(t, signing)
	serving.change(func(p *platform) { p.lifetime = 3 * time.Second })
	held := enrolled(t, signing, "web-01", 3*time.Second)
	renewing := renewerFor(t, held, serving, []*x509.Certificate{signing.certificate}, month, renewal.Policy{Retry: 20 * time.Millisecond, Longest: 100 * time.Millisecond, Recheck: 100 * time.Millisecond})
	ctx, cancel := context.WithCancel(t.Context())
	stopped := make(chan error, 1)
	go func() { stopped <- renewing.renewer.Run(ctx) }()
	deadline := time.After(20 * time.Second)
	for held.active(t).Generation < 3 {
		select {
		case <-deadline:
			t.Fatalf("the agent had not renewed twice within 20s:\n%v", renewing.logs.entries(t, "credential_not_renewed"))
		case <-time.After(50 * time.Millisecond):
		}
	}
	cancel()
	if err := <-stopped; err != nil {
		t.Fatalf("the renewal stopped with %v", err)
	}
	scheduled := renewing.logs.entries(t, "credential_renewal_scheduled")
	renewedLogs := renewing.logs.entries(t, "credential_renewed")
	if len(scheduled) < 3 || len(renewedLogs) < 2 || renewedLogs[0]["key"] != "kept" || renewedLogs[0]["credential_generation"] != float64(2) {
		t.Fatalf("the agent logged %v and %v", scheduled, renewedLogs)
	}
	if failed := renewing.logs.entries(t, "credential_not_renewed"); len(failed) != 0 {
		t.Fatalf("renewing without an operator failed: %v", failed)
	}
}

func TestARenewalThatFailsIsRetriedWithinItsBounds(t *testing.T) {
	signing := authorityNamed(t, "Seagull agents")
	signing.backdate = 0
	serving := listen(t, signing)
	held := enrolled(t, signing, "web-01", 4*time.Second)
	serving.change(func(p *platform) { p.failures = 3 })
	renewing := renewerFor(t, held, serving, []*x509.Certificate{signing.certificate}, month, renewal.Policy{Retry: 40 * time.Millisecond, Longest: 200 * time.Millisecond, Recheck: 50 * time.Millisecond})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	stopped := make(chan error, 1)
	go func() { stopped <- renewing.renewer.Run(ctx) }()
	deadline := time.After(20 * time.Second)
	for held.active(t).Generation < 2 {
		select {
		case <-deadline:
			t.Fatal("the agent did not renew once the platform recovered")
		case <-time.After(20 * time.Millisecond):
		}
	}
	cancel()
	<-stopped
	failed := renewing.logs.entries(t, "credential_not_renewed")
	if len(failed) != 3 {
		t.Fatalf("logged %d failed renewals, the platform failed 3", len(failed))
	}
	var previous time.Time
	for attempt, entry := range failed {
		next, err := time.Parse(time.RFC3339Nano, entry["next_attempt"].(string))
		at, err2 := time.Parse(time.RFC3339Nano, entry["time"].(string))
		if err != nil || err2 != nil || entry["level"] != "WARN" || entry["attempt"] != float64(attempt+1) || entry["recovery"] == "" {
			t.Fatalf("logged %v", entry)
		}
		wait := next.Sub(at)
		if base := min(40*time.Millisecond<<attempt, 200*time.Millisecond); wait < base*49/100 || wait > base*3/2 {
			t.Errorf("attempt %d waited %s", attempt+1, wait)
		}
		if entry["failure"] != "capacity" {
			t.Errorf("attempt %d failed as %v", attempt+1, entry["failure"])
		}
		if !at.After(previous) {
			t.Errorf("attempt %d was logged at %s", attempt+1, at)
		}
		previous = at
	}
}

func TestACredentialThatExpiredWaitsForAnOperator(t *testing.T) {
	signing := authorityNamed(t, "Seagull agents")
	signing.backdate = 0
	serving := listen(t, signing)
	held := enrolled(t, signing, "web-01", 2*time.Second)
	serving.change(func(p *platform) { p.state = "revoked" })
	renewing := renewerFor(t, held, serving, []*x509.Certificate{signing.certificate}, month, renewal.Policy{Retry: 50 * time.Millisecond, Longest: 100 * time.Millisecond, Recheck: 100 * time.Millisecond})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	stopped := make(chan error, 1)
	go func() { stopped <- renewing.renewer.Run(ctx) }()
	deadline := time.After(20 * time.Second)
	for len(renewing.logs.entries(t, "credential_expired")) == 0 {
		select {
		case <-deadline:
			t.Fatal("the agent did not report its credential expired")
		case <-time.After(100 * time.Millisecond):
		}
	}
	refused := renewing.logs.entries(t, "credential_not_renewed")
	time.Sleep(500 * time.Millisecond)
	cancel()
	<-stopped
	if len(refused) == 0 || refused[0]["level"] != "ERROR" || !strings.Contains(refused[0]["error"].(string), "illegal_move") {
		t.Fatalf("the refusals were logged as %v", refused)
	}
	if later := renewing.logs.entries(t, "credential_not_renewed"); len(later) != len(refused) {
		t.Fatalf("the agent kept asking with a certificate that expired: %d attempts, then %d", len(refused), len(later))
	}
	if expired := renewing.logs.entries(t, "credential_expired"); len(expired) != 1 || expired[0]["level"] != "ERROR" {
		t.Fatalf("the expiry was logged as %v", expired)
	}
	if active := held.active(t); active.Generation != 1 {
		t.Fatalf("a revoked agent moved to generation %d", active.Generation)
	}
}

func TestRenewalsAreSpreadAcrossTheLifetimeOfACertificate(t *testing.T) {
	signing := authorityNamed(t, "Seagull agents")
	serving := listen(t, signing)
	moments := map[time.Duration]bool{}
	for range 8 {
		held := enrolled(t, signing, "web-01", 12*time.Hour)
		active := held.active(t)
		renewer := renewerFor(t, held, serving, []*x509.Certificate{signing.certificate}, month, renewal.Policy{}).renewer
		due := renewer.Due(active)
		lifetime := active.Certificate.NotAfter.Sub(active.Certificate.NotBefore)
		into := due.Sub(active.Certificate.NotBefore)
		if into < lifetime*7/12 || into > lifetime*9/12 || !renewer.Due(active).Equal(due) {
			t.Fatalf("a certificate valid for %s renews %s into it", lifetime, into)
		}
		moments[into] = true
	}
	if len(moments) < 7 {
		t.Fatalf("eight installations renew at %d moments", len(moments))
	}
}

func TestComposingTheRenewalRefusesWhatItCannotKeep(t *testing.T) {
	signing := authorityNamed(t, "Seagull agents")
	serving := listen(t, signing)
	held := enrolled(t, signing, "web-01", time.Hour)
	trusted := []*x509.Certificate{signing.certificate}
	client := renewerFor(t, held, serving, trusted, month, renewal.Policy{}).client
	valid := func() renewal.Options {
		return renewal.Options{
			Installation: held.installation, Keys: held.keys, Certificates: held.certificates, Authorities: held.authorities,
			Client: client, URL: serving.URL, Trusted: trusted, Configured: pki.Digest(trusted),
			KeyLifetime: func() time.Duration { return month }, Logger: slog.New(slog.DiscardHandler),
		}
	}
	if _, err := renewal.New(valid()); err != nil {
		t.Fatalf("compose the renewal: %v", err)
	}
	for name, change := range map[string]func(*renewal.Options){
		"no installation":                 func(o *renewal.Options) { o.Installation = nil },
		"no transport":                    func(o *renewal.Options) { o.Client = nil },
		"a listener reached in the clear": func(o *renewal.Options) { o.URL = "http://127.0.0.1:8446" },
		"no authority trusted":            func(o *renewal.Options) { o.Trusted = nil },
		"no key lifetime":                 func(o *renewal.Options) { o.KeyLifetime = nil },
		"a wait that is negative":         func(o *renewal.Options) { o.Policy = renewal.Policy{Retry: -time.Second} },
		"a longest wait shorter than one": func(o *renewal.Options) { o.Policy = renewal.Policy{Retry: time.Hour, Longest: time.Minute} },
	} {
		options := valid()
		change(&options)
		if _, err := renewal.New(options); err == nil {
			t.Errorf("composed the renewal with %s", name)
		}
	}
}

func TestAFailureIsLastingOnlyWhenSomebodyHasToAct(t *testing.T) {
	cases := map[string]struct {
		err     error
		lasting bool
	}{
		"the network":                   {err: fmt.Errorf("%w: connection refused", transport.ErrUnreachable)},
		"a request never answered":      {err: fmt.Errorf("%w: context deadline exceeded", transport.ErrUnanswered)},
		"a platform that is busy":       {err: &renewal.Refusal{Status: http.StatusTooManyRequests, Code: "rate_limited"}},
		"a platform that is down":       {err: &renewal.Refusal{Status: http.StatusServiceUnavailable}},
		"a revoked agent":               {err: &renewal.Refusal{Status: http.StatusUnprocessableEntity, Code: "illegal_move"}, lasting: true},
		"an agent the platform forgot":  {err: &renewal.Refusal{Status: http.StatusNotFound, Code: "unknown_agent"}, lasting: true},
		"a certificate refused":         {err: fmt.Errorf("%w: bad certificate", transport.ErrRefused), lasting: true},
		"a platform not authenticated":  {err: fmt.Errorf("%w: unknown authority", transport.ErrUntrusted), lasting: true},
		"a credential that is unusable": {err: fmt.Errorf("%w: expired", transport.ErrUnauthenticated), lasting: true},
		"a key that is gone":            {err: fmt.Errorf("%w: there is no key", pki.ErrKeyMissing), lasting: true},
		"a state that cannot be kept":   {err: fmt.Errorf("%w: disk full", identity.ErrRefused), lasting: true},
	}
	for name, c := range cases {
		if renewal.Lasting(c.err) != c.lasting {
			t.Errorf("%s: lasting is %t", name, !c.lasting)
		}
	}
}

func TestNothingIsLeftOfARefusalButWhatAMessageMayCarry(t *testing.T) {
	marker := strings.Repeat("written", 36) + "-marker-tail"
	signing := authorityNamed(t, "Seagull agents")
	serving := listen(t, signing)
	held := enrolled(t, signing, "web-01", time.Hour)
	serving.change(func(p *platform) { p.state = marker })
	_, err := renewerFor(t, held, serving, []*x509.Certificate{signing.certificate}, month, renewal.Policy{}).renewer.Renew(t.Context())
	if err == nil || strings.Contains(err.Error(), "-marker-tail") || len(err.Error()) > 4<<10 {
		t.Fatalf("the refusal carries what the platform wrote:\n%v", err)
	}
	if _, err := os.Stat(filepath.Join(held.directory, "trust")); err != nil {
		t.Fatalf("the installation holds no trust directory: %v", err)
	}
}
