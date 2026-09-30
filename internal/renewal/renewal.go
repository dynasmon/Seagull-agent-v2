// Package renewal keeps the credential of an enrolled installation current.
// Before the certificate of the active generation expires, it asks the
// platform's renewal listener, as the agent that certificate names, for the
// next one, and activates it once it verifies. The platform decides whether it
// still renews the agent, and the agent never enrolls itself again when it
// does not: an expired, refused or revoked credential waits for an operator.
package renewal

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-agent-v2/internal/enrollment"
	"github.com/dynasmon/Seagull-agent-v2/internal/identity"
	"github.com/dynasmon/Seagull-agent-v2/internal/pki"
	"github.com/dynasmon/Seagull-agent-v2/internal/secrets"
	"github.com/dynasmon/Seagull-agent-v2/internal/transport"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
	controlv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/control/v1"
)

const (
	Path        = "/v1/agents/certificate"
	contentType = "application/x-protobuf"
)

var (
	ErrNotEnrolled   = errors.New("the installation holds no credential to renew")
	ErrExpired       = errors.New("the certificate of the active credential generation expired")
	ErrNotAdoptable  = errors.New("the authorities the platform published do not authenticate its renewal listener")
	errNoAuthorities = errors.New("the renewal listener presented no certificate")
)

type Client interface {
	Post(ctx context.Context, request transport.Request) (transport.Reply, error)
	Trust(authorities []*x509.Certificate) error
}

type Options struct {
	Installation *identity.Installation
	Keys         pki.KeyProvider
	Certificates *pki.CertificateFiles
	Authorities  *pki.AuthorityFiles
	Client       Client
	URL          string
	Trusted      []*x509.Certificate
	Configured   string
	KeyLifetime  func() time.Duration
	Policy       Policy
	Logger       *slog.Logger
	Recovery     func(error) string
}

type Renewer struct {
	options Options
	target  *url.URL
	trusted []*x509.Certificate

	mu    sync.Mutex
	state State
}

type Renewed struct {
	Enrollment  identity.Enrollment
	Rotated     bool
	Issuer      string
	Adopted     bool
	Kept        error
	Authorities []*x509.Certificate
}

// A Refusal is the platform's answer to a renewal it did not grant, with the
// code and the explanation it gave, as a message may carry them.
type Refusal struct {
	Status int
	Code   string
	Detail string
}

func (r *Refusal) Error() string {
	if r.Code == "" {
		return fmt.Sprintf("the platform answered the renewal with %d %s", r.Status, http.StatusText(r.Status))
	}
	return fmt.Sprintf("the platform answered the renewal with %d %s: %s", r.Status, r.Code, r.Detail)
}

func New(options Options) (*Renewer, error) {
	var problems []error
	if options.Installation == nil || options.Keys == nil || options.Certificates == nil || options.Authorities == nil || options.Client == nil {
		problems = append(problems, errors.New("an installation, its keys, certificates and authorities, and a transport are all needed to renew"))
	}
	target, err := url.Parse(options.URL)
	if err != nil || target.Scheme != "https" || target.Hostname() == "" {
		problems = append(problems, errors.New("the renewal listener is an https address with a host"))
	}
	if len(options.Trusted) == 0 || options.KeyLifetime == nil || options.Logger == nil {
		problems = append(problems, errors.New("the authorities trusted now, a key lifetime and a logger are all needed to renew"))
	}
	policy, err := options.Policy.settled()
	if err != nil {
		problems = append(problems, err)
	}
	if len(problems) > 0 {
		return nil, fmt.Errorf("compose the renewal: %w", errors.Join(problems...))
	}
	options.Policy = policy
	if options.Recovery == nil {
		options.Recovery = func(error) string { return "" }
	}
	target.Path += Path
	return &Renewer{options: options, target: target, trusted: options.Trusted}, nil
}

// Renew asks for the next certificate once, now. It keeps the key of the
// active generation while that key is younger than the key lifetime and draws
// a new one otherwise, records the request before it is sent, and resumes a
// request an earlier attempt did not see answered with the same key.
func (r *Renewer) Renew(ctx context.Context) (Renewed, error) {
	now := time.Now()
	active, enrolled := r.options.Installation.Enrollment()
	if !enrolled {
		return Renewed{}, ErrNotEnrolled
	}
	key, rotated, err := r.key(active, now)
	if err != nil {
		return Renewed{}, err
	}
	requested, err := pki.Request(key, active.AgentID)
	if err != nil {
		return Renewed{}, err
	}
	body, err := proto.Marshal(&agentv1.RenewalRequest{CsrPem: requested})
	if err != nil {
		return Renewed{}, fmt.Errorf("encode the renewal: %w", err)
	}
	reply, err := r.options.Client.Post(ctx, transport.Request{URL: r.target.String(), ContentType: contentType, Body: bytes.NewReader(body), Length: int64(len(body))})
	if err != nil {
		return Renewed{}, err
	}
	if reply.Status != http.StatusCreated {
		return Renewed{}, refusal(reply)
	}
	published, err := enrollment.Published(reply.Body)
	if err != nil {
		return Renewed{}, err
	}
	imported, err := enrollment.Import(r.options.Installation, r.options.Keys, r.options.Certificates, published, reply.Body, time.Now())
	if err != nil {
		return Renewed{}, err
	}
	renewed := Renewed{Enrollment: imported.Enrollment, Rotated: rotated, Issuer: imported.Issuer}
	renewed.Adopted, renewed.Kept = r.adopt(published, reply.Peer, time.Now())
	renewed.Authorities = r.trusted
	return renewed, nil
}

func (r *Renewer) key(active identity.Enrollment, now time.Time) (pki.Key, bool, error) {
	if pending, ok := r.options.Installation.Pending(); ok && pending.AgentID == active.AgentID {
		key, err := r.options.Keys.Open(pending.KeyID)
		switch {
		case err == nil:
			return key, pending.KeyID != active.KeyID, nil
		case !errors.Is(err, pki.ErrKeyMissing) && !errors.Is(err, pki.ErrKeyDamaged):
			return nil, false, err
		}
	}
	rotated := active.KeyDrawnAt.IsZero() || now.Sub(active.KeyDrawnAt) >= r.options.KeyLifetime()
	var key pki.Key
	var err error
	if rotated {
		key, err = r.options.Keys.Create()
	} else {
		key, err = r.options.Keys.Open(active.KeyID)
	}
	if err != nil {
		return nil, false, err
	}
	if err := r.options.Installation.Ask(identity.Request{AgentID: active.AgentID, KeyID: key.ID(), RequestedAt: now.UTC()}); err != nil {
		return nil, false, err
	}
	return key, rotated, nil
}

// The authorities an answer publishes arrived over a connection the agent
// authenticated against the ones it trusts, from the platform its credential
// authenticated to, so they replace those. Only a set that still authenticates
// the listener that answered is adopted: one that does not would leave the
// agent unable to reach the platform to be told better.
func (r *Renewer) adopt(published, peer []*x509.Certificate, now time.Time) (bool, error) {
	if pki.Digest(published) == pki.Digest(r.trusted) {
		return false, nil
	}
	if len(peer) == 0 {
		return false, errNoAuthorities
	}
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	for _, authority := range published {
		roots.AddCert(authority)
	}
	for _, certificate := range peer[1:] {
		intermediates.AddCert(certificate)
	}
	if _, err := peer[0].Verify(x509.VerifyOptions{
		DNSName:       r.target.Hostname(),
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return false, fmt.Errorf("%w: %s", ErrNotAdoptable, secrets.Bounded(err.Error()))
	}
	stored, err := r.options.Authorities.Store(published)
	if err == nil {
		err = r.options.Installation.Adopt(identity.Trust{Authorities: stored, Configured: r.options.Configured, AdoptedAt: now.UTC()})
	}
	if err == nil {
		err = r.options.Client.Trust(published)
	}
	if err != nil {
		return false, err
	}
	r.trusted = published
	return true, nil
}

func refusal(reply transport.Reply) error {
	refused := &Refusal{Status: reply.Status}
	var told controlv1.Refusal
	if err := proto.Unmarshal(reply.Body, &told); err == nil {
		refused.Code, refused.Detail = secrets.Bounded(told.GetCode()), secrets.Bounded(told.GetDetail())
	}
	return refused
}
