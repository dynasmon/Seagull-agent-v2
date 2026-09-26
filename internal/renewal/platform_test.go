package renewal_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-agent-v2/internal/enrollment"
	"github.com/dynasmon/Seagull-agent-v2/internal/identity"
	"github.com/dynasmon/Seagull-agent-v2/internal/pki"
	"github.com/dynasmon/Seagull-agent-v2/internal/renewal"
	"github.com/dynasmon/Seagull-agent-v2/internal/transport"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
	controlv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/control/v1"
)

type authority struct {
	certificate *x509.Certificate
	key         *ecdsa.PrivateKey
	backdate    time.Duration
}

var serials atomic.Int64

func authorityNamed(t *testing.T, name string) *authority {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("draw the key of %s: %v", name, err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(serials.Add(1)),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(48 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	signed, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatalf("sign %s: %v", name, err)
	}
	certificate, err := x509.ParseCertificate(signed)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return &authority{certificate: certificate, key: key, backdate: time.Minute}
}

func (a *authority) server(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("draw the key of a listener: %v", err)
	}
	signed, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(serials.Add(1)),
		Subject:      pkix.Name{CommonName: "control-api"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, a.certificate, key.Public(), a.key)
	if err != nil {
		t.Fatalf("issue the certificate of a listener: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{signed}, PrivateKey: key}
}

// What the recorded platform's authority signs from a request: the agent it
// names and the key it carries, a random serial, a minute of backdating, a
// validity of lifetime, and nothing but a signature for client authentication.
func (a *authority) sign(t *testing.T, agentID string, public crypto.PublicKey, lifetime time.Duration) *x509.Certificate {
	t.Helper()
	certificate, err := a.signed(agentID, public, lifetime)
	if err != nil {
		t.Fatalf("sign a certificate for %s: %v", agentID, err)
	}
	return certificate
}

func (a *authority) signed(agentID string, public crypto.PublicKey, lifetime time.Duration) (*x509.Certificate, error) {
	now := time.Now().UTC().Truncate(time.Second)
	signed, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber:          big.NewInt(serials.Add(1) + 1<<40),
		Subject:               pkix.Name{CommonName: agentID},
		NotBefore:             now.Add(-a.backdate),
		NotAfter:              now.Add(lifetime),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}, a.certificate, public, a.key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(signed)
}

func answer(t *testing.T, signed *x509.Certificate, chain, published []*x509.Certificate) []byte {
	t.Helper()
	encoded, err := answered(signed, chain, published)
	if err != nil {
		t.Fatalf("encode the answer: %v", err)
	}
	return encoded
}

func answered(signed *x509.Certificate, chain, published []*x509.Certificate) ([]byte, error) {
	digest := sha256.Sum256(signed.Raw)
	return proto.Marshal(&agentv1.IssuedCertificate{
		CertificatePem: encode(signed),
		ChainPem:       encode(chain...),
		TrustBundlePem: encode(published...),
		Identity: &agentv1.Identity{
			Subject:           signed.Subject.CommonName,
			Serial:            hex.EncodeToString(signed.SerialNumber.Bytes()),
			FingerprintSha256: hex.EncodeToString(digest[:]),
			IssuedAt:          timestamppb.New(signed.NotBefore),
			ExpiresAt:         timestamppb.New(signed.NotAfter),
		},
	})
}

func encode(certificates ...*x509.Certificate) []byte {
	var written []byte
	for _, certificate := range certificates {
		written = append(written, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})...)
	}
	return written
}

type renewed struct {
	agent     string
	presented string
	requested string
}

// A renewal listener set up as the recorded platform's is: TLS 1.3, a
// certificate required of every client and verified against the authorities
// that issue agents theirs, the agent read off that certificate, and a
// certificate signed only for a request naming that agent while the platform
// still admits it. What it presents, trusts, signs with and publishes can be
// changed while it serves, as a platform rotating its authority changes them.
type platform struct {
	*httptest.Server
	mu        sync.Mutex
	serving   tls.Certificate
	agents    []*authority
	signing   *authority
	published []*x509.Certificate
	lifetime  time.Duration
	state     string
	failures  int
	throttled bool
	lose      bool
	foreign   crypto.PublicKey
	seen      []renewed
}

func listen(t *testing.T, signing *authority) *platform {
	t.Helper()
	serving := &platform{
		serving:   signing.server(t),
		agents:    []*authority{signing},
		signing:   signing,
		published: []*x509.Certificate{signing.certificate},
		lifetime:  time.Hour,
		state:     "active",
	}
	serving.Server = httptest.NewUnstartedServer(http.HandlerFunc(serving.renew))
	serving.Config.ErrorLog = log.New(io.Discard, "", 0)
	serving.TLS = &tls.Config{
		MinVersion: tls.VersionTLS13,
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			serving.mu.Lock()
			defer serving.mu.Unlock()
			agents := x509.NewCertPool()
			for _, issuer := range serving.agents {
				agents.AddCert(issuer.certificate)
			}
			return &tls.Config{
				MinVersion:   tls.VersionTLS13,
				Certificates: []tls.Certificate{serving.serving},
				ClientAuth:   tls.RequireAndVerifyClientCert,
				ClientCAs:    agents,
			}, nil
		},
	}
	serving.StartTLS()
	t.Cleanup(serving.Close)
	return serving
}

func (p *platform) change(change func(*platform)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	change(p)
}

func (p *platform) renewals() []renewed {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]renewed(nil), p.seen...)
}

func (p *platform) renew(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != renewal.Path {
		refuse(w, http.StatusNotFound, "not_found", "the renewal listener serves nothing else")
		return
	}
	if len(r.TLS.VerifiedChains) == 0 {
		refuse(w, http.StatusUnauthorized, "no_client_certificate", "the connection carries no verified client certificate")
		return
	}
	presented := r.TLS.VerifiedChains[0][0]
	agent := presented.Subject.CommonName
	content, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 32<<10))
	var asked agentv1.RenewalRequest
	if err == nil {
		err = proto.Unmarshal(content, &asked)
	}
	if err != nil {
		refuse(w, http.StatusBadRequest, "unreadable_request", "the request body is not the message this route reads")
		return
	}
	block, _ := pem.Decode(asked.GetCsrPem())
	var requested *x509.CertificateRequest
	if block != nil {
		requested, err = x509.ParseCertificateRequest(block.Bytes)
	}
	if block == nil || err != nil || requested.CheckSignature() != nil || requested.Subject.CommonName != agent {
		refuse(w, http.StatusUnprocessableEntity, "malformed_certificate_request", "the certificate signing request cannot be signed")
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	presentedKey, _ := pki.KeyID(presented.PublicKey)
	requestedKey, _ := pki.KeyID(requested.PublicKey)
	switch {
	case p.failures > 0:
		p.failures--
		refuse(w, http.StatusServiceUnavailable, "certificate_not_signed", "the platform could not answer this request; it has been recorded")
		return
	case p.throttled:
		refuse(w, http.StatusTooManyRequests, "rate_limited", "this agent is renewing too often")
		return
	case p.state != "active":
		refuse(w, http.StatusUnprocessableEntity, "illegal_move", "the agent does not move that way: an agent that is "+p.state+" does not renew its own certificate")
		return
	}
	public := requested.PublicKey
	if p.foreign != nil {
		public = p.foreign
	}
	signed, err := p.signing.signed(agent, public, p.lifetime)
	var issued []byte
	if err == nil {
		issued, err = answered(signed, []*x509.Certificate{p.signing.certificate}, p.published)
	}
	if err != nil {
		refuse(w, http.StatusServiceUnavailable, "certificate_not_signed", err.Error())
		return
	}
	p.seen = append(p.seen, renewed{agent: agent, presented: presentedKey, requested: requestedKey})
	if p.lose {
		if hijacker, ok := w.(http.Hijacker); ok {
			if connection, _, err := hijacker.Hijack(); err == nil {
				connection.Close()
				return
			}
		}
	}
	w.Header().Set("Content-Type", "application/x-protobuf")
	w.WriteHeader(http.StatusCreated)
	w.Write(issued)
}

func refuse(w http.ResponseWriter, status int, code, detail string) {
	encoded, _ := proto.Marshal(&controlv1.Refusal{Code: code, Detail: detail})
	w.Header().Set("Content-Type", "application/x-protobuf")
	w.WriteHeader(status)
	w.Write(encoded)
}

type installed struct {
	directory    string
	installation *identity.Installation
	keys         *pki.KeyFiles
	certificates *pki.CertificateFiles
	authorities  *pki.AuthorityFiles
}

// An installation enrolled as agentID the way an operator enrolls one: it asks
// for a certificate, and imports the one the platform's authority signed.
func enrolled(t *testing.T, signing *authority, agentID string, lifetime time.Duration) *installed {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "state")
	installation, err := identity.Open(directory)
	if err != nil {
		t.Fatalf("open the installation: %v", err)
	}
	t.Cleanup(func() { installation.Close() })
	held := &installed{directory: directory, installation: installation}
	for name, open := range map[string]func(*identity.Installation) error{
		"keys": func(i *identity.Installation) error {
			root, err := i.Directory("keys")
			if err == nil {
				held.keys, err = pki.OpenKeyFiles(root)
			}
			return err
		},
		"certificates": func(i *identity.Installation) error {
			root, err := i.Directory("certificates")
			if err == nil {
				held.certificates, err = pki.OpenCertificateFiles(root)
			}
			return err
		},
		"trust": func(i *identity.Installation) error {
			root, err := i.Directory("trust")
			if err == nil {
				held.authorities, err = pki.OpenAuthorityFiles(root)
			}
			return err
		},
	} {
		if err := open(installation); err != nil {
			t.Fatalf("open the %s: %v", name, err)
		}
	}
	asked, err := enrollment.Request(installation, held.keys, agentID, time.Now())
	if err != nil {
		t.Fatalf("ask for a certificate: %v", err)
	}
	block, _ := pem.Decode(asked.Request)
	requested, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("parse the request: %v", err)
	}
	signed := signing.sign(t, agentID, requested.PublicKey, lifetime)
	issued := answer(t, signed, []*x509.Certificate{signing.certificate}, []*x509.Certificate{signing.certificate})
	if _, err := enrollment.Import(installation, held.keys, held.certificates, []*x509.Certificate{signing.certificate}, issued, time.Now()); err != nil {
		t.Fatalf("import the first certificate: %v", err)
	}
	return held
}

func (i *installed) active(t *testing.T) identity.Enrollment {
	t.Helper()
	active, ok := i.installation.Enrollment()
	if !ok {
		t.Fatal("the installation is not enrolled")
	}
	return active
}

// The credential of the active generation, as the composition root hands it to
// the transport.
type credentials struct{ held *installed }

func (c credentials) Credential() (transport.Credential, error) {
	active, _ := c.held.installation.Enrollment()
	credential, err := pki.OpenCredential(c.held.keys, c.held.certificates, active.KeyID, active.Certificate.FingerprintSHA256)
	if err != nil {
		return transport.Credential{}, err
	}
	return transport.Credential{Chain: credential.Chain, Signer: credential.Key}, nil
}

type logs struct {
	mu      sync.Mutex
	written bytes.Buffer
}

func (l *logs) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.written.Write(p)
}

func (l *logs) entries(t *testing.T, message string) []map[string]any {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	var found []map[string]any
	for line := range strings.Lines(l.written.String()) {
		entry := map[string]any{}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("decode the log line %q: %v", line, err)
		}
		if entry["msg"] == message {
			found = append(found, entry)
		}
	}
	return found
}

type renewing struct {
	renewer *renewal.Renewer
	client  *transport.Client
	logs    *logs
}

func renewerFor(t *testing.T, held *installed, serving *platform, trusted []*x509.Certificate, lifetime time.Duration, policy renewal.Policy) *renewing {
	t.Helper()
	client, err := transport.New(transport.Options{
		Authorities:      trusted,
		Credentials:      credentials{held: held},
		ConnectTimeout:   time.Second,
		RequestTimeout:   2 * time.Second,
		MaxResponseBytes: 64 << 10,
		MaxConnections:   1,
	})
	if err != nil {
		t.Fatalf("compose the transport: %v", err)
	}
	t.Cleanup(client.Close)
	written := &logs{}
	renewer, err := renewal.New(renewal.Options{
		Installation: held.installation,
		Keys:         held.keys,
		Certificates: held.certificates,
		Authorities:  held.authorities,
		Client:       client,
		URL:          serving.URL,
		Trusted:      trusted,
		Configured:   pki.Digest(trusted),
		KeyLifetime:  func() time.Duration { return lifetime },
		Policy:       policy,
		Logger:       slog.New(slog.NewJSONHandler(written, nil)),
		Recovery:     func(err error) string { return "recover from " + err.Error() },
	})
	if err != nil {
		t.Fatalf("compose the renewal: %v", err)
	}
	return &renewing{renewer: renewer, client: client, logs: written}
}
