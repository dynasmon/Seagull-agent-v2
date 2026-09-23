package transport_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/pki"
	"github.com/dynasmon/Seagull-agent-v2/internal/transport"
)

const (
	protobuf = "application/x-protobuf"
	settle   = 5 * time.Second
)

func TestThePlatformKnowsTheAgentByItsCertificateAlone(t *testing.T) {
	agents := authorityNamed(t, "Seagull agents")
	platform := serve(t, authorityNamed(t, "Seagull platform"), agents, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", protobuf)
		w.Write([]byte("admitted"))
	})
	key := agentKey(t)
	client := compose(t, platform.trusted, &held{credential: transport.Credential{Chain: agents.agent(t, "web-01", key.Public()), Signer: key}})

	reply, err := client.Post(t.Context(), batch(platform.URL+"/v1/events", "sshd: accepted publickey"))
	if err != nil {
		t.Fatalf("send a batch: %v", err)
	}
	if reply.Status != http.StatusOK || reply.ContentType != protobuf || string(reply.Body) != "admitted" {
		t.Fatalf("the platform answered %+v", reply)
	}
	seen := platform.requests()
	if len(seen) != 1 || seen[0].agent != "web-01" || seen[0].version != tls.VersionTLS13 || seen[0].protocol != "HTTP/1.1" {
		t.Fatalf("the platform saw %+v", seen)
	}
	for name, values := range seen[0].headers {
		if strings.Contains(strings.Join(values, " "), "web-01") {
			t.Errorf("the request names the agent in %s, and only its certificate may", name)
		}
	}
	if string(seen[0].body) != "sshd: accepted publickey" {
		t.Errorf("the platform received %q", seen[0].body)
	}
}

func TestNothingIsSentToAPlatformTheAgentCannotAuthenticate(t *testing.T) {
	trusted, agents := authorityNamed(t, "Seagull platform"), authorityNamed(t, "Seagull agents")
	key := agentKey(t)
	credential := &held{credential: transport.Credential{Chain: agents.agent(t, "web-01", key.Public()), Signer: key}}
	cases := map[string]struct {
		certificate func() tls.Certificate
		version     uint16
		says        string
	}{
		"a certificate an authority the agent does not trust issued": {
			certificate: func() tls.Certificate {
				return authorityNamed(t, "Somebody else").server(t, nil, "localhost", "127.0.0.1")
			},
			says: "unknown authority",
		},
		"a certificate for another name": {
			certificate: func() tls.Certificate { return trusted.server(t, nil, "gateway.example") },
			says:        "127.0.0.1",
		},
		"a certificate that expired": {
			certificate: func() tls.Certificate {
				return trusted.server(t, func(c *x509.Certificate) {
					c.NotBefore, c.NotAfter = time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour)
				}, "127.0.0.1")
			},
			says: "expired",
		},
		"a certificate issued to authenticate a client": {
			certificate: func() tls.Certificate {
				return trusted.server(t, func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} }, "127.0.0.1")
			},
			says: "usage",
		},
		"a platform that speaks TLS 1.2 at most": {
			certificate: func() tls.Certificate { return trusted.server(t, nil, "127.0.0.1") },
			version:     tls.VersionTLS12,
			says:        "protocol version",
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			platform := serveWith(t, trusted, agents, c.certificate(), c.version, admit)
			client := compose(t, platform.trusted, credential)
			_, err := client.Post(t.Context(), batch(platform.URL+"/v1/events", "sshd: accepted publickey"))
			if !errors.Is(err, transport.ErrUntrusted) || !strings.Contains(err.Error(), c.says) {
				t.Fatalf("sending to %s returned %v", name, err)
			}
			if _, err := client.Check(t.Context(), platform.URL); !errors.Is(err, transport.ErrUntrusted) {
				t.Fatalf("checking %s returned %v", name, err)
			}
			if seen := platform.requests(); len(seen) != 0 {
				t.Fatalf("the agent sent %d requests to %s", len(seen), name)
			}
		})
	}
}

func TestWithoutAUsableCredentialTheAgentConnectsNowhere(t *testing.T) {
	agents := authorityNamed(t, "Seagull agents")
	platform := serve(t, authorityNamed(t, "Seagull platform"), agents, admit)
	key, other := agentKey(t), agentKey(t)
	issued := func(change func(*x509.Certificate)) transport.Credentials {
		return &held{credential: transport.Credential{Chain: agents.issue(t, "web-01", key.Public(), change), Signer: key}}
	}
	cases := map[string]struct {
		credentials transport.Credentials
		says        string
	}{
		"an installation that is not enrolled":         {says: "not enrolled"},
		"a credential the installation cannot produce": {credentials: &held{err: pki.ErrKeyMissing}, says: "does not exist"},
		"a certificate that expired": {
			credentials: issued(func(c *x509.Certificate) {
				c.NotBefore, c.NotAfter = time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour)
			}),
			says: "expired",
		},
		"a certificate the clock says is not valid yet": {
			credentials: issued(func(c *x509.Certificate) { c.NotBefore = time.Now().Add(time.Hour) }),
			says:        "is valid from",
		},
		"a certificate issued for another key": {
			credentials: &held{credential: transport.Credential{Chain: agents.agent(t, "web-01", other.Public()), Signer: key}},
			says:        "not issued for the agent's key",
		},
		"a certificate that does not authenticate a client": {
			credentials: issued(func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth} }),
			says:        "does not authenticate a client",
		},
		"a certificate whose key may not sign": {
			credentials: issued(func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageKeyEncipherment }),
			says:        "does not let its key sign",
		},
		"no certificate at all": {
			credentials: &held{credential: transport.Credential{Signer: key}},
			says:        "holds no certificate",
		},
		"a chain of something that is not certificates": {
			credentials: &held{credential: transport.Credential{Chain: [][]byte{agents.agent(t, "web-01", key.Public())[0], []byte("intermediate")}, Signer: key}},
			says:        "not a certificate",
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			client := compose(t, platform.trusted, c.credentials)
			_, err := client.Post(t.Context(), batch(platform.URL+"/v1/events", "sshd: accepted publickey"))
			if !errors.Is(err, transport.ErrUnauthenticated) || !strings.Contains(err.Error(), c.says) {
				t.Fatalf("sending with %s returned %v", name, err)
			}
			if connected := platform.connected.Load(); connected != 0 {
				t.Fatalf("the agent opened %d connections with %s", connected, name)
			}
		})
	}
}

func TestARefusedCredentialIsToldApartFromAPlatformThatCannotBeReached(t *testing.T) {
	trusted, agents := authorityNamed(t, "Seagull platform"), authorityNamed(t, "Seagull agents")
	key := agentKey(t)
	credential := &held{credential: transport.Credential{Chain: agents.agent(t, "web-01", key.Public()), Signer: key}}

	strangers := serve(t, trusted, authorityNamed(t, "Another estate's agents"), admit)
	client := compose(t, strangers.trusted, credential)
	if _, err := client.Post(t.Context(), batch(strangers.URL+"/v1/events", "sshd: accepted publickey")); !errors.Is(err, transport.ErrRefused) {
		t.Fatalf("a platform that does not know the agent's authority answered with %v", err)
	}
	if seen := strangers.requests(); len(seen) != 0 {
		t.Fatalf("a platform that refused the agent's certificate served %d requests", len(seen))
	}

	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	address := closed.Addr().String()
	closed.Close()
	if _, err := client.Post(t.Context(), batch("https://"+address+"/v1/events", "sshd")); !errors.Is(err, transport.ErrUnreachable) {
		t.Fatalf("a closed port answered with %v", err)
	}

	silent, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { silent.Close() })
	go func() {
		for {
			held, err := silent.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { held.Close() })
		}
	}()
	began := time.Now()
	if _, err := client.Post(t.Context(), batch("https://"+silent.Addr().String()+"/v1/events", "sshd")); !errors.Is(err, transport.ErrUnreachable) {
		t.Fatalf("a listener that never answers the handshake answered with %v", err)
	}
	if took := time.Since(began); took > time.Second+settle/2 {
		t.Fatalf("a handshake nobody answered was waited for %s, with a connect timeout of 1s", took)
	}

	slow := serve(t, trusted, agents, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(time.Minute):
		}
	})
	began = time.Now()
	if _, err := client.Post(t.Context(), batch(slow.URL+"/v1/events", "sshd")); !errors.Is(err, transport.ErrUnreachable) {
		t.Fatalf("a platform that never answers the request answered with %v", err)
	}
	if took := time.Since(began); took < 2*time.Second || took > 2*time.Second+settle/2 {
		t.Fatalf("a request nobody answered was waited for %s, with a request timeout of 2s", took)
	}
}

func TestAStopReleasesTheRequestAndTheConnectionItWasWaitingOn(t *testing.T) {
	agents := authorityNamed(t, "Seagull agents")
	entered, released := make(chan struct{}, 1), make(chan struct{}, 1)
	platform := serve(t, authorityNamed(t, "Seagull platform"), agents, func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		<-r.Context().Done()
		released <- struct{}{}
	})
	key := agentKey(t)
	client := compose(t, platform.trusted, &held{credential: transport.Credential{Chain: agents.agent(t, "web-01", key.Public()), Signer: key}})
	baseline := runtime.NumGoroutine()

	ctx, stop := context.WithCancel(t.Context())
	returned := make(chan error, 1)
	go func() {
		_, err := client.Post(ctx, batch(platform.URL+"/v1/events", "sshd"))
		returned <- err
	}()
	await(t, entered, "the platform never received the request")
	stop()
	select {
	case err := <-returned:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("a stopped request returned %v", err)
		}
	case <-time.After(settle):
		t.Fatal("a stopped request did not return")
	}
	await(t, released, "the platform still held the request the agent stopped")
	client.Close()
	deadline := time.Now().Add(settle)
	for runtime.NumGoroutine() > baseline && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if running := runtime.NumGoroutine(); running > baseline {
		t.Fatalf("%d goroutines run after a stopped request, %d ran before it", running, baseline)
	}
}

func TestAReplyIsReadNoFurtherThanTheAgentAllows(t *testing.T) {
	agents := authorityNamed(t, "Seagull agents")
	platform := serve(t, authorityNamed(t, "Seagull platform"), agents, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", protobuf)
		chunk := bytes.Repeat([]byte("a"), 32<<10)
		for {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	})
	key := agentKey(t)
	client := compose(t, platform.trusted, &held{credential: transport.Credential{Chain: agents.agent(t, "web-01", key.Public()), Signer: key}})
	for range 2 {
		if _, err := client.Post(t.Context(), batch(platform.URL+"/v1/events", "sshd")); !errors.Is(err, transport.ErrReplyTooLarge) {
			t.Fatalf("an endless reply returned %v", err)
		}
	}
	if connected := platform.connected.Load(); connected != 2 {
		t.Fatalf("two replies the agent stopped reading used %d connections", connected)
	}
}

func TestNoMoreConnectionsAreOpenAtOnceThanTheTransportAllows(t *testing.T) {
	agents := authorityNamed(t, "Seagull agents")
	platform := serve(t, authorityNamed(t, "Seagull platform"), agents, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		admit(w, r)
	})
	key := agentKey(t)
	client := compose(t, platform.trusted, &held{credential: transport.Credential{Chain: agents.agent(t, "web-01", key.Public()), Signer: key}})
	var senders sync.WaitGroup
	for range 8 {
		senders.Go(func() {
			if _, err := client.Post(t.Context(), batch(platform.URL+"/v1/events", "sshd")); err != nil {
				t.Errorf("send a batch: %v", err)
			}
		})
	}
	senders.Wait()
	if most := platform.most.Load(); most > 2 || most < 1 {
		t.Fatalf("%d connections were open at once, and the transport allows 2", most)
	}
	if seen := platform.requests(); len(seen) != 8 {
		t.Fatalf("the platform served %d of 8 requests", len(seen))
	}
}

func TestARenewedCredentialIsPresentedFromTheNextRequestOn(t *testing.T) {
	agents := authorityNamed(t, "Seagull agents")
	platform := serve(t, authorityNamed(t, "Seagull platform"), agents, admit)
	first, second := agentKey(t), agentKey(t)
	credential := &held{credential: transport.Credential{Chain: agents.agent(t, "web-01", first.Public()), Signer: first}}
	client := compose(t, platform.trusted, credential)
	for range 2 {
		if _, err := client.Post(t.Context(), batch(platform.URL+"/v1/events", "sshd")); err != nil {
			t.Fatalf("send with the first generation: %v", err)
		}
	}
	credential.set(transport.Credential{Chain: agents.agent(t, "web-01", second.Public()), Signer: second})
	if _, err := client.Post(t.Context(), batch(platform.URL+"/v1/events", "sshd")); err != nil {
		t.Fatalf("send with the second generation: %v", err)
	}
	seen := platform.requests()
	if len(seen) != 3 || seen[0].key != seen[1].key || seen[2].key == seen[1].key || seen[2].agent != "web-01" {
		t.Fatalf("the platform saw %+v", seen)
	}
	if connected := platform.connected.Load(); connected != 2 {
		t.Fatalf("three requests over two credential generations used %d connections", connected)
	}
}

func TestThePlatformMayReplaceItsCertificateAndItsAuthority(t *testing.T) {
	current, next, agents := authorityNamed(t, "Seagull platform 2026"), authorityNamed(t, "Seagull platform 2027"), authorityNamed(t, "Seagull agents")
	key := agentKey(t)
	credential := &held{credential: transport.Credential{Chain: agents.agent(t, "web-01", key.Public()), Signer: key}}
	client := compose(t, []*x509.Certificate{current.certificate, next.certificate}, credential)
	for name, certificate := range map[string]tls.Certificate{
		"the certificate it had":           current.server(t, nil, "127.0.0.1"),
		"a certificate for another key":    current.server(t, nil, "127.0.0.1"),
		"a certificate of a new authority": next.server(t, nil, "127.0.0.1"),
	} {
		platform := serveWith(t, current, agents, certificate, 0, admit)
		if _, err := client.Post(t.Context(), batch(platform.URL+"/v1/events", "sshd")); err != nil {
			t.Fatalf("a platform presenting %s was refused: %v", name, err)
		}
	}
}

func TestTheAgentFollowsNoRedirect(t *testing.T) {
	agents := authorityNamed(t, "Seagull agents")
	platform := serve(t, authorityNamed(t, "Seagull platform"), agents, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://127.0.0.1:1/v1/events", http.StatusTemporaryRedirect)
	})
	key := agentKey(t)
	client := compose(t, platform.trusted, &held{credential: transport.Credential{Chain: agents.agent(t, "web-01", key.Public()), Signer: key}})
	reply, err := client.Post(t.Context(), batch(platform.URL+"/v1/events", "sshd"))
	if err != nil || reply.Status != http.StatusTemporaryRedirect {
		t.Fatalf("a redirect was answered with %+v, %v", reply, err)
	}
	if seen := platform.requests(); len(seen) != 1 {
		t.Fatalf("the platform served %d requests for one batch", len(seen))
	}
}

func TestCheckingThePlatformAuthenticatesItAndPresentsNothing(t *testing.T) {
	trusted, agents := authorityNamed(t, "Seagull platform"), authorityNamed(t, "Seagull agents")
	key := agentKey(t)
	mutual := serve(t, trusted, agents, admit)
	client := compose(t, mutual.trusted, &held{credential: transport.Credential{Chain: agents.agent(t, "web-01", key.Public()), Signer: key}})
	peer, err := client.Check(t.Context(), mutual.URL)
	if err != nil {
		t.Fatalf("check the platform: %v", err)
	}
	if peer.Version != tls.VersionTLS13 || peer.Issuer != "Seagull platform" || !slices.Contains(peer.Names, "127.0.0.1") || !peer.Asks || peer.NotAfter.Before(time.Now()) {
		t.Fatalf("the platform presented %+v", peer)
	}
	if seen := mutual.requests(); len(seen) != 0 {
		t.Fatalf("checking the platform sent it %d requests", len(seen))
	}

	open := serveWith(t, trusted, nil, trusted.server(t, nil, "127.0.0.1"), 0, admit)
	if peer, err := client.Check(t.Context(), open.URL); err != nil || peer.Asks {
		t.Fatalf("a listener that asks for no certificate was checked as %+v: %v", peer, err)
	}
}

func TestComposingTheTransportRefusesWhatItCannotKeep(t *testing.T) {
	platform := authorityNamed(t, "Seagull platform")
	leaf, err := x509.ParseCertificate(platform.server(t, nil, "127.0.0.1").Certificate[0])
	if err != nil {
		t.Fatalf("parse a certificate: %v", err)
	}
	valid := transport.Options{
		Authorities: []*x509.Certificate{platform.certificate}, ConnectTimeout: time.Second, RequestTimeout: 2 * time.Second,
		MaxResponseBytes: 64 << 10, MaxConnections: 1,
	}
	for name, c := range map[string]struct {
		change func(*transport.Options)
		says   string
	}{
		"no authority":                  {change: func(o *transport.Options) { o.Authorities = nil }, says: "no authority"},
		"a leaf among the authorities":  {change: func(o *transport.Options) { o.Authorities = append(o.Authorities, leaf) }, says: "not a certificate authority"},
		"no time to connect":            {change: func(o *transport.Options) { o.ConnectTimeout = 0 }, says: "not both waits"},
		"a request shorter than a dial": {change: func(o *transport.Options) { o.RequestTimeout = time.Millisecond }, says: "shorter than the connect timeout"},
		"no reply to read":              {change: func(o *transport.Options) { o.MaxResponseBytes = 0 }, says: "leaves nothing to read"},
		"no connection to send over":    {change: func(o *transport.Options) { o.MaxConnections = 0 }, says: "nothing to send over"},
	} {
		t.Run(name, func(t *testing.T) {
			options := valid
			c.change(&options)
			if client, err := transport.New(options); client != nil || err == nil || !strings.Contains(err.Error(), c.says) {
				t.Fatalf("composing the transport with %s returned %v, %v", name, client, err)
			}
		})
	}
	client, err := transport.New(valid)
	if err != nil {
		t.Fatalf("compose the transport: %v", err)
	}
	for _, address := range []string{"http://gateway.example:8443/v1/events", "https://agent:secret@gateway.example/v1/events", "gateway.example:8443"} {
		if _, err := client.Post(t.Context(), batch(address, "sshd")); err == nil || strings.Contains(err.Error(), "secret") {
			t.Errorf("the transport took %s: %v", address, err)
		}
	}
}

func admit(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", protobuf)
	w.Write([]byte("admitted"))
}

func batch(address, content string) transport.Request {
	return transport.Request{URL: address, ContentType: protobuf, Body: strings.NewReader(content), Length: int64(len(content))}
}

func compose(t *testing.T, authorities []*x509.Certificate, credentials transport.Credentials) *transport.Client {
	t.Helper()
	client, err := transport.New(transport.Options{
		Authorities:      authorities,
		Credentials:      credentials,
		ConnectTimeout:   time.Second,
		RequestTimeout:   2 * time.Second,
		MaxResponseBytes: 64 << 10,
		MaxConnections:   2,
	})
	if err != nil {
		t.Fatalf("compose the transport: %v", err)
	}
	t.Cleanup(client.Close)
	return client
}

func await(t *testing.T, signal chan struct{}, otherwise string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(settle):
		t.Fatal(otherwise)
	}
}

// The credential the installation holds, which a test may replace as renewal
// would, or make unusable.
type held struct {
	mu         sync.Mutex
	credential transport.Credential
	err        error
}

func (h *held) Credential() (transport.Credential, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.credential, h.err
}

func (h *held) set(credential transport.Credential) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.credential = credential
}

func agentKey(t *testing.T) pki.Key {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "keys")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatalf("create %s: %v", directory, err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatalf("open %s: %v", directory, err)
	}
	t.Cleanup(func() { root.Close() })
	keys, err := pki.OpenKeyFiles(root)
	if err != nil {
		t.Fatalf("open the keys: %v", err)
	}
	key, err := keys.Create()
	if err != nil {
		t.Fatalf("draw a key: %v", err)
	}
	return key
}

type authority struct {
	certificate *x509.Certificate
	key         *ecdsa.PrivateKey
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
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatalf("sign %s: %v", name, err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return &authority{certificate: certificate, key: key}
}

func (a *authority) issue(t *testing.T, subject string, public crypto.PublicKey, change func(*x509.Certificate)) [][]byte {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serials.Add(1)),
		Subject:      pkix.Name{CommonName: subject},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if change != nil {
		change(template)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, a.certificate, public, a.key)
	if err != nil {
		t.Fatalf("issue a certificate for %s: %v", subject, err)
	}
	return [][]byte{der}
}

func (a *authority) agent(t *testing.T, agentID string, public crypto.PublicKey) [][]byte {
	t.Helper()
	return a.issue(t, agentID, public, nil)
}

func (a *authority) server(t *testing.T, change func(*x509.Certificate), hosts ...string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("draw a key: %v", err)
	}
	chain := a.issue(t, "ingest-gateway", key.Public(), func(template *x509.Certificate) {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		for _, host := range hosts {
			if address := net.ParseIP(host); address != nil {
				template.IPAddresses = append(template.IPAddresses, address)
			} else {
				template.DNSNames = append(template.DNSNames, host)
			}
		}
		if change != nil {
			change(template)
		}
	})
	return tls.Certificate{Certificate: chain, PrivateKey: key}
}

type request struct {
	agent    string
	key      string
	version  uint16
	protocol string
	headers  http.Header
	body     []byte
}

// A listener set up the way the platform's agent listeners are: TLS 1.3 alone,
// a certificate required of every client and verified against the authority
// that issues agents theirs, and the agent named by that certificate.
type platform struct {
	*httptest.Server
	trusted   []*x509.Certificate
	connected atomic.Int32
	open      atomic.Int32
	most      atomic.Int32
	mu        sync.Mutex
	seen      []request
}

func serve(t *testing.T, issuer, agents *authority, handler http.HandlerFunc) *platform {
	t.Helper()
	return serveWith(t, issuer, agents, issuer.server(t, nil, "localhost", "127.0.0.1"), 0, handler)
}

func serveWith(t *testing.T, issuer, agents *authority, certificate tls.Certificate, version uint16, handler http.HandlerFunc) *platform {
	t.Helper()
	listening := &platform{trusted: []*x509.Certificate{issuer.certificate}}
	listening.Server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		content, _ := io.ReadAll(r.Body)
		seen := request{version: r.TLS.Version, protocol: r.Proto, headers: r.Header.Clone(), body: content}
		if len(r.TLS.VerifiedChains) > 0 {
			leaf := r.TLS.VerifiedChains[0][0]
			seen.agent = leaf.Subject.CommonName
			keyID, _ := pki.KeyID(leaf.PublicKey)
			seen.key = keyID
		}
		listening.mu.Lock()
		listening.seen = append(listening.seen, seen)
		listening.mu.Unlock()
		handler(w, r)
	}))
	listening.Config.ErrorLog = log.New(io.Discard, "", 0)
	listening.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		switch state {
		case http.StateNew:
			listening.connected.Add(1)
			for now, most := listening.open.Add(1), listening.most.Load(); now > most && !listening.most.CompareAndSwap(most, now); most = listening.most.Load() {
			}
		case http.StateClosed, http.StateHijacked:
			listening.open.Add(-1)
		}
	}
	listening.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}
	if version != 0 {
		listening.TLS.MinVersion, listening.TLS.MaxVersion = version, version
	}
	if agents != nil {
		pool := x509.NewCertPool()
		pool.AddCert(agents.certificate)
		listening.TLS.ClientAuth, listening.TLS.ClientCAs = tls.RequireAndVerifyClientCert, pool
	}
	listening.StartTLS()
	t.Cleanup(listening.Close)
	return listening
}

func (p *platform) requests() []request {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.seen)
}
