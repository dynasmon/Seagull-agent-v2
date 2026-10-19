//go:build linux

package native_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
	assessmentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/assessment/v1"
	controlv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/control/v1"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	ingestv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/ingest/v1"
	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
)

// The platform an installed agent enrolls with and renews through, as the
// recorded platform behaves: an authority that issues the certificates of its
// agents and of its listeners, and ingest and renewal listeners that speak TLS
// 1.3 alone and ask every client for the certificate of an agent.
type platform struct {
	authority  *x509.Certificate
	key        *ecdsa.PrivateKey
	ingest     *httptest.Server
	renewal    *httptest.Server
	named      bool
	renewals   atomic.Int32
	renewed    atomic.Pointer[string]
	handed     atomic.Pointer[[]byte]
	taking     atomic.Bool
	dropping   atomic.Bool
	handling   atomic.Pointer[func(w http.ResponseWriter, r *http.Request, content []byte) bool]
	renewing   atomic.Pointer[func(w http.ResponseWriter, agent string, asked *agentv1.RenewalRequest) bool]
	presenting atomic.Pointer[func(local net.Addr) *tls.Config]
	mu         sync.Mutex
	stored     map[string][]string
	collected  []*eventv1.Event
	batches    [][]byte
	inventory  []*inventoryv1.Record
	stocked    [][]byte
	reports    []*agentv1.Status
	statused   [][]byte
	assessed   []*assessmentv1.Assessment
	assessing  [][]byte
	offered    []byte
	packages   map[string][]byte
}

const platformName = "platform.seagull.test"

type dropping struct {
	net.Listener
	drop *atomic.Bool
}

func (d dropping) Accept() (net.Conn, error) {
	for {
		connection, err := d.Listener.Accept()
		if err != nil || !d.drop.Load() {
			return connection, err
		}
		connection.Close()
	}
}

func emulate(t *testing.T) *platform {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("draw the key of the platform's authority: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Seagull platform"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(2 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatalf("sign the certificate of the platform's authority: %v", err)
	}
	authority, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse the certificate of the platform's authority: %v", err)
	}
	emulated := &platform{authority: authority, key: key, stored: map[string][]string{}}
	emulated.ingest = emulated.listen(t, http.HandlerFunc(emulated.admit), &emulated.dropping)
	emulated.renewal = emulated.listen(t, http.HandlerFunc(emulated.renew), nil)
	return emulated
}

func (p *platform) address(listener *httptest.Server) string {
	if !p.named {
		return listener.URL
	}
	_, port, _ := net.SplitHostPort(listener.Listener.Addr().String())
	return "https://" + net.JoinHostPort(platformName, port)
}

func (p *platform) bundle() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.authority.Raw})
}

func (p *platform) listen(t *testing.T, handler http.Handler, drop *atomic.Bool) *httptest.Server {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("draw the key of a listener: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "platform listener"},
		DNSNames:     []string{platformName},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(2 * time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, p.authority, key.Public(), p.key)
	if err != nil {
		t.Fatalf("issue the certificate of a listener: %v", err)
	}
	agents := x509.NewCertPool()
	agents.AddCert(p.authority)
	listener := httptest.NewUnstartedServer(handler)
	listener.Config.ErrorLog = log.New(io.Discard, "", 0)
	if drop != nil {
		listener.Listener = dropping{Listener: listener.Listener, drop: drop}
	}
	listener.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    agents,
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			if present := p.presenting.Load(); present != nil {
				return (*present)(hello.Conn.LocalAddr()), nil
			}
			return nil, nil
		},
	}
	listener.StartTLS()
	t.Cleanup(listener.Close)
	return listener
}

// The answer the platform gives to a certificate request: the certificate it
// signed for agent, the chain and the authorities it tells its agents to trust,
// and what it recorded of the certificate.
func (p *platform) issue(requested []byte, agent string, notBefore, notAfter time.Time) ([]byte, error) {
	return issueBy(p.authority, p.key, p.bundle(), p.bundle(), requested, agent, notBefore, notAfter)
}

func issueBy(authority *x509.Certificate, key *ecdsa.PrivateKey, chain, trusted, requested []byte, agent string, notBefore, notAfter time.Time) ([]byte, error) {
	block, _ := pem.Decode(requested)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("the agent asked with %q", requested)
	}
	asked, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || asked.CheckSignature() != nil {
		return nil, errors.New("the agent asked with a request that does not verify")
	}
	if asked.Subject.CommonName != agent {
		return nil, fmt.Errorf("the request asks for %s, and the certificate is issued to %s", asked.Subject.CommonName, agent)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial.Add(serial, big.NewInt(1)),
		Subject:               pkix.Name{CommonName: agent},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	signed, err := x509.CreateCertificate(rand.Reader, template, authority, asked.PublicKey, key)
	if err != nil {
		return nil, err
	}
	certificate, err := x509.ParseCertificate(signed)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(signed)
	return proto.Marshal(&agentv1.IssuedCertificate{
		CertificatePem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: signed}),
		ChainPem:       chain,
		TrustBundlePem: trusted,
		Identity: &agentv1.Identity{
			Subject:           certificate.Subject.CommonName,
			Serial:            hex.EncodeToString(certificate.SerialNumber.Bytes()),
			FingerprintSha256: hex.EncodeToString(digest[:]),
			IssuedAt:          timestamppb.New(certificate.NotBefore),
			ExpiresAt:         timestamppb.New(certificate.NotAfter),
		},
	})
}

// A batch as the recorded gateway answers one: decoded with the published
// contracts and acknowledged as durable once its backbone takes it, and refused
// as not made durable while the backbone does not.
func (p *platform) admit(w http.ResponseWriter, r *http.Request) {
	answer := func(status int, message proto.Message) {
		encoded, _ := proto.Marshal(message)
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(status)
		w.Write(encoded)
	}
	content, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8<<20))
	if handle := p.handling.Load(); handle != nil && err == nil && r.Method == http.MethodPost && r.URL.Path == "/v1/events" && (*handle)(w, r, content) {
		return
	}
	var reported agentv1.StatusBatch
	if err == nil && r.Method == http.MethodPost && r.URL.Path == "/v1/status" && proto.Unmarshal(content, &reported) == nil && len(reported.GetReports()) > 0 {
		p.mu.Lock()
		p.reports = append(p.reports, reported.GetReports()...)
		p.statused = append(p.statused, content)
		p.mu.Unlock()
		answer(http.StatusOK, &ingestv1.BatchAck{Accepted: true, Durable: true, Received: uint32(len(reported.GetReports()))})
		return
	}
	var ids []string
	var collected []*eventv1.Event
	var stocked []*inventoryv1.Record
	var assessed []*assessmentv1.Assessment
	switch {
	case err != nil || r.Method != http.MethodPost:
	case r.URL.Path == "/v1/events":
		var batch ingestv1.EventBatch
		if err = proto.Unmarshal(content, &batch); err == nil {
			for _, event := range batch.GetEvents() {
				ids = append(ids, event.GetEventId())
				if event.GetCollection().GetCollector() == "authentication" {
					collected = append(collected, event)
				}
			}
		}
	case r.URL.Path == "/v1/inventory":
		var batch inventoryv1.RecordBatch
		if err = proto.Unmarshal(content, &batch); err == nil {
			for _, record := range batch.GetRecords() {
				ids = append(ids, record.GetRecordId())
				if collector := record.GetCollection().GetCollector(); collector == "inventory" || collector == "processes" {
					stocked = append(stocked, record)
				}
			}
		}
	case r.URL.Path == "/v1/assessments":
		var batch assessmentv1.AssessmentBatch
		if err = proto.Unmarshal(content, &batch); err == nil {
			for _, assessment := range batch.GetAssessments() {
				ids = append(ids, assessment.GetAssessmentId())
			}
			assessed = batch.GetAssessments()
		}
	}
	if len(ids) == 0 {
		answer(http.StatusBadRequest, &ingestv1.Rejection{Code: "malformed_payload", Detail: "the batch is not a valid protobuf message", EventIndex: -1})
		return
	}
	if !p.taking.Load() {
		w.Header().Set("Retry-After", "5")
		answer(http.StatusServiceUnavailable, &ingestv1.Rejection{Code: "backbone_unavailable", Detail: "the batch was not made durable", EventIndex: -1})
		return
	}
	p.mu.Lock()
	p.stored[r.URL.Path] = append(p.stored[r.URL.Path], ids...)
	p.collected = append(p.collected, collected...)
	if len(collected) > 0 {
		p.batches = append(p.batches, content)
	}
	p.inventory = append(p.inventory, stocked...)
	if len(stocked) > 0 {
		p.stocked = append(p.stocked, content)
	}
	p.assessed = append(p.assessed, assessed...)
	if len(assessed) > 0 {
		p.assessing = append(p.assessing, content)
	}
	p.mu.Unlock()
	answer(http.StatusOK, &ingestv1.BatchAck{Accepted: true, Durable: true, Received: uint32(len(ids))})
}

// What the agent said of itself, in the order the platform took it: status
// travels on a topic of its own, so the emulated backbone takes it whether or
// not it takes telemetry.
func (p *platform) told() []*agentv1.Status {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.reports)
}

func (p *platform) statusBatches() [][]byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.statused)
}

func (p *platform) holds(path string) []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Sorted(slices.Values(p.stored[path]))
}

func (p *platform) authentications() ([]*eventv1.Event, [][]byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.collected), slices.Clone(p.batches)
}

func (p *platform) inventories() ([]*inventoryv1.Record, [][]byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.inventory), slices.Clone(p.stocked)
}

func (p *platform) assessments() ([]*assessmentv1.Assessment, [][]byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.assessed), slices.Clone(p.assessing)
}

// A renewal as the recorded platform answers one: to the agent the certificate
// the connection presented names, backdated by a minute and valid for as long
// as the authority is.
func (p *platform) renew(w http.ResponseWriter, r *http.Request) {
	answer := func(status int, body []byte) {
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(status)
		w.Write(body)
	}
	refuse := func(status int, code string) {
		encoded, _ := proto.Marshal(&controlv1.Refusal{Code: code, Detail: "refused by the emulated platform"})
		answer(status, encoded)
	}
	if r.Method == http.MethodGet && r.TLS != nil && len(r.TLS.VerifiedChains) > 0 {
		switch {
		case r.URL.Path == "/v1/agents/policy":
			p.policy(w, r)
			return
		case r.URL.Path == "/v1/agents/update":
			p.offer(w, r)
			return
		case strings.HasPrefix(r.URL.Path, "/v1/agents/update/packages/"):
			p.hand(w, r)
			return
		}
	}
	if r.Method != http.MethodPost || r.URL.Path != "/v1/agents/certificate" || r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
		refuse(http.StatusNotFound, "not_found")
		return
	}
	agent := r.TLS.VerifiedChains[0][0].Subject.CommonName
	content, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 32<<10))
	var asked agentv1.RenewalRequest
	if err == nil {
		err = proto.Unmarshal(content, &asked)
	}
	if handle := p.renewing.Load(); handle != nil && err == nil && (*handle)(w, agent, &asked) {
		return
	}
	var issued []byte
	if err == nil {
		issued, err = p.issue(asked.GetCsrPem(), agent, time.Now().Add(-time.Minute).Truncate(time.Second), p.authority.NotAfter)
	}
	if err != nil {
		refuse(http.StatusUnprocessableEntity, "malformed_certificate_request")
		return
	}
	p.renewals.Add(1)
	p.renewed.Store(&agent)
	answer(http.StatusCreated, issued)
}
