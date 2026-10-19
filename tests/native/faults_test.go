//go:build linux

package native_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-agent-v2/internal/protocol"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
	controlv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/control/v1"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	ingestv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/ingest/v1"
)

const (
	answering int32 = iota
	unsteady
	unavailable
	withdrawn
	late
)

type authority struct {
	certificate *x509.Certificate
	key         *ecdsa.PrivateKey
}

func newAuthority(t *testing.T, name string) *authority {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(2 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &authority{certificate: certificate, key: key}
}

func bundled(authorities ...*authority) []byte {
	var held []byte
	for _, issuer := range authorities {
		held = append(held, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.certificate.Raw})...)
	}
	return held
}

// What a listener of the platform presents once a authority issued its
// certificate, asking for the certificate of an agent any of accepting issued.
func (a *authority) serving(t *testing.T, accepting ...*authority) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
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
	der, err := x509.CreateCertificate(rand.Reader, template, a.certificate, key.Public(), a.key)
	if err != nil {
		t.Fatal(err)
	}
	agents := x509.NewCertPool()
	for _, issuer := range accepting {
		agents.AddCert(issuer.certificate)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    agents,
	}
}

func (c *chaos) present(ingest, renewal *tls.Config) {
	presenting := func(local net.Addr) *tls.Config {
		if renewal != nil && local.String() == c.platform.renewal.Listener.Addr().String() {
			return renewal
		}
		if ingest != nil && local.String() == c.platform.ingest.Listener.Addr().String() {
			return ingest
		}
		return nil
	}
	c.platform.presenting.Store(&presenting)
}

func refuse(w http.ResponseWriter, status int, code, field string, index int) {
	encoded, _ := proto.Marshal(&ingestv1.Rejection{Code: code, Detail: "refused by the emulated platform", Field: field, EventIndex: int32(index)})
	w.Header().Set("Content-Type", "application/x-protobuf")
	w.WriteHeader(status)
	w.Write(encoded)
}

func acknowledge(w http.ResponseWriter, received int) {
	encoded, _ := proto.Marshal(&ingestv1.BatchAck{Accepted: true, Durable: true, Received: uint32(received)})
	w.Header().Set("Content-Type", "application/x-protobuf")
	w.Write(encoded)
}

// A batch of events as the recorded gateway takes one: every record checked
// before any is published, then published to a backbone that may take part of
// them, lose the answer or count them wrong when the gate makes it unsteady.
// What it publishes is what the gate holds the agent to.
func (c *chaos) admit(w http.ResponseWriter, r *http.Request, content []byte) bool {
	records := protocol.Events.Records(content)
	events := make([]*eventv1.Event, len(records))
	for i, record := range records {
		events[i] = &eventv1.Event{}
		if err := proto.Unmarshal(record, events[i]); err != nil {
			refuse(w, http.StatusBadRequest, "malformed_payload", "", -1)
			return true
		}
	}
	mode := c.mode.Load()
	switch {
	case len(events) == 0:
		refuse(w, http.StatusBadRequest, "malformed_payload", "", -1)
		return true
	case mode == unavailable:
		w.Header().Set("Retry-After", "1")
		refuse(w, http.StatusServiceUnavailable, "backbone_unavailable", "", -1)
		return true
	case mode == withdrawn:
		refuse(w, http.StatusForbidden, "agent_not_admitted", "", -1)
		return true
	}
	c.mu.Lock()
	for i, event := range events {
		if c.refused[event.GetAuthentication().GetUser().GetName()] {
			c.mu.Unlock()
			refuse(w, http.StatusUnprocessableEntity, "invalid_event", "authentication.user.name", i)
			return true
		}
	}
	c.mu.Unlock()
	switch mode {
	case late:
		c.publish(records, events, len(events))
		time.Sleep(7 * time.Second)
	case unsteady:
		switch c.draw(20) {
		case 0, 1, 2:
			c.publish(records, events, len(events))
			if hijacked, _, err := w.(http.Hijacker).Hijack(); err == nil {
				hijacked.Close()
			}
			return true
		case 3, 4:
			c.publish(records, events, c.draw(len(events)+1))
			refuse(w, http.StatusServiceUnavailable, "backbone_unavailable", "", -1)
			return true
		case 5, 6:
			c.publish(records, events, len(events))
			acknowledge(w, len(events)+1)
			return true
		case 7:
			refuse(w, http.StatusServiceUnavailable, "backbone_unavailable", "", -1)
			return true
		}
		c.publish(records, events, len(events))
	default:
		c.publish(records, events, len(events))
	}
	acknowledge(w, len(events))
	return true
}

func (c *chaos) publish(records [][]byte, events []*eventv1.Event, count int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, event := range events[:count] {
		user := event.GetAuthentication().GetUser().GetName()
		if !decided.MatchString(user) {
			continue
		}
		id := event.GetEventId()
		c.copies[id] = append(c.copies[id], records[i])
		if c.named[user] == nil {
			c.named[user] = map[string]bool{}
		}
		c.named[user][id] = true
	}
}

type renewing struct {
	by       *authority
	trusted  []*authority
	lifetime time.Duration
	refused  bool
}

func (c *chaos) renew(w http.ResponseWriter, agent string, asked *agentv1.RenewalRequest) bool {
	held := c.renewing.Load()
	if held == nil {
		return false
	}
	answer := func(status int, body []byte) {
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(status)
		w.Write(body)
	}
	if held.refused {
		encoded, _ := proto.Marshal(&controlv1.Refusal{Code: "unavailable", Detail: "the emulated platform renews nothing now"})
		answer(http.StatusServiceUnavailable, encoded)
		return true
	}
	issued, err := issueBy(held.by.certificate, held.by.key, bundled(held.by), bundled(held.trusted...), asked.GetCsrPem(), agent,
		time.Now().Add(-time.Minute).Truncate(time.Second), time.Now().Add(held.lifetime))
	if err != nil {
		encoded, _ := proto.Marshal(&controlv1.Refusal{Code: "malformed_certificate_request", Detail: err.Error()})
		answer(http.StatusUnprocessableEntity, encoded)
		return true
	}
	c.platform.renewals.Add(1)
	answer(http.StatusCreated, issued)
	return true
}

func (c *chaos) network(t *testing.T) {
	writing := c.write(t, "network", 20000, 50*time.Millisecond)
	connection := func(failed string) func(map[string]any) bool {
		return func(entry map[string]any) bool {
			return entry["msg"] == "connection_failing" && entry["failure"] == failed
		}
	}
	batch := func(failed string) func(map[string]any) bool {
		return func(entry map[string]any) bool {
			return entry["msg"] == "delivery_failed" && entry["stream"] == "events" && (entry["outcome"] == failed || entry["failure"] == failed)
		}
	}
	for _, failure := range []struct {
		name     string
		begin    func()
		end      func()
		reported func(map[string]any) bool
	}{
		{name: "an outage of the backbone", begin: func() { c.mode.Store(unavailable) }, end: func() { c.mode.Store(answering) }, reported: batch("unconfirmed")},
		{name: "a name that does not resolve", begin: func() { c.resolve(t, false) }, end: func() { c.resolve(t, true) }, reported: connection("transport")},
		{name: "a listener that drops every connection", begin: func() { c.platform.dropping.Store(true) }, end: func() { c.platform.dropping.Store(false) }, reported: connection("transport")},
		{name: "answers that come after the agent stopped waiting", begin: func() { c.mode.Store(late) }, end: func() { c.mode.Store(answering) }, reported: batch("transport")},
		{name: "a listener whose certificate no authority the agent trusts issued", begin: func() { c.present(newAuthority(t, "Stranger").serving(t, c.current), nil) },
			end: func() { c.platform.presenting.Store(nil) }, reported: connection("tls")},
	} {
		failing := time.Now()
		failure.begin()
		c.platform.ingest.CloseClientConnections()
		time.Sleep(15 * time.Second)
		failure.end()
		c.found(t, failing, 10*time.Second, "failure during "+failure.name, failure.reported)
		c.caughtUp(t, failure.name, 2*time.Minute)
	}
	writing.stop(t)
	c.settled(t, 3*time.Minute)
}

func (c *chaos) delivered() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.named)
}

// An operator issues the installation a certificate, as it asks for one with
// the agent stopped, from authority, for lifetime.
func (c *chaos) reissue(t *testing.T, by *authority, trusted []*authority, lifetime time.Duration) {
	t.Helper()
	requested, err := as(t, "-config", configuration, "enrollment", "request", agentID)
	if err != nil {
		t.Fatalf("ask for a certificate: %v\n%s", err, requested)
	}
	issuedAt := time.Now().UTC().Truncate(time.Second)
	issued, err := issueBy(by.certificate, by.key, bundled(by), bundled(trusted...), []byte(requested), agentID, issuedAt.Add(-time.Minute), issuedAt.Add(lifetime))
	if err != nil {
		t.Fatalf("the platform refused the request: %v", err)
	}
	answered := filepath.Join(c.scratch, fmt.Sprintf("issued-%d.pb", time.Now().UnixNano()))
	place(t, answered, issued)
	if said, err := as(t, "-config", configuration, "enrollment", "import", answered); err != nil || !strings.Contains(said, "is enrolled as agent "+agentID) {
		t.Fatalf("import the certificate: %v\n%s", err, said)
	}
}

func (c *chaos) renewed(t *testing.T, authorities string, trusted int, after time.Time) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Minute)
	for {
		for _, entry := range journal(t, c.invocation) {
			at, _ := time.Parse(time.RFC3339Nano, fmt.Sprint(entry["time"]))
			if entry["msg"] == "credential_renewed" && entry["authorities"] == authorities && entry["trusted"] == float64(trusted) && at.After(after) {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("the agent renewed no certificate with the authorities %s, %d trusted, within 2m:\n%s", authorities, trusted,
				answer("journalctl", "--no-pager", "--output", "cat", "--lines", "40", "_SYSTEMD_INVOCATION_ID="+c.invocation))
		}
		time.Sleep(time.Second)
	}
}

func (c *chaos) credentials(t *testing.T) {
	writing := c.write(t, "credential", 20000, 50*time.Millisecond)
	next := newAuthority(t, "Seagull platform next")

	c.renewing.Store(&renewing{refused: true})
	run(t, "systemctl", "stop", unit)
	c.reissue(t, c.current, []*authority{c.current}, 45*time.Second)
	run(t, "systemctl", "start", unit)
	c.invocation = started(t, c.invocation)
	expired := await(t, c.invocation, "credential_expired", 3*time.Minute)
	if expired["level"] != "ERROR" || !strings.Contains(fmt.Sprint(expired["recovery"]), "enrollment request") {
		t.Errorf("the agent reported its expired certificate as %v", expired)
	}
	time.Sleep(5 * time.Second)
	held := c.delivered()
	time.Sleep(10 * time.Second)
	if c.delivered() != held {
		t.Fatal("the platform took events from an agent whose certificate expired")
	}
	c.says(t, "\ncredential: failed", 45*time.Second)

	c.renewing.Store(&renewing{by: c.current, trusted: []*authority{c.current, next}, lifetime: 30 * time.Second})
	run(t, "systemctl", "stop", unit)
	began := time.Now()
	c.reissue(t, c.current, []*authority{c.current}, 30*time.Second)
	run(t, "systemctl", "start", unit)
	c.invocation = started(t, c.invocation)
	c.renewed(t, "adopted", 2, began)
	c.present(next.serving(t, c.current, next), next.serving(t, c.current, next))
	c.renewing.Store(&renewing{by: next, trusted: []*authority{c.current, next}, lifetime: 30 * time.Second})
	began = time.Now()
	c.renewed(t, "unchanged", 2, began)
	c.renewing.Store(&renewing{by: next, trusted: []*authority{next}, lifetime: time.Hour})
	began = time.Now()
	c.renewed(t, "adopted", 1, began)
	c.current = next
	c.present(next.serving(t, next), next.serving(t, next))
	c.caughtUp(t, "the rotation", 2*time.Minute)

	c.mode.Store(withdrawn)
	time.Sleep(2 * time.Second)
	before := c.delivered()
	time.Sleep(18 * time.Second)
	if c.delivered() != before {
		t.Error("the platform took events while it did not admit the agent")
	}
	c.says(t, "no longer admits this agent", 45*time.Second)
	c.mode.Store(answering)
	writing.stop(t)
	c.settled(t, 3*time.Minute)
	if kept := slices.DeleteFunc(journal(t, c.invocation), func(entry map[string]any) bool { return entry["msg"] != "spool_records_quarantined" }); len(kept) > 0 {
		t.Errorf("the agent quarantined records the platform refused only for a while: %v", kept)
	}
}
