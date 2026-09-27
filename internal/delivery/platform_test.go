package delivery_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"math/big"
	"mime"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-agent-v2/internal/delivery"
	"github.com/dynasmon/Seagull-agent-v2/internal/governor"
	"github.com/dynasmon/Seagull-agent-v2/internal/pki"
	"github.com/dynasmon/Seagull-agent-v2/internal/protocol"
	"github.com/dynasmon/Seagull-agent-v2/internal/spool"
	"github.com/dynasmon/Seagull-agent-v2/internal/transport"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	ingestv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/ingest/v1"
	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
)

const settle = 10 * time.Second

var (
	identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$`)
	fast       = delivery.Policy{Retry: 5 * time.Millisecond, RetryLongest: 20 * time.Millisecond, Hold: 10 * time.Millisecond, HoldLongest: 40 * time.Millisecond}
)

// A batch as the platform received it: the bytes that arrived, the records it
// read out of them with the published contracts, and how many times a batch
// under this identifier had arrived, this one included.
type received struct {
	route   protocol.Route
	id      string
	body    []byte
	records [][]byte
	ids     []string
	attempt int
	gone    <-chan struct{}
}

// The platform an agent delivers to, as the recorded gateway behaves: TLS 1.3
// alone, the certificate of an agent required, batches decoded with the
// published contracts, records published whole or not at all, and every record
// acknowledged once they are. It keeps every record it published, in order,
// and stores each once, as the platform's own store keeps an event however
// often it arrives; a record stored twice under one identifier with different
// bytes is a conflict.
type platform struct {
	*httptest.Server
	trusted []*x509.Certificate
	agents  *authority

	mu        sync.Mutex
	intercept func(w http.ResponseWriter, r *http.Request) bool
	answer    func(w http.ResponseWriter, arrived *received) bool
	batches   []*received
	published []string
	stored    map[protocol.Route]map[string][]byte
	conflicts []string
}

func emulate(t *testing.T) *platform {
	t.Helper()
	issuer, agents := authorityNamed(t, "Seagull platform"), authorityNamed(t, "Seagull agents")
	emulated := &platform{trusted: []*x509.Certificate{issuer.certificate}, agents: agents, stored: map[protocol.Route]map[string][]byte{}}
	emulated.Server = httptest.NewUnstartedServer(http.HandlerFunc(emulated.serve))
	emulated.Config.ErrorLog = log.New(io.Discard, "", 0)
	pool := x509.NewCertPool()
	pool.AddCert(agents.certificate)
	emulated.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{issuer.server(t, "localhost", "127.0.0.1")},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
	}
	emulated.StartTLS()
	t.Cleanup(emulated.Close)
	return emulated
}

func (p *platform) serve(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	intercept, answer := p.intercept, p.answer
	p.mu.Unlock()
	if intercept != nil && intercept(w, r) {
		return
	}
	route := map[string]protocol.Route{"/v1/events": protocol.Events, "/v1/inventory": protocol.Inventory}[r.URL.Path]
	if route == 0 || r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || media != protocol.ContentType {
		refuse(w, http.StatusUnsupportedMediaType, "unsupported_media_type", "", -1)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8<<20))
	if err != nil {
		refuse(w, http.StatusBadRequest, "unreadable_body", "", -1)
		return
	}
	arrived, refused := decode(route, body)
	if refused != nil {
		refused(w)
		return
	}
	arrived.gone = r.Context().Done()
	p.mu.Lock()
	for _, earlier := range p.batches {
		if earlier.id == arrived.id {
			arrived.attempt = max(arrived.attempt, earlier.attempt)
		}
	}
	arrived.attempt++
	p.batches = append(p.batches, arrived)
	p.mu.Unlock()
	if answer != nil && answer(w, arrived) {
		return
	}
	p.publish(arrived, len(arrived.records))
	acknowledge(w, &ingestv1.BatchAck{Accepted: true, Durable: true, Received: uint32(len(arrived.records))})
}

func decode(route protocol.Route, body []byte) (*received, func(http.ResponseWriter)) {
	arrived := &received{route: route, body: body, records: route.Records(body)}
	var version uint32
	switch route {
	case protocol.Events:
		var batch ingestv1.EventBatch
		if err := proto.Unmarshal(body, &batch); err != nil {
			return nil, func(w http.ResponseWriter) { refuse(w, http.StatusBadRequest, "malformed_payload", "", -1) }
		}
		arrived.id, version = batch.GetBatchId(), batch.GetProtocolVersion()
		for _, event := range batch.GetEvents() {
			arrived.ids = append(arrived.ids, event.GetEventId())
		}
	case protocol.Inventory:
		var batch inventoryv1.RecordBatch
		if err := proto.Unmarshal(body, &batch); err != nil {
			return nil, func(w http.ResponseWriter) { refuse(w, http.StatusBadRequest, "malformed_payload", "", -1) }
		}
		arrived.id, version = batch.GetBatchId(), batch.GetProtocolVersion()
		for _, record := range batch.GetRecords() {
			arrived.ids = append(arrived.ids, record.GetRecordId())
		}
	}
	switch {
	case len(arrived.ids) == 0:
		return nil, func(w http.ResponseWriter) { refuse(w, http.StatusUnprocessableEntity, "empty_batch", "", -1) }
	case version != protocol.Version:
		return nil, func(w http.ResponseWriter) {
			refuse(w, http.StatusUpgradeRequired, "unsupported_protocol_version", "", -1)
		}
	case !identifier.MatchString(arrived.id):
		return nil, func(w http.ResponseWriter) {
			refuse(w, http.StatusUnprocessableEntity, "malformed_batch_id", "batch_id", -1)
		}
	case len(arrived.records) != len(arrived.ids):
		return nil, func(w http.ResponseWriter) { refuse(w, http.StatusBadRequest, "malformed_payload", "", -1) }
	}
	return arrived, nil
}

// publish takes the first records of a batch, as a backbone that failed part
// way through a batch has taken some of it.
func (p *platform) publish(arrived *received, records int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	kept := p.stored[arrived.route]
	if kept == nil {
		kept = map[string][]byte{}
		p.stored[arrived.route] = kept
	}
	for i, id := range arrived.ids[:records] {
		p.published = append(p.published, arrived.route.String()+"/"+id)
		if held, found := kept[id]; found && !bytes.Equal(held, arrived.records[i]) {
			p.conflicts = append(p.conflicts, fmt.Sprintf("%s %s arrived again as other bytes, in batch %s", arrived.route, id, arrived.id))
		}
		kept[id] = slices.Clone(arrived.records[i])
	}
}

func (p *platform) set(answer func(w http.ResponseWriter, arrived *received) bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.answer = answer
}

func (p *platform) interceptWith(intercept func(w http.ResponseWriter, r *http.Request) bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.intercept = intercept
}

func (p *platform) received() []*received {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.batches)
}

func (p *platform) storedIDs(route protocol.Route) []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	var ids []string
	for id := range p.stored[route] {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}

func (p *platform) publications(route protocol.Route, id string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return strings.Count(strings.Join(p.published, "\n")+"\n", route.String()+"/"+id+"\n")
}

func (p *platform) conflicting() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.conflicts)
}

func refuse(w http.ResponseWriter, status int, code, field string, index int) {
	answer(w, status, &ingestv1.Rejection{Code: code, Detail: "as the gateway explains it", Field: field, EventIndex: int32(index)})
}

func acknowledge(w http.ResponseWriter, acknowledgement *ingestv1.BatchAck) {
	answer(w, http.StatusOK, acknowledgement)
}

func answer(w http.ResponseWriter, status int, message proto.Message) {
	encoded, err := proto.Marshal(message)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", protocol.ContentType)
	w.WriteHeader(status)
	w.Write(encoded)
}

// The key and the certificate an enrolled installation holds: the key drawn by
// the agent's own provider in a directory a child process can open too.
type credential struct {
	keys     string
	keyID    string
	chain    [][]byte
	provider pki.KeyProvider
}

func enrolled(t *testing.T, serving *platform) *credential {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "keys")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatalf("create %s: %v", directory, err)
	}
	provider := keyProvider(t, directory)
	key, err := provider.Create()
	if err != nil {
		t.Fatalf("draw a key: %v", err)
	}
	return &credential{keys: directory, keyID: key.ID(), chain: serving.agents.issue(t, "web-01", key.Public()), provider: provider}
}

func keyProvider(t testing.TB, directory string) pki.KeyProvider {
	t.Helper()
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatalf("open %s: %v", directory, err)
	}
	t.Cleanup(func() { root.Close() })
	provider, err := pki.OpenKeyFiles(root)
	if err != nil {
		t.Fatalf("open the keys in %s: %v", directory, err)
	}
	return provider
}

func (c *credential) Credential() (transport.Credential, error) {
	key, err := c.provider.Open(c.keyID)
	if err != nil {
		return transport.Credential{}, err
	}
	return transport.Credential{Chain: c.chain, Signer: key}, nil
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

func (a *authority) issue(t *testing.T, subject string, public any, hosts ...string) [][]byte {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serials.Add(1)),
		Subject:      pkix.Name{CommonName: subject},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if len(hosts) > 0 {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		for _, host := range hosts {
			if address := net.ParseIP(host); address != nil {
				template.IPAddresses = append(template.IPAddresses, address)
			} else {
				template.DNSNames = append(template.DNSNames, host)
			}
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, a.certificate, public, a.key)
	if err != nil {
		t.Fatalf("issue a certificate for %s: %v", subject, err)
	}
	return [][]byte{der}
}

func (a *authority) server(t *testing.T, hosts ...string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("draw a key: %v", err)
	}
	return tls.Certificate{Certificate: a.issue(t, "ingest-gateway", key.Public(), hosts...), PrivateKey: key}
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

func (l *logs) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.written.String()
}

func spoolIn(t testing.TB, directory string) *spool.Spool {
	t.Helper()
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatalf("open %s: %v", directory, err)
	}
	t.Cleanup(func() { root.Close() })
	held, err := spool.Open(root, spool.Limits{MaxBytes: 64 << 20}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("open the spool in %s: %v", directory, err)
	}
	t.Cleanup(func() { held.Close() })
	return held
}

func spoolDirectory(t testing.TB) string {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "spool")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatalf("create %s: %v", directory, err)
	}
	return directory
}

func event(id string, at time.Time) *eventv1.Event {
	return &eventv1.Event{
		EventId:       id,
		SchemaVersion: protocol.EventSchemaVersion,
		EventClass:    eventv1.EventClass_EVENT_CLASS_AUTHENTICATION,
		Time:          &eventv1.Timestamps{EventTime: timestamppb.New(at), ObservedTime: timestamppb.New(at)},
		Collection:    &eventv1.Collection{Collector: "auth", Source: "journal"},
		Body: &eventv1.Event_Authentication{Authentication: &eventv1.Authentication{
			Activity:  eventv1.Authentication_ACTIVITY_LOGON,
			Outcome:   eventv1.Outcome_OUTCOME_FAILURE,
			User:      &eventv1.User{Name: "root"},
			RawRecord: "sshd[812]: Failed password for root from 203.0.113.9 port 51022 ssh2",
		}},
	}
}

func snapshot(id string, at time.Time, items int) *inventoryv1.Record {
	record := &inventoryv1.Record{
		RecordId:      id,
		SchemaVersion: protocol.InventorySchemaVersion,
		Kind:          inventoryv1.Kind_KIND_PACKAGE,
		Mode:          inventoryv1.Mode_MODE_SNAPSHOT,
		CollectedAt:   timestamppb.New(at),
		Collection:    &eventv1.Collection{Collector: "inventory", Source: "dpkg"},
	}
	for i := range items {
		record.Items = append(record.Items, &inventoryv1.Item{Body: &inventoryv1.Item_Package{
			Package: &inventoryv1.Package{Name: fmt.Sprintf("package-%d", i), Version: "1.0", Architecture: "amd64", Manager: "dpkg"},
		}})
	}
	return record
}

func admitEvents(t testing.TB, held *spool.Spool, prefix string, count int) []string {
	t.Helper()
	var records []spool.Record
	var ids []string
	for i := range count {
		id := fmt.Sprintf("%s-%06d", prefix, i)
		records = append(records, spool.Record{ID: id, Payload: marshal(t, event(id, time.Now()))})
		ids = append(ids, id)
	}
	if _, err := held.Admit(spool.Events, records...); err != nil {
		t.Fatalf("admit %d events: %v", count, err)
	}
	return ids
}

func admitInventory(t testing.TB, held *spool.Spool, prefix string, count, items int) []string {
	t.Helper()
	var records []spool.Record
	var ids []string
	for i := range count {
		id := fmt.Sprintf("%s-%06d", prefix, i)
		records = append(records, spool.Record{ID: id, Payload: marshal(t, snapshot(id, time.Now(), items))})
		ids = append(ids, id)
	}
	if _, err := held.Admit(spool.Inventory, records...); err != nil {
		t.Fatalf("admit %d inventory records: %v", count, err)
	}
	return ids
}

func marshal(t testing.TB, message proto.Message) []byte {
	t.Helper()
	encoded, err := proto.Marshal(message)
	if err != nil {
		t.Fatalf("encode %T: %v", message, err)
	}
	return encoded
}

type delivering struct {
	delivery *delivery.Delivery
	client   *transport.Client
	governor *governor.Governor
	logs     *logs
	limits   *atomic.Pointer[delivery.Batching]
	stop     context.CancelFunc
	done     chan error
}

type setup struct {
	batching delivery.Batching
	policy   delivery.Policy
	timeout  time.Duration
	uploads  int
}

func deliver(t *testing.T, held *spool.Spool, serving *platform, holding *credential, change func(*setup)) *delivering {
	t.Helper()
	chosen := setup{
		batching: delivery.Batching{MaxBytes: 4 << 20, MaxEvents: 1000, MaxInventoryRecords: 64},
		policy:   fast,
		timeout:  2 * time.Second,
		uploads:  2,
	}
	if change != nil {
		change(&chosen)
	}
	client, err := transport.New(transport.Options{
		Authorities:      serving.trusted,
		Credentials:      holding,
		ConnectTimeout:   min(time.Second, chosen.timeout),
		RequestTimeout:   chosen.timeout,
		MaxResponseBytes: 64 << 10,
		MaxConnections:   chosen.uploads,
	})
	if err != nil {
		t.Fatalf("compose the transport: %v", err)
	}
	t.Cleanup(client.Close)
	written := &logs{}
	logger := slog.New(slog.NewJSONHandler(written, &slog.HandlerOptions{Level: slog.LevelDebug}))
	governed, err := governor.New(logger, "8a4a6c52-3a3b-4f0e-9c38-1f2d7f0c9b11",
		governor.Budget{Scans: 1, ScanBytesPerSecond: 1 << 20, Uploads: chosen.uploads, UploadBytesPerSecond: 1 << 30})
	if err != nil {
		t.Fatalf("compose the governor: %v", err)
	}
	limits := &atomic.Pointer[delivery.Batching]{}
	limits.Store(&chosen.batching)
	delivered, err := delivery.New(delivery.Options{
		Spool:    held,
		Client:   client,
		Governor: governed,
		URL:      serving.URL,
		Batching: func() delivery.Batching { return *limits.Load() },
		Policy:   chosen.policy,
		Logger:   logger,
		Recovery: func(err error) string { return "recover from " + err.Error() },
	})
	if err != nil {
		t.Fatalf("compose the delivery: %v", err)
	}
	ctx, stop := context.WithCancel(context.Background())
	running := &delivering{delivery: delivered, client: client, governor: governed, logs: written, limits: limits, stop: stop, done: make(chan error, 1)}
	go func() { running.done <- delivered.Run(ctx) }()
	t.Cleanup(func() { running.halt(t) })
	return running
}

func (d *delivering) halt(t *testing.T) {
	t.Helper()
	d.stop()
	select {
	case err, open := <-d.done:
		if open && err != nil {
			t.Errorf("the delivery stopped with %v", err)
		}
		if open {
			close(d.done)
		}
	case <-time.After(settle):
		t.Fatal("the delivery did not stop")
	}
}

func eventually(t *testing.T, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(settle)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("%s did not happen within %s", what, settle)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func outstanding(held *spool.Spool, stream spool.Stream) spool.StreamStats {
	for _, kept := range held.Stats().Streams {
		if kept.Stream == stream {
			return kept
		}
	}
	return spool.StreamStats{}
}
