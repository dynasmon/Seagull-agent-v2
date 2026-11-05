package compatibility_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-agent-v2/internal/enrollment"
	"github.com/dynasmon/Seagull-agent-v2/internal/link"
	"github.com/dynasmon/Seagull-agent-v2/internal/pki"
	"github.com/dynasmon/Seagull-agent-v2/internal/policy"
	"github.com/dynasmon/Seagull-agent-v2/internal/protocol"
	"github.com/dynasmon/Seagull-agent-v2/internal/renewal"
	"github.com/dynasmon/Seagull-agent-v2/internal/transport"
	"github.com/dynasmon/Seagull-agent-v2/internal/update"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
	assessmentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/assessment/v1"
	controlv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/control/v1"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	ingestv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/ingest/v1"
	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
	platformv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/platform/v1"
	updatev1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/update/v1"
)

var bookJudged = map[string]struct {
	outcome protocol.Outcome
	record  int
}{
	"events-accepted":               {protocol.Durable, -1},
	"events-replayed":               {protocol.Durable, -1},
	"inventory-accepted":            {protocol.Durable, -1},
	"status-accepted":               {protocol.Durable, -1},
	"assessments-accepted":          {protocol.Durable, -1},
	"events-protocol-2":             {protocol.Incompatible, -1},
	"inventory-protocol-2":          {protocol.Incompatible, -1},
	"events-schema-2":               {protocol.Incompatible, 1},
	"status-schema-2":               {protocol.Incompatible, 1},
	"assessments-schema-2":          {protocol.Incompatible, 1},
	"events-unknown-class":          {protocol.RecordRefused, 1},
	"inventory-unknown-kind":        {protocol.RecordRefused, 1},
	"inventory-unknown-mode":        {protocol.RecordRefused, 1},
	"events-too-old":                {protocol.RecordRefused, 1},
	"events-ahead":                  {protocol.Disputed, 1},
	"events-too-many":               {protocol.BatchTooLarge, -1},
	"events-batch-too-large":        {protocol.BatchTooLarge, -1},
	"events-body-too-large":         {protocol.BatchTooLarge, -1},
	"events-malformed-payload":      {protocol.BatchUndecodable, -1},
	"events-malformed-batch-id":     {protocol.Unexpected, -1},
	"events-unsupported-media-type": {protocol.Unexpected, -1},
	"events-backbone-unavailable":   {protocol.Unconfirmed, -1},
	"events-rate-limited":           {protocol.Busy, -1},
	"events-gateway-at-capacity":    {protocol.Busy, -1},
	"events-roster-stale":           {protocol.Busy, -1},
	"events-agent-not-registered":   {protocol.AgentRefused, -1},
	"events-agent-not-admitted":     {protocol.AgentRefused, -1},
	"inventory-agent-not-admitted":  {protocol.AgentRefused, -1},
}

var bookUnbuilt = []string{
	"events-protocol-2", "inventory-protocol-2", "events-malformed-payload", "events-body-too-large", "events-batch-too-large",
}

var bookDescribed = map[string]string{
	"gateway-descriptor":                      "",
	"gateway-descriptor-unchanged":            "",
	"agent-descriptor":                        "",
	"agent-descriptor-unchanged":              "",
	"gateway-descriptor-agent-not-registered": "events-agent-not-registered",
	"gateway-descriptor-roster-stale":         "events-roster-stale",
}

var bookCertified = map[string]error{
	"issuance-accepted":     nil,
	"renewal-renewed":       nil,
	"renewal-asked-again":   nil,
	"issuance-other-agent":  enrollment.ErrUnreadable,
	"issuance-unregistered": enrollment.ErrUnreadable,
	"renewal-superseded":    errLasting,
	"renewal-revoked":       errLasting,
}

var errLasting = errors.New("a refusal that waits for an operator")

var bookPolicies = map[string]policy.Answer{
	"policy-none":         policy.NoPolicy,
	"policy-served":       policy.Served,
	"policy-unchanged":    policy.Unchanged,
	"policy-not-admitted": policy.NotAdmitted,
}

var bookUpdates = map[string]string{
	"update-offered":      "200",
	"update-unchanged":    "304",
	"update-not-admitted": "403",
}

func TestEveryAnswerABackendRecordedIsOneTheAgentReads(t *testing.T) {
	for _, recorded := range books(t) {
		t.Run(recorded.name(), func(t *testing.T) {
			if recorded.Protocol != protocol.Version {
				t.Fatalf("the book records protocol %d, and the agent speaks %d", recorded.Protocol, protocol.Version)
			}
			read := map[string]bool{}
			for _, answered := range recorded.Answers {
				claims := 0
				for _, family := range []bool{
					has(bookJudged, answered.Name), has(bookDescribed, answered.Name), has(bookCertified, answered.Name),
					has(bookPolicies, answered.Name), has(bookUpdates, answered.Name),
				} {
					if family {
						claims++
					}
				}
				if claims != 1 {
					t.Errorf("%s is read by %d of the agent's readers, want one: decide what the agent makes of it", answered.Name, claims)
				}
				read[answered.Name] = true
			}
			for _, names := range [][]string{
				keys(bookJudged), keys(bookDescribed), keys(bookCertified), keys(bookPolicies), keys(bookUpdates),
			} {
				for _, name := range names {
					if !read[name] {
						t.Errorf("the book recorded no %s", name)
					}
				}
			}
		})
	}
}

func TestTheAgentReadsEveryBatchAnswerABackendRecordedAsWhatItMeans(t *testing.T) {
	for _, recorded := range books(t) {
		for name, want := range bookJudged {
			t.Run(recorded.name()+"/"+name, func(t *testing.T) {
				answered := recorded.answer(t, name)
				verdict := recorded.judge(t, answered)
				if verdict.Outcome != want.outcome || verdict.Record != want.record {
					t.Fatalf("judged %v about record %d (%v), want %v about record %d", verdict.Outcome, verdict.Record, verdict.Reason, want.outcome, want.record)
				}
				if answered.RetryAfter && want.outcome != protocol.Busy && want.outcome != protocol.Unconfirmed {
					t.Fatalf("an answer asking the agent to wait is judged %v", want.outcome)
				}
			})
		}
		t.Run(recorded.name()+"/events-replayed", func(t *testing.T) {
			first, again := recorded.answer(t, "events-accepted"), recorded.answer(t, "events-replayed")
			if !bytes.Equal(recorded.request(t, first), recorded.request(t, again)) {
				t.Fatal("the batch sent again after its answer was lost is not the batch sent first")
			}
		})
	}
}

func TestTheBatchesABackendRecordedAreTheBytesTheAgentBuildsFromTheirRecords(t *testing.T) {
	for _, recorded := range books(t) {
		for name := range bookJudged {
			if slices.Contains(bookUnbuilt, name) {
				continue
			}
			t.Run(recorded.name()+"/"+name, func(t *testing.T) {
				answered := recorded.answer(t, name)
				carried, request := recorded.route(answered), recorded.request(t, answered)
				if built := carried.Batch(batchID(t, carried, request), carried.Records(request)); !bytes.Equal(built, request) {
					t.Fatalf("the agent builds %d bytes from the records of a batch the backend read as %d", len(built), len(request))
				}
			})
		}
	}
}

func TestABackendRecordedDescribesTheRoutesAndVersionsTheAgentSpeaks(t *testing.T) {
	sent := map[string]struct {
		batch, record string
		schema        uint32
	}{
		"POST " + protocol.Events.Path():      {"seagull.ingest.v1.EventBatch", "seagull.event.v1.Event", protocol.EventSchemaVersion},
		"POST " + protocol.Inventory.Path():   {"seagull.inventory.v1.RecordBatch", "seagull.inventory.v1.Record", protocol.InventorySchemaVersion},
		"POST " + protocol.Status.Path():      {"seagull.agent.v1.StatusBatch", "seagull.agent.v1.Status", protocol.StatusSchemaVersion},
		"POST " + protocol.Assessments.Path(): {"seagull.assessment.v1.AssessmentBatch", "seagull.assessment.v1.Assessment", protocol.AssessmentSchemaVersion},
	}
	asked := map[string]struct {
		route  string
		schema uint32
	}{
		"renewal": {"POST " + renewal.Path, 0},
		"policy":  {"GET " + policy.Path, policy.SchemaVersion},
		"update":  {"GET " + update.Path, update.SchemaVersion},
	}
	for _, recorded := range books(t) {
		t.Run(recorded.name(), func(t *testing.T) {
			gateway, agent := recorded.descriptor(t, "gateway-descriptor"), recorded.descriptor(t, "agent-descriptor")
			for _, described := range []*platformv1.Descriptor{gateway, agent} {
				if !within(described.GetSupportedProtocol(), protocol.Version) || !within(described.GetSupportedEventSchema(), protocol.EventSchemaVersion) {
					t.Errorf("a descriptor offers protocols %v and event schemas %v, and the agent speaks %d and %d",
						described.GetSupportedProtocol(), described.GetSupportedEventSchema(), protocol.Version, protocol.EventSchemaVersion)
				}
			}
			for route, want := range sent {
				index := slices.IndexFunc(gateway.GetStreams(), func(stream *platformv1.Stream) bool { return stream.GetRoute() == route })
				if index < 0 {
					t.Errorf("the gateway describes no %s, where the agent sends", route)
					continue
				}
				stream := gateway.GetStreams()[index]
				if stream.GetBatch() != want.batch || stream.GetRecord() != want.record || !within(stream.GetSupportedSchema(), want.schema) {
					t.Errorf("the gateway takes %s as %s of %s at schemas %v, and the agent sends %s of %s at schema %d", route,
						stream.GetBatch(), stream.GetRecord(), stream.GetSupportedSchema(), want.batch, want.record, want.schema)
				}
			}
			for name, want := range asked {
				index := slices.IndexFunc(agent.GetCapabilities(), func(capability *platformv1.Capability) bool { return capability.GetName() == name })
				if index < 0 {
					t.Errorf("the agent listener offers no %s, which the agent asks for", name)
					continue
				}
				capability := agent.GetCapabilities()[index]
				if capability.GetRoute() != want.route || want.schema != 0 && !within(capability.GetSupportedSchema(), want.schema) {
					t.Errorf("the agent listener offers %s at %s for schemas %v, and the agent asks %s for schema %d", name,
						capability.GetRoute(), capability.GetSupportedSchema(), want.route, want.schema)
				}
			}
			for name, refused := range bookDescribed {
				answered := recorded.answer(t, name)
				switch {
				case refused != "":
					reading, batch := recorded.judge(t, answered), recorded.judge(t, recorded.answer(t, refused))
					if reading.Outcome != batch.Outcome {
						t.Errorf("%s is read as %v, and the same refusal of a batch as %v", name, reading.Outcome, batch.Outcome)
					}
				case strings.HasSuffix(name, "-unchanged"):
					if answered.Status != http.StatusNotModified || !answered.IfNoneMatch || !answered.Tagged {
						t.Errorf("%s answered %d to a request naming what it held", name, answered.Status)
					}
				case !answered.Tagged:
					t.Errorf("%s tags no descriptor, so asking again costs it whole", name)
				}
			}
		})
	}
}

func TestTheAgentVerifiesTheCertificatesABackendRecordedAndReadsItsRefusals(t *testing.T) {
	for _, recorded := range books(t) {
		for name, want := range bookCertified {
			t.Run(recorded.name()+"/"+name, func(t *testing.T) {
				answered := recorded.answer(t, name)
				reply := recorded.reply(t, answered)
				switch want {
				case nil:
					asked := recorded.requested(t, answered)
					published, err := enrollment.Published(reply)
					if err != nil {
						t.Fatal(err)
					}
					leaf := recorded.leaf(t, reply)
					issued, err := enrollment.Verify(reply, asked, published, leaf.NotBefore)
					if err != nil {
						t.Fatalf("the agent refuses the certificate %s handed it: %v", name, err)
					}
					if issued.Certificate.Subject != asked.AgentID {
						t.Fatalf("%s certifies %s, and %s was asked for", name, issued.Certificate.Subject, asked.AgentID)
					}
					stranger := recorded.stranger(t)
					if _, err := enrollment.Verify(reply, asked, []*x509.Certificate{stranger}, leaf.NotBefore); !errors.Is(err, enrollment.ErrUntrusted) {
						t.Fatalf("%s verifies under an authority the platform never held: %v", name, err)
					}
				case errLasting:
					var refused controlv1.Refusal
					unmarshal(t, reply, &refused)
					read := &renewal.Refusal{Status: answered.Status, Code: refused.GetCode(), Detail: refused.GetDetail()}
					if !renewal.Lasting(read) {
						t.Fatalf("%s, %v, is read as a refusal that passes on its own", name, read)
					}
				default:
					if _, err := enrollment.Verify(reply, enrollment.Expected{AgentID: "e2e-agent-70"}, nil, recorded.moment(t)); !errors.Is(err, want) {
						t.Fatalf("an operator who hands the agent %s is answered %v, want %v", name, err, want)
					}
				}
			})
		}
		t.Run(recorded.name()+"/renewal-asked-again", func(t *testing.T) {
			first, again := recorded.answer(t, "renewal-renewed"), recorded.answer(t, "renewal-asked-again")
			if !bytes.Equal(recorded.request(t, first), recorded.request(t, again)) {
				t.Fatal("the renewal asked again after a lost answer was not the request asked first")
			}
		})
	}
}

func TestTheAgentReadsThePolicyAnswersABackendRecorded(t *testing.T) {
	for _, recorded := range books(t) {
		t.Run(recorded.name(), func(t *testing.T) {
			stranger, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			elsewhere, err := policy.NewVerifier([]*ecdsa.PublicKey{&stranger.PublicKey})
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"policy-none", "policy-served", "policy-unchanged", "policy-not-admitted"} {
				answered := recorded.answer(t, name)
				client := &replaying{reply: recorded.replied(t, answered)}
				var offered [][]byte
				follower, err := policy.New(policy.Options{
					Client:  client,
					URL:     "https://control.example:8446",
					Tag:     func() string { return "held" },
					Offered: func(_ context.Context, served []byte) error { offered = append(offered, served); return nil },
					Every:   func() time.Duration { return time.Hour },
					Policy:  link.Policy{},
					Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
				})
				if err != nil {
					t.Fatal(err)
				}
				follower.Ask(t.Context())
				if got := follower.State().Answer; got != bookPolicies[name] {
					t.Fatalf("%s was read as %s, want %s", name, got, bookPolicies[name])
				}
				switch {
				case bookPolicies[name] != policy.Served && len(offered) != 0:
					t.Fatalf("%s handed the agent a policy", name)
				case bookPolicies[name] == policy.Served && (len(offered) != 1 || !bytes.Equal(offered[0], recorded.reply(t, answered))):
					t.Fatalf("%s handed the agent %d policies, not the one served", name, len(offered))
				case bookPolicies[name] == policy.Served:
					if _, err := elsewhere.Verify(offered[0]); err == nil {
						t.Fatalf("%s verifies under a key the platform's operator never held", name)
					}
				}
			}
		})
	}
}

func TestTheAgentReadsTheUpdateAnswersABackendRecorded(t *testing.T) {
	for _, recorded := range books(t) {
		t.Run(recorded.name(), func(t *testing.T) {
			offered := recorded.answer(t, "update-offered")
			var offer updatev1.Offer
			if err := protocol.Decode(recorded.reply(t, offered), &offer, update.MaxOfferValues); err != nil || len(offer.GetRoots()) == 0 {
				t.Fatalf("the agent does not read the offer: %v", err)
			}
			at := recorded.moment(t)
			first, err := proto.Marshal(offer.GetRoots()[0])
			if err != nil {
				t.Fatal(err)
			}
			anchor, err := update.Anchor(first, at)
			if err != nil {
				t.Fatalf("the root the platform offers is not one its own keys signed: %v", err)
			}
			client := &replaying{}
			follower := recorded.follow(t, anchor, client, at)
			for _, name := range []string{"update-offered", "update-unchanged", "update-not-admitted"} {
				answered := recorded.answer(t, name)
				client.reply = recorded.replied(t, answered)
				follower.Ask(t.Context())
				if answered.IfNoneMatch && client.asked.Unchanged == "" {
					t.Fatalf("%s was asked naming no offer, and the platform was asked naming one", name)
				}
				state := follower.State()
				if state.Asking != bookUpdates[name] || state.Stage != "" || state.Failure != "" {
					t.Fatalf("after %s the agent stands at %+v", name, state)
				}
			}
		})
	}
}

func (b book) replied(t *testing.T, answered bookAnswer) transport.Reply {
	t.Helper()
	reply := transport.Reply{Status: answered.Status, ContentType: answered.ContentType, Body: b.reply(t, answered)}
	if answered.Tagged {
		reply.Tag = `"` + b.platform.Commit + `"`
	}
	return reply
}

func (b book) route(answered bookAnswer) protocol.Route {
	for _, route := range []protocol.Route{protocol.Inventory, protocol.Status, protocol.Assessments} {
		if answered.Path == route.Path() {
			return route
		}
	}
	return protocol.Events
}

// The book keeps no instant, and every answer an agent reads carries the Date
// its listener sent: the certificates the same run issued were valid from a
// minute before it, which stands for that Date in a judgement of whole days.
func (b book) judge(t *testing.T, answered bookAnswer) protocol.Verdict {
	t.Helper()
	carried := b.route(answered)
	var sent []protocol.Sent
	if request := b.request(t, answered); request != nil && answered.Method == http.MethodPost {
		for _, record := range carried.Records(request) {
			sent = append(sent, protocol.Sent{Record: record, Admitted: admittedAt(carried, record)})
		}
	}
	return carried.Judge(sent, protocol.Answer{Status: answered.Status, ContentType: answered.ContentType, Body: b.reply(t, answered), Date: b.moment(t)})
}

func batchID(t *testing.T, route protocol.Route, batch []byte) string {
	t.Helper()
	var held interface {
		proto.Message
		GetBatchId() string
	}
	switch route {
	case protocol.Inventory:
		held = &inventoryv1.RecordBatch{}
	case protocol.Status:
		held = &agentv1.StatusBatch{}
	case protocol.Assessments:
		held = &assessmentv1.AssessmentBatch{}
	default:
		held = &ingestv1.EventBatch{}
	}
	unmarshal(t, batch, held)
	return held.GetBatchId()
}

func admittedAt(route protocol.Route, record []byte) time.Time {
	switch route {
	case protocol.Events:
		var event eventv1.Event
		if proto.Unmarshal(record, &event) == nil && event.GetTime().GetObservedTime() != nil {
			return event.GetTime().GetObservedTime().AsTime()
		}
	case protocol.Inventory:
		var held inventoryv1.Record
		if proto.Unmarshal(record, &held) == nil && held.GetCollectedAt() != nil {
			return held.GetCollectedAt().AsTime()
		}
	case protocol.Status:
		var report agentv1.Status
		if proto.Unmarshal(record, &report) == nil && report.GetReportedAt() != nil {
			return report.GetReportedAt().AsTime()
		}
	case protocol.Assessments:
		var assessment assessmentv1.Assessment
		if proto.Unmarshal(record, &assessment) == nil && assessment.GetAssessedAt() != nil {
			return assessment.GetAssessedAt().AsTime()
		}
	}
	return time.Time{}
}

func (b book) descriptor(t *testing.T, name string) *platformv1.Descriptor {
	t.Helper()
	answered := b.answer(t, name)
	var described platformv1.Descriptor
	if answered.Status != http.StatusOK || protocol.Decode(b.reply(t, answered), &described, protocol.MaxAnswerValues) != nil {
		t.Fatalf("%s answered %d with no descriptor the agent reads", name, answered.Status)
	}
	return &described
}

func (b book) requested(t *testing.T, answered bookAnswer) enrollment.Expected {
	t.Helper()
	var asked interface{ GetCsrPem() []byte }
	switch answered.Listener {
	case "agent":
		asked = &agentv1.RenewalRequest{}
	default:
		asked = &agentv1.CertificateRequest{}
	}
	unmarshal(t, b.request(t, answered), asked.(proto.Message))
	request, err := x509.ParseCertificateRequest(pemBlock(t, asked.GetCsrPem()))
	if err != nil {
		t.Fatalf("read the request %s answered: %v", answered.Name, err)
	}
	key, err := pki.KeyID(request.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return enrollment.Expected{AgentID: request.Subject.CommonName, KeyID: key}
}

func (b book) leaf(t *testing.T, reply []byte) *x509.Certificate {
	t.Helper()
	var issued agentv1.IssuedCertificate
	unmarshal(t, reply, &issued)
	leaf, err := x509.ParseCertificate(pemBlock(t, issued.GetCertificatePem()))
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

func (b book) moment(t *testing.T) time.Time {
	t.Helper()
	return b.leaf(t, b.reply(t, b.answer(t, "issuance-accepted"))).NotBefore
}

func (b book) stranger(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	at := b.moment(t)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Seagull Agent Test CA"},
		NotBefore:             at.Add(-time.Hour),
		NotAfter:              at.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	signed, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := x509.ParseCertificate(signed)
	if err != nil {
		t.Fatal(err)
	}
	return authority
}

func pemBlock(t *testing.T, content []byte) []byte {
	t.Helper()
	block, _ := pem.Decode(content)
	if block == nil {
		t.Fatal("the answer holds no PEM block")
	}
	return block.Bytes
}

func (b book) follow(t *testing.T, anchor *update.Root, client update.Client, at time.Time) *update.Follower {
	t.Helper()
	open := func() *os.Root {
		root, err := os.OpenRoot(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { root.Close() })
		return root
	}
	store, err := update.OpenStore(open())
	if err != nil {
		t.Fatal(err)
	}
	version, _ := update.ParseVersion("v0.1.0")
	follower, err := update.NewFollower(update.Options{
		Client:  client,
		URL:     "https://control.example:8446",
		Anchor:  anchor,
		Store:   store,
		Staging: update.OpenStaging(open()),
		Journal: func() (update.Journal, bool, error) { return update.Journal{}, false, nil },
		Running: update.Running{Version: version, OS: "linux", Architecture: "amd64", Format: updatev1.Format_FORMAT_DEB, State: update.StateGeneration},
		Every:   func() time.Duration { return time.Hour },
		Policy:  link.Policy{Retry: time.Second, RetryLongest: time.Minute, Hold: time.Minute, HoldLongest: time.Hour},
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:     func() time.Time { return at },
	})
	if err != nil {
		t.Fatal(err)
	}
	return follower
}

func within(supported *platformv1.VersionRange, version uint32) bool {
	return supported != nil && supported.GetMinimum() <= version && version <= supported.GetMaximum()
}

func has[V any](held map[string]V, name string) bool {
	_, found := held[name]
	return found
}

func keys[V any](held map[string]V) []string {
	names := make([]string, 0, len(held))
	for name := range held {
		names = append(names, name)
	}
	return names
}
