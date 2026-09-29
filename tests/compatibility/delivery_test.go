package compatibility_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-agent-v2/internal/link"
	"github.com/dynasmon/Seagull-agent-v2/internal/protocol"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	ingestv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/ingest/v1"
	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
)

// Each delivery.json under testdata was recorded from the ingest gateway of one
// platform commit, driven by that commit's own end-to-end harness: batches
// accepted and sent again under another identifier, and batches the gateway
// refused for their size, their encoding, their identifier, their media type,
// the times of a record, a backbone that did not take them, an agent sending
// too fast and a gateway holding all it may. With the answer's status, media
// type and date, and how many records the gateway's backbone held after it.
type deliveryRecording struct {
	directory string
	Platform  struct {
		Repository string `json:"repository"`
		Commit     string `json:"commit"`
		Contracts  string `json:"contracts"`
	} `json:"platform"`
	RecordedAt time.Time          `json:"recorded_at"`
	Exchanges  []deliveryExchange `json:"exchanges"`
}

type deliveryExchange struct {
	Name        string `json:"name"`
	Route       string `json:"route"`
	Status      int    `json:"status"`
	ContentType string `json:"content_type"`
	Date        string `json:"date"`
	RetryAfter  string `json:"retry_after"`
	Published   int    `json:"published"`
}

// What the agent does with a batch after each answer a recorded platform gave:
// only what the platform made durable is dropped, only a record it refused for
// good is quarantined, and every other answer leaves the batch to be sent again.
var judged = map[string]struct {
	outcome protocol.Outcome
	record  int
}{
	"events-accepted":                 {protocol.Durable, -1},
	"events-original":                 {protocol.Durable, -1},
	"events-replayed":                 {protocol.Durable, -1},
	"inventory-accepted":              {protocol.Durable, -1},
	"inventory-original":              {protocol.Durable, -1},
	"inventory-replayed":              {protocol.Durable, -1},
	"events-backbone-unavailable":     {protocol.Unconfirmed, -1},
	"inventory-backbone-unavailable":  {protocol.Unconfirmed, -1},
	"events-rate-limited":             {protocol.Busy, -1},
	"events-at-capacity":              {protocol.Busy, -1},
	"events-body-too-large":           {protocol.BatchTooLarge, -1},
	"events-too-many":                 {protocol.BatchTooLarge, -1},
	"inventory-too-many-items":        {protocol.BatchTooLarge, -1},
	"events-malformed-payload":        {protocol.BatchUndecodable, -1},
	"events-too-old":                  {protocol.RecordRefused, 1},
	"inventory-too-old":               {protocol.RecordRefused, 1},
	"events-ahead":                    {protocol.Disputed, 1},
	"inventory-ahead":                 {protocol.Disputed, 1},
	"events-invalid-record":           {protocol.RecordRefused, 0},
	"inventory-invalid-record":        {protocol.RecordRefused, 0},
	"events-unknown-class":            {protocol.RecordRefused, 0},
	"events-unknown-transport":        {protocol.RecordRefused, 1},
	"inventory-unknown-kind":          {protocol.RecordRefused, 0},
	"inventory-unknown-mode":          {protocol.RecordRefused, 0},
	"inventory-unknown-service-state": {protocol.RecordRefused, 0},
	"events-protocol-2":               {protocol.Incompatible, -1},
	"inventory-protocol-2":            {protocol.Incompatible, -1},
	"events-schema-2":                 {protocol.Incompatible, 1},
	"inventory-schema-2":              {protocol.Incompatible, 1},
	"events-agent-not-registered":     {protocol.AgentRefused, -1},
	"events-agent-not-admitted":       {protocol.AgentRefused, -1},
	"events-unusable-identity":        {protocol.AgentRefused, -1},
	"inventory-agent-not-registered":  {protocol.AgentRefused, -1},
	"inventory-agent-not-admitted":    {protocol.AgentRefused, -1},
	"inventory-unusable-identity":     {protocol.AgentRefused, -1},
	"events-unsupported-media-type":   {protocol.Unexpected, -1},
	"events-malformed-batch-id":       {protocol.Unexpected, -1},
}

func TestTheAgentReadsEveryAnswerARecordedGatewayGaveAsWhatItMeans(t *testing.T) {
	for _, recorded := range deliveryRecordings(t) {
		judgedHere := map[string]bool{}
		for _, sent := range recorded.Exchanges {
			t.Run(recorded.name()+"/"+sent.Name, func(t *testing.T) {
				want, known := judged[sent.Name]
				if !known {
					t.Fatalf("nothing says what the agent does after %s", sent.Name)
				}
				date, err := http.ParseTime(sent.Date)
				if err != nil {
					t.Fatalf("the platform answered at %q: %v", sent.Date, err)
				}
				verdict := recorded.judge(t, sent.Route, sent.Name, protocol.Answer{
					Status: sent.Status, ContentType: sent.ContentType, Body: recorded.payload(t, sent.Name, "reply"), Date: date,
				})
				if verdict.Outcome != want.outcome || verdict.Record != want.record {
					t.Fatalf("judged %v about record %d (%v), want %v about record %d", verdict.Outcome, verdict.Record, verdict.Reason, want.outcome, want.record)
				}
			})
			judgedHere[sent.Name] = true
		}
		for _, older := range recordings(t) {
			if older.directory != recorded.directory {
				continue
			}
			for _, sent := range older.Exchanges {
				t.Run(recorded.name()+"/"+sent.Name, func(t *testing.T) {
					want := judged[sent.Name]
					body := older.payload(t, sent.Name, "reply")
					verdict := recorded.judge(t, sent.Route, sent.Name, protocol.Answer{Status: sent.Status, ContentType: protocol.ContentType, Body: body})
					if verdict.Outcome != want.outcome || verdict.Record != want.record {
						t.Fatalf("judged %v about record %d (%v), want %v about record %d", verdict.Outcome, verdict.Record, verdict.Reason, want.outcome, want.record)
					}
				})
				judgedHere[sent.Name] = true
			}
		}
		for name := range judged {
			if !judgedHere[name] {
				t.Errorf("%s recorded no %s exchange", recorded.name(), name)
			}
		}
	}
}

func TestTheAgentWaitsAsLongAsARecordedGatewayAskedBeforeSendingAgain(t *testing.T) {
	policy, err := link.Policy{}.Settled()
	if err != nil {
		t.Fatalf("settle the documented policy: %v", err)
	}
	for _, recorded := range deliveryRecordings(t) {
		asking := 0
		for _, sent := range recorded.Exchanges {
			if sent.RetryAfter == "" {
				continue
			}
			asking++
			t.Run(recorded.name()+"/"+sent.Name, func(t *testing.T) {
				seconds, err := strconv.Atoi(sent.RetryAfter)
				if err != nil || seconds < 1 {
					t.Fatalf("the gateway asked the agent to wait %q", sent.RetryAfter)
				}
				if outcome := judged[sent.Name].outcome; outcome != protocol.Busy && outcome != protocol.Unconfirmed {
					t.Fatalf("an answer asking the agent to wait is judged %v", outcome)
				}
				asked := time.Duration(seconds) * time.Second
				for range 1000 {
					if wait := policy.Wait(1, false, asked); wait < asked || wait > 2*asked {
						t.Fatalf("asked to wait %s, the agent waits %s", asked, wait)
					}
				}
			})
		}
		if asking == 0 {
			t.Errorf("%s recorded no answer asking the agent to wait", recorded.name())
		}
	}
}

// A batch built again after a restart carries its records under another batch
// identifier, and the recorded gateway takes it again whole: the platform's
// backbone then holds every record twice, so it is the platform's store that
// keeps a record once by its identifier, and the agent's part is to send it
// again unchanged.
func TestARecordedGatewayTakesAgainTheRecordsOfABatchBuiltAgain(t *testing.T) {
	for _, recorded := range deliveryRecordings(t) {
		for _, route := range []string{"events", "inventory"} {
			t.Run(recorded.name()+"/"+route, func(t *testing.T) {
				first, again := recorded.exchange(t, route+"-original"), recorded.exchange(t, route+"-replayed")
				original, replayed := recorded.payload(t, first.Name, "request"), recorded.payload(t, again.Name, "request")
				carried := routeOf(t, first.Route)
				if identifier(t, carried, original) == identifier(t, carried, replayed) {
					t.Fatal("the batch built again kept the identifier of the one it was built from")
				}
				records, recarried := carried.Records(original), carried.Records(replayed)
				if len(records) == 0 || len(records) != len(recarried) {
					t.Fatalf("the batches carried %d and %d records", len(records), len(recarried))
				}
				for i := range records {
					if !bytes.Equal(records[i], recarried[i]) {
						t.Fatalf("record %d was sent again as other bytes", i)
					}
				}
				if again.Status != http.StatusOK || again.Published != 2*first.Published {
					t.Fatalf("sent again, the batch was answered %d and the backbone held %d records after holding %d", again.Status, again.Published, first.Published)
				}
			})
		}
	}
}

// The agent frames records it never decodes, so the batches a recorded
// platform read have to be the bytes the agent builds from their records.
func TestTheRecordedBatchesAreTheBytesTheAgentBuildsFromTheirRecords(t *testing.T) {
	for _, recorded := range deliveryRecordings(t) {
		for _, sent := range recorded.Exchanges {
			if sent.Name == "events-malformed-payload" {
				continue
			}
			t.Run(recorded.name()+"/"+sent.Name, func(t *testing.T) {
				carried := routeOf(t, sent.Route)
				request := recorded.payload(t, sent.Name, "request")
				if built := carried.Batch(identifier(t, carried, request), carried.Records(request)); !bytes.Equal(built, request) {
					t.Fatalf("the agent builds %d bytes from the records of a batch the platform read as %d", len(built), len(request))
				}
			})
		}
	}
}

func deliveryRecordings(t *testing.T) []deliveryRecording {
	t.Helper()
	manifests, err := filepath.Glob(filepath.Join("testdata", "*", "delivery.json"))
	if err != nil || len(manifests) == 0 {
		t.Fatalf("find the recorded deliveries: %v", err)
	}
	var found []deliveryRecording
	for _, manifest := range manifests {
		encoded, err := os.ReadFile(manifest)
		if err != nil {
			t.Fatalf("read %s: %v", manifest, err)
		}
		decoder := json.NewDecoder(bytes.NewReader(encoded))
		decoder.DisallowUnknownFields()
		recorded := deliveryRecording{directory: filepath.Dir(manifest)}
		if err := decoder.Decode(&recorded); err != nil {
			t.Fatalf("decode %s: %v", manifest, err)
		}
		if recorded.Platform.Commit == "" || recorded.RecordedAt.IsZero() || len(recorded.Exchanges) == 0 {
			t.Fatalf("%s does not say what it recorded and when", manifest)
		}
		found = append(found, recorded)
	}
	return found
}

func (r deliveryRecording) name() string { return filepath.Base(r.directory) }

func (r deliveryRecording) exchange(t *testing.T, name string) deliveryExchange {
	t.Helper()
	index := slices.IndexFunc(r.Exchanges, func(sent deliveryExchange) bool { return sent.Name == name })
	if index < 0 {
		t.Fatalf("%s recorded no %s exchange", r.name(), name)
	}
	return r.Exchanges[index]
}

func (r deliveryRecording) payload(t *testing.T, name, part string) []byte {
	t.Helper()
	encoded, err := os.ReadFile(filepath.Join(r.directory, name+"."+part+".pb"))
	if err != nil {
		t.Fatalf("read the %s of %s: %v", part, name, err)
	}
	return encoded
}

// The agent admits a record once it observed it, so a recorded record is taken
// to have been admitted at the moment it says it was observed or collected.
func (r deliveryRecording) judge(t *testing.T, route, name string, answer protocol.Answer) protocol.Verdict {
	t.Helper()
	carried := routeOf(t, route)
	request := r.payload(t, name, "request")
	var sent []protocol.Sent
	for _, record := range carried.Records(request) {
		admitted := r.RecordedAt
		switch carried {
		case protocol.Events:
			var event eventv1.Event
			if proto.Unmarshal(record, &event) == nil && event.GetTime().GetObservedTime() != nil {
				admitted = event.GetTime().GetObservedTime().AsTime()
			}
		case protocol.Inventory:
			var held inventoryv1.Record
			if proto.Unmarshal(record, &held) == nil && held.GetCollectedAt() != nil {
				admitted = held.GetCollectedAt().AsTime()
			}
		}
		sent = append(sent, protocol.Sent{Record: record, Admitted: admitted})
	}
	return carried.Judge(sent, answer)
}

func routeOf(t *testing.T, route string) protocol.Route {
	t.Helper()
	switch route {
	case eventsRoute:
		return protocol.Events
	case inventoryRoute:
		return protocol.Inventory
	}
	t.Fatalf("the agent delivers nothing to %s", route)
	return 0
}

func identifier(t *testing.T, route protocol.Route, request []byte) string {
	t.Helper()
	var id string
	switch route {
	case protocol.Events:
		var batch ingestv1.EventBatch
		if err := proto.Unmarshal(request, &batch); err != nil {
			t.Fatalf("decode a recorded batch of events: %v", err)
		}
		id = batch.GetBatchId()
	case protocol.Inventory:
		var batch inventoryv1.RecordBatch
		if err := proto.Unmarshal(request, &batch); err != nil {
			t.Fatalf("decode a recorded inventory batch: %v", err)
		}
		id = batch.GetBatchId()
	}
	return id
}

// Each replay.json under testdata was measured on a real broker: the batches of
// events-original and events-replayed in delivery.json admitted in that order
// by the gateway's own admitter, as it admits them after a lost answer, and the
// topic read back whole. Both are acknowledged as durable, and the backbone
// holds every record twice, the same but for what the gateway stamps on it.
type replayMeasurement struct {
	Platform struct {
		Repository string `json:"repository"`
		Commit     string `json:"commit"`
		Contracts  string `json:"contracts"`
		Broker     string `json:"broker"`
	} `json:"platform"`
	RecordedAt time.Time `json:"recorded_at"`
	Measured   string    `json:"measured"`
	Batches    []struct {
		Request  string `json:"request"`
		BatchID  string `json:"batch_id"`
		Accepted bool   `json:"accepted"`
		Durable  bool   `json:"durable"`
		Received int    `json:"received"`
	} `json:"batches"`
	Backbone struct {
		Records                     int            `json:"records"`
		Copies                      map[string]int `json:"copies"`
		CopiesDifferOnlyInReception bool           `json:"copies_differ_only_in_reception"`
		ReceptionBatches            []string       `json:"reception_batches"`
	} `json:"backbone"`
}

func TestARealBackboneHoldsTheRecordsOfABatchSentAgainTwiceAndUnchanged(t *testing.T) {
	for _, recorded := range deliveryRecordings(t) {
		t.Run(recorded.name(), func(t *testing.T) {
			encoded, err := os.ReadFile(filepath.Join(recorded.directory, "replay.json"))
			if err != nil {
				t.Fatalf("read the replay measured on %s: %v", recorded.name(), err)
			}
			decoder := json.NewDecoder(bytes.NewReader(encoded))
			decoder.DisallowUnknownFields()
			var measured replayMeasurement
			if err := decoder.Decode(&measured); err != nil {
				t.Fatalf("decode the replay: %v", err)
			}
			if measured.Platform.Commit != recorded.Platform.Commit || measured.Platform.Broker == "" || len(measured.Batches) != 2 {
				t.Fatalf("the replay was measured as %+v", measured)
			}
			sent, identifiers := 0, []string{}
			for _, batch := range measured.Batches {
				request := recorded.payload(t, batch.Request, "request")
				records := len(protocol.Events.Records(request))
				if identifier(t, protocol.Events, request) != batch.BatchID || !batch.Accepted || !batch.Durable || batch.Received != records {
					t.Fatalf("%s was answered %+v for %d records", batch.Request, batch, records)
				}
				sent += records
				identifiers = append(identifiers, batch.BatchID)
			}
			if measured.Backbone.Records != sent || !measured.Backbone.CopiesDifferOnlyInReception || len(measured.Backbone.Copies) != sent/2 {
				t.Fatalf("after %d records were sent the backbone held %+v", sent, measured.Backbone)
			}
			for id, copies := range measured.Backbone.Copies {
				if copies != 2 {
					t.Errorf("the backbone held %s %d times", id, copies)
				}
			}
			slices.Sort(identifiers)
			if held := slices.Sorted(slices.Values(measured.Backbone.ReceptionBatches)); !slices.Equal(held, identifiers) {
				t.Fatalf("the backbone stamped the records as received in %v", held)
			}
		})
	}
}
