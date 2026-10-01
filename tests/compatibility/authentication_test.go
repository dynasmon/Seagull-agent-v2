package compatibility_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-agent-v2/internal/governor"
	"github.com/dynasmon/Seagull-agent-v2/internal/modules/authentication"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/journal"
	"github.com/dynasmon/Seagull-agent-v2/internal/protocol"
	"github.com/dynasmon/Seagull-agent-v2/internal/spool"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	ingestv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/ingest/v1"
)

const recordedArchitecture = "amd64"

var batchIdentifier = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// What the native gate recorded of the sshd of an Ubuntu 24.04 host: a burst of
// passwords guessed for an account that does not exist, from an address outside
// the private ranges, then a wrong and a right password for an account that
// does. The entries are what journald held, as the agent's adapter read them,
// and the batches are what the installed agent delivered of them, byte for byte.
type collectedScenario struct {
	RecordedAt     time.Time         `json:"recorded_at"`
	Began          time.Time         `json:"began"`
	Build          string            `json:"build"`
	InstallationID string            `json:"installation_id"`
	AgentID        string            `json:"agent_id"`
	Host           map[string]string `json:"host"`
	Outside        string            `json:"outside"`
	Account        string            `json:"account"`
	Guesses        int               `json:"guesses"`
	Batches        int               `json:"batches"`
	Journal        []journal.Entry   `json:"journal"`
}

type delivered struct {
	name    string
	batch   *ingestv1.EventBatch
	records [][]byte
}

func scenario(t *testing.T) (collectedScenario, []delivered) {
	t.Helper()
	directory := filepath.Join("testdata", "authentication")
	encoded, err := os.ReadFile(filepath.Join(directory, "scenario.json"))
	if err != nil {
		t.Fatalf("read the collected scenario: %v", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var held collectedScenario
	if err := decoder.Decode(&held); err != nil {
		t.Fatalf("decode the collected scenario: %v", err)
	}
	if held.InstallationID == "" || held.Build == "" || held.RecordedAt.IsZero() || held.Host["openssh"] == "" || len(held.Journal) == 0 {
		t.Fatalf("the collected scenario does not say what recorded it, where and when: %+v", held)
	}
	var batches []delivered
	for i := range held.Batches {
		name := fmt.Sprintf("batch-%03d.pb", i)
		body, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		batch := &ingestv1.EventBatch{}
		if err := proto.Unmarshal(body, batch); err != nil {
			t.Fatalf("%s is not an event batch: %v", name, err)
		}
		if batch.GetProtocolVersion() != protocol.Version || !batchIdentifier.MatchString(batch.GetBatchId()) {
			t.Fatalf("%s was sent as batch %q of protocol %d", name, batch.GetBatchId(), batch.GetProtocolVersion())
		}
		batches = append(batches, delivered{name: name, batch: batch, records: protocol.Events.Records(body)})
	}
	return held, batches
}

// The events the installed agent delivered are the ones the collector of this
// build makes of what sshd wrote: read again, the entries journald held become
// the same events, byte for byte, in the order they were delivered.
func TestTheCollectorMakesOfWhatSshdWroteTheEventsTheAgentDelivered(t *testing.T) {
	held, batches := scenario(t)
	var sent [][]byte
	for _, batch := range batches {
		sent = append(sent, batch.records...)
	}
	if len(sent) != held.Guesses+2 {
		t.Fatalf("the agent delivered %d events of %d outcomes", len(sent), held.Guesses+2)
	}
	made := collect(t, held, len(sent))
	if len(made) != len(sent) {
		t.Fatalf("the collector made %d events of the entries the agent delivered %d of", len(made), len(sent))
	}
	for i := range sent {
		if runtime.GOARCH == recordedArchitecture {
			if !bytes.Equal(made[i], sent[i]) {
				t.Errorf("event %d was delivered as\n%x\nand the collector makes\n%x", i, sent[i], made[i])
			}
			continue
		}
		recorded, again := decoded(t, sent[i]), decoded(t, made[i])
		again.GetOrigin().GetHost().Architecture = recorded.GetOrigin().GetHost().GetArchitecture()
		if !proto.Equal(recorded, again) {
			t.Errorf("event %d was delivered as %v and the collector makes %v", i, recorded, again)
		}
	}
	outcomes := map[string]int{}
	for _, record := range sent {
		event := decoded(t, record)
		body := event.GetAuthentication()
		if body.GetNetwork().GetSource().GetIp() != held.Outside || body.GetService().GetProtocol() != "ssh" {
			t.Errorf("an event was delivered as %v", event)
		}
		outcomes[fmt.Sprintf("%s %s", body.GetUser().GetName(), body.GetOutcome())]++
	}
	if outcomes["admin OUTCOME_FAILURE"] != held.Guesses || outcomes[held.Account+" OUTCOME_FAILURE"] != 1 || outcomes[held.Account+" OUTCOME_SUCCESS"] != 1 {
		t.Errorf("the agent delivered %v", outcomes)
	}
}

func decoded(t *testing.T, record []byte) *eventv1.Event {
	t.Helper()
	event := &eventv1.Event{}
	if err := proto.Unmarshal(record, event); err != nil {
		t.Fatalf("a delivered record is not an event: %v", err)
	}
	return event
}

func collect(t *testing.T, held collectedScenario, want int) [][]byte {
	t.Helper()
	base := t.TempDir()
	for _, name := range []string{"spool", "collection"} {
		if err := os.Mkdir(filepath.Join(base, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	place := fmt.Sprintf(`{"format":1,"since":%q}`, held.Began.Add(-time.Second).Format(time.RFC3339Nano))
	if err := os.WriteFile(filepath.Join(base, "collection", authentication.Name+".json"), []byte(place), 0o600); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.DiscardHandler)
	root, err := os.OpenRoot(filepath.Join(base, "spool"))
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	kept, err := spool.Open(root, spool.Limits{MaxBytes: 64 << 20}, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer kept.Close()
	directory, err := os.OpenRoot(filepath.Join(base, "collection"))
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	governed, err := governor.New(logger, held.InstallationID, governor.Budget{Scans: 1, ScanBytesPerSecond: 1 << 20, Uploads: 1, UploadBytesPerSecond: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	collector, err := authentication.New(authentication.Options{
		Installation: held.InstallationID,
		Spool:        kept,
		Governor:     governed,
		Directory:    directory,
		Logger:       logger,
		Open: func(ctx context.Context, _ journal.Position, follow bool) (authentication.Entries, error) {
			if follow {
				return &recordedEntries{ctx: ctx, follow: true}, nil
			}
			return &recordedEntries{ctx: ctx, entries: held.Journal}, nil
		},
		Now: func() time.Time { return held.RecordedAt },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- collector.Collect(ctx) }()
	deadline := time.Now().Add(10 * time.Second)
	var admitted []spool.Entry
	for len(admitted) < want && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
		if admitted, err = kept.Read(spool.Events, 1, 1<<16, 64<<20); err != nil {
			t.Fatal(err)
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("the collector stopped with %v", err)
	}
	made := make([][]byte, 0, len(admitted))
	for _, entry := range admitted {
		made = append(made, entry.Payload)
	}
	return made
}

type recordedEntries struct {
	ctx     context.Context
	entries []journal.Entry
	follow  bool
}

func (r *recordedEntries) Next() (journal.Entry, error) {
	if len(r.entries) == 0 {
		if !r.follow {
			return journal.Entry{}, io.EOF
		}
		<-r.ctx.Done()
		return journal.Entry{}, r.ctx.Err()
	}
	next := r.entries[0]
	r.entries = r.entries[1:]
	return next, nil
}

func (r *recordedEntries) Pending() bool { return len(r.entries) > 0 }

func (r *recordedEntries) Close() error { return nil }

// Each authentication.json under testdata measured what one platform commit
// keeps and decides of the batches the agent delivered of the scenario: each
// admitted by that commit's own admitter to a real broker, stored by its own
// event writer, decided by its own analysis engine against the rules it
// deploys, and stored again as detections by its own detection writer. Once
// for the batches as they were delivered, and once with all of them sent again.
type authenticationMeasurement struct {
	Platform struct {
		Repository     string    `json:"repository"`
		Commit         string    `json:"commit"`
		Contracts      string    `json:"contracts"`
		Broker         string    `json:"broker"`
		Store          string    `json:"store"`
		AdmissionClock time.Time `json:"admission_clock"`
		Rules          []string  `json:"rules"`
	} `json:"platform"`
	Agent struct {
		Build          string    `json:"build"`
		InstallationID string    `json:"installation_id"`
		AgentID        string    `json:"agent_id"`
		RecordedAt     time.Time `json:"recorded_at"`
	} `json:"agent"`
	Exchanges []struct {
		Phase    string `json:"phase"`
		Batch    string `json:"batch"`
		BatchID  string `json:"batch_id"`
		Events   int    `json:"events"`
		Accepted bool   `json:"accepted"`
		Durable  bool   `json:"durable"`
		Received int    `json:"received"`
		Refused  string `json:"refused"`
	} `json:"exchanges"`
	Alone    authenticationRun `json:"alone"`
	Replayed authenticationRun `json:"replayed"`
}

type authenticationRun struct {
	Backbone   int                              `json:"backbone_records"`
	Events     int                              `json:"stored_events"`
	Distinct   int                              `json:"distinct_events"`
	Detections map[string]authenticationOutcome `json:"detections"`
}

type authenticationOutcome struct {
	Published int        `json:"published"`
	Distinct  int        `json:"distinct"`
	Stored    int        `json:"stored"`
	Counts    []int      `json:"counts"`
	Stages    [][]string `json:"stages"`
}

// The scenario reaches a recorded platform's broker durably, is stored once,
// and is decided by the rules that platform deploys as the scenario reads: a
// failure from outside the estate for each wrong password, a count once twenty
// of them fall in a minute, and the guess that succeeded. Sent again, nothing
// the platform stores or decides grows.
func TestARecordedPlatformStoresAndDecidesWhatTheCollectorDeliveredOnce(t *testing.T) {
	held, batches := scenario(t)
	manifests, err := filepath.Glob(filepath.Join("testdata", "*", "authentication.json"))
	if err != nil || len(manifests) == 0 {
		t.Fatalf("no platform was measured keeping and deciding what the collector delivered: %v", err)
	}
	ids := map[string]string{}
	for _, batch := range batches {
		for _, record := range batch.records {
			event := decoded(t, record)
			ids[event.GetEventId()] = fmt.Sprintf("%s %s", event.GetAuthentication().GetUser().GetName(), event.GetAuthentication().GetOutcome())
		}
	}
	for _, manifest := range manifests {
		t.Run(filepath.Base(filepath.Dir(manifest)), func(t *testing.T) {
			encoded, err := os.ReadFile(manifest)
			if err != nil {
				t.Fatal(err)
			}
			decoder := json.NewDecoder(bytes.NewReader(encoded))
			decoder.DisallowUnknownFields()
			var measured authenticationMeasurement
			if err := decoder.Decode(&measured); err != nil {
				t.Fatalf("decode %s: %v", manifest, err)
			}
			if measured.Platform.Commit == "" || measured.Platform.Contracts == "" || measured.Agent.InstallationID != held.InstallationID || measured.Agent.Build != held.Build {
				t.Fatalf("%s measured %+v of %+v", manifest, measured.Platform, measured.Agent)
			}
			events := len(ids)
			for i, exchange := range measured.Exchanges {
				batch := batches[i%len(batches)]
				phase := []string{"original", "replayed"}[i/len(batches)]
				if exchange.Phase != phase || exchange.Batch != batch.name || exchange.BatchID != batch.batch.GetBatchId() || exchange.Events != len(batch.records) ||
					!exchange.Accepted || !exchange.Durable || exchange.Received != exchange.Events || exchange.Refused != "" {
					t.Errorf("the platform took %s, %s, as %+v", phase, batch.name, exchange)
				}
			}
			alone, again := measured.Alone, measured.Replayed
			if len(measured.Exchanges) != 2*len(batches) || alone.Backbone != events || again.Backbone != 2*events {
				t.Fatalf("the broker held %d records of %d events and %d once they were sent again", alone.Backbone, events, again.Backbone)
			}
			if alone.Events != events || alone.Distinct != events || again.Events != events || again.Distinct != events {
				t.Errorf("the platform stores %d events, %d distinct, and %d, %d distinct, once they were sent again", alone.Events, alone.Distinct, again.Events, again.Distinct)
			}
			for rule, once := range alone.Detections {
				twice := again.Detections[rule]
				if once.Stored != once.Distinct || twice.Stored != once.Stored || twice.Distinct != once.Distinct || !slices.Equal(twice.Counts, once.Counts) || fmt.Sprint(twice.Stages) != fmt.Sprint(once.Stages) {
					t.Errorf("%s decided %+v of the batches sent once and %+v of them sent again", rule, once, twice)
				}
			}
			outside := alone.Detections["ssh.failed_password_from_outside"]
			if outside.Distinct != held.Guesses+1 {
				t.Errorf("the platform found %d failures from outside the estate, and sshd decided %d", outside.Distinct, held.Guesses+1)
			}
			if counted := alone.Detections["ssh.repeated_failed_password"].Counts; len(counted) == 0 || counted[0] != 20 || counted[len(counted)-1] != held.Guesses+1 {
				t.Errorf("the platform counted %v failures from one address", counted)
			}
			story := alone.Detections["ssh.password_guessing_that_succeeded"].Stages
			if len(story) != 1 || len(story[0]) != 2 || ids[story[0][1]] != held.Account+" OUTCOME_SUCCESS" || !slices.Contains([]string{"admin OUTCOME_FAILURE", held.Account + " OUTCOME_FAILURE"}, ids[story[0][0]]) {
				t.Errorf("the platform told the guess that succeeded as %v", story)
			}
			if !slices.Equal(slices.Sorted(slices.Values(measured.Platform.Rules)), []string{"ssh.failed_password_from_outside", "ssh.password_guessing_that_succeeded", "ssh.repeated_failed_password"}) {
				t.Errorf("the platform ran the rules %v", measured.Platform.Rules)
			}
		})
	}
}
