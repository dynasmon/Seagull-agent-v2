package compatibility_test

import (
	"bytes"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// Each downstream.json under testdata measured what one platform commit keeps
// and decides from a batch the agent sent again: the recorded original and
// replayed batches, admitted by that commit's own admitter to a real broker,
// stored by its own event writer, decided by its own analysis engine and
// stored again as detections by its own detection writer. Once for the
// original batch alone and once with the batch sent again.
type downstreamMeasurement struct {
	Platform   map[string]string `json:"platform"`
	RecordedAt time.Time         `json:"recorded_at"`
	Measured   string            `json:"measured"`
	Alone      downstreamRun     `json:"alone"`
	Replayed   downstreamRun     `json:"replayed"`
}

type downstreamRun struct {
	Batches []struct {
		Request  string `json:"request"`
		BatchID  string `json:"batch_id"`
		Accepted bool   `json:"accepted"`
		Durable  bool   `json:"durable"`
		Received int    `json:"received"`
	} `json:"batches"`
	Backbone   int                          `json:"backbone_records"`
	Events     int                          `json:"stored_events"`
	Detections map[string]downstreamOutcome `json:"detections"`
}

type downstreamOutcome struct {
	Published int   `json:"published"`
	Distinct  int   `json:"distinct"`
	Stored    int   `json:"stored"`
	Counts    []int `json:"counts"`
}

// A batch sent again reaches the broker whole, since the platform cannot know
// the agent already sent it. What the platform keeps and decides from it does
// not grow: the events it stores, the detections it stores and what a rule
// that counts decided are the same as for the batch sent once.
func TestABatchSentAgainChangesNothingARecordedPlatformKeepsOrDecides(t *testing.T) {
	manifests, err := filepath.Glob(filepath.Join("testdata", "*", "downstream.json"))
	if err != nil || len(manifests) == 0 {
		t.Fatalf("no platform was measured keeping and deciding a batch the agent sent again: %v", err)
	}
	for _, manifest := range manifests {
		t.Run(filepath.Base(filepath.Dir(manifest)), func(t *testing.T) {
			encoded, err := os.ReadFile(manifest)
			if err != nil {
				t.Fatalf("read %s: %v", manifest, err)
			}
			decoder := json.NewDecoder(bytes.NewReader(encoded))
			decoder.DisallowUnknownFields()
			var measured downstreamMeasurement
			if err := decoder.Decode(&measured); err != nil {
				t.Fatalf("decode %s: %v", manifest, err)
			}
			if measured.Platform["commit"] == "" || measured.RecordedAt.IsZero() || measured.Measured == "" {
				t.Fatalf("%s does not say what it measured and when", manifest)
			}
			sent := sentBatches(t)
			for _, run := range []downstreamRun{measured.Alone, measured.Replayed} {
				for _, batch := range run.Batches {
					if id, recorded := sent[batch.Request]; !recorded || id != batch.BatchID || !batch.Accepted || !batch.Durable || batch.Received == 0 {
						t.Fatalf("the measurement admitted %+v, which is not the recorded %s acknowledged as durable", batch, batch.Request)
					}
				}
			}
			alone, replayed := measured.Alone, measured.Replayed
			if len(alone.Batches) != 1 || len(replayed.Batches) != 2 || replayed.Batches[1].Request != "events-replayed" || replayed.Backbone != 2*alone.Backbone {
				t.Fatalf("the batch was sent again as %+v, and the broker held %d records after holding %d", replayed.Batches, replayed.Backbone, alone.Backbone)
			}
			if alone.Events != alone.Backbone || replayed.Events != alone.Events {
				t.Errorf("the platform stores %d events of a batch sent once and %d of it sent again", alone.Events, replayed.Events)
			}
			if rules := slices.Sorted(maps.Keys(alone.Detections)); len(rules) < 2 || !slices.Equal(rules, slices.Sorted(maps.Keys(replayed.Detections))) {
				t.Fatalf("the rules decided %v once and %v with the batch sent again", rules, slices.Sorted(maps.Keys(replayed.Detections)))
			}
			for rule, once := range alone.Detections {
				again := replayed.Detections[rule]
				if once.Stored == 0 || again.Stored != once.Stored || again.Distinct != once.Distinct || !slices.Equal(again.Counts, once.Counts) {
					t.Errorf("%s decided %+v from the batch sent once and %+v from it sent again", rule, once, again)
				}
			}
		})
	}
}

// The batch identifiers the recorded deliveries sent, by exchange.
func sentBatches(t *testing.T) map[string]string {
	t.Helper()
	sent := map[string]string{}
	for _, recorded := range deliveryRecordings(t) {
		for _, name := range []string{"events-original", "events-replayed"} {
			exchange := recorded.exchange(t, name)
			sent[name] = identifier(t, routeOf(t, exchange.Route), recorded.payload(t, name, "request"))
		}
	}
	if sent["events-original"] == sent["events-replayed"] {
		t.Fatal("the recorded batch sent again kept the identifier of the batch it repeats")
	}
	return sent
}
