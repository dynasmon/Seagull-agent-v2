package compatibility_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Each chaos.json under testdata counted what one platform commit kept of what
// the installed agent delivered to its own ingest gateway, backbone and event
// store while the agent's native test killed the agent over and over and the
// recorder stopped the backbone for a while, by the identifier of the event of
// every outcome the test had sshd decide: how often the backbone holds it and
// how often the store keeps it.
type chaosMeasurement struct {
	Platform   map[string]string `json:"platform"`
	RecordedAt time.Time         `json:"recorded_at"`
	Agent      struct {
		Build          string             `json:"build"`
		InstallationID string             `json:"installation_id"`
		AgentID        string             `json:"agent_id"`
		Kills          int                `json:"kills"`
		Spool          map[string]float64 `json:"spool"`
	} `json:"agent"`
	Backbone struct {
		StoppedAt time.Time `json:"stopped_at"`
		StartedAt time.Time `json:"started_at"`
	} `json:"backbone"`
	Published int `json:"published"`
	Stored    struct {
		Rows     int `json:"rows"`
		Unmerged int `json:"unmerged"`
	} `json:"stored"`
	Events []struct {
		User      string `json:"user"`
		EventID   string `json:"event_id"`
		Published int    `json:"published"`
		Stored    int    `json:"stored"`
	} `json:"events"`
}

// Killed while it delivered and held back by a backbone that stopped, the
// agent sent some batches again, and part of a batch may have reached the
// backbone before the gateway refused it: the backbone holds some events more
// than once. The store keeps each outcome sshd decided as one event, and the
// agent's spool settled every one of them as delivered and nothing otherwise.
func TestARecordedPlatformKeepsOnceEveryEventTheAgentDeliveredThroughFailures(t *testing.T) {
	manifests, err := filepath.Glob(filepath.Join("testdata", "*", "chaos.json"))
	if err != nil || len(manifests) == 0 {
		t.Fatalf("no platform was measured keeping what the agent delivered through failures: %v", err)
	}
	for _, manifest := range manifests {
		t.Run(filepath.Base(filepath.Dir(manifest)), func(t *testing.T) {
			encoded, err := os.ReadFile(manifest)
			if err != nil {
				t.Fatalf("read %s: %v", manifest, err)
			}
			decoder := json.NewDecoder(bytes.NewReader(encoded))
			decoder.DisallowUnknownFields()
			var measured chaosMeasurement
			if err := decoder.Decode(&measured); err != nil {
				t.Fatalf("decode %s: %v", manifest, err)
			}
			if measured.Platform["commit"] == "" || measured.Platform["contracts"] == "" || measured.RecordedAt.IsZero() ||
				!strings.HasPrefix(measured.Agent.Build, "seagull-agent v") || measured.Agent.InstallationID == "" {
				t.Fatalf("%s does not say which platform and agent it measured and when", manifest)
			}
			if measured.Agent.Kills == 0 || measured.Backbone.StartedAt.Sub(measured.Backbone.StoppedAt) < 15*time.Second {
				t.Fatalf("the agent was killed %d times and the backbone stopped from %s to %s", measured.Agent.Kills,
					measured.Backbone.StoppedAt, measured.Backbone.StartedAt)
			}
			ids, users, published := map[string]string{}, map[string]bool{}, 0
			for _, kept := range measured.Events {
				switch {
				case users[kept.User]:
					t.Errorf("the platform holds more than one event for the one outcome of %s", kept.User)
				case kept.EventID == "" || kept.Published == 0:
					t.Errorf("the backbone holds no event of %s", kept.User)
				case kept.Stored != 1:
					t.Errorf("the store keeps the event %s of %s %d times", kept.EventID, kept.User, kept.Stored)
				case ids[kept.EventID] != "":
					t.Errorf("the event %s names both %s and %s", kept.EventID, ids[kept.EventID], kept.User)
				}
				users[kept.User], ids[kept.EventID] = true, kept.User
				published += kept.Published
			}
			if published != measured.Published || measured.Stored.Rows != len(users) || measured.Stored.Unmerged < measured.Stored.Rows {
				t.Errorf("the backbone holds %d records, %d of them events of the %d outcomes sshd decided, and the store %d events (%d rows before merging)",
					measured.Published, published, len(users), measured.Stored.Rows, measured.Stored.Unmerged)
			}
			spool := measured.Agent.Spool
			if spool["outstanding"] != 0 || spool["lost"] != 0 || spool["expired"] != 0 || spool["quarantined"] != 0 || spool["delivered"] < float64(len(users)) {
				t.Errorf("the agent's spool settled %v for %d outcomes", spool, len(users))
			}
			t.Logf("%d outcomes, %d backbone records, %d stored events, %d kills", len(users), measured.Published, measured.Stored.Rows, measured.Agent.Kills)
		})
	}
}
