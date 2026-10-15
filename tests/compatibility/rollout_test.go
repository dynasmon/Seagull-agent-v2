package compatibility_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
	updatev1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/update/v1"
)

// What a recorded platform made of two rollouts on the reports the installed
// agent sent while it was updated in the native gate: one to the release it
// installed, one to the release it went back from.
type rolloutRecording struct {
	Platform struct {
		Repository string `json:"repository"`
		Commit     string `json:"commit"`
		Contracts  string `json:"contracts"`
		Broker     string `json:"broker"`
		Store      string `json:"store"`
		Registry   string `json:"registry"`
	} `json:"platform"`
	RecordedAt time.Time `json:"recorded_at"`
	Agent      string    `json:"agent"`
	Agents     []string  `json:"agents"`
	Base       string    `json:"base"`
	Rollouts   []struct {
		Name      string `json:"name"`
		RolloutID string `json:"rollout_id"`
		Version   string `json:"version"`
		Waves     []struct {
			AgentIDs []string `json:"agent_ids"`
			Percent  uint32   `json:"percent"`
			Soak     string   `json:"soak"`
			Running  uint32   `json:"running"`
		} `json:"waves"`
		Failures uint32 `json:"failures"`
		Steps    []struct {
			After    string            `json:"after"`
			Sequence uint64            `json:"sequence"`
			State    string            `json:"state"`
			Wave     uint32            `json:"wave"`
			Reason   string            `json:"reason"`
			Reached  uint32            `json:"reached"`
			Running  uint32            `json:"running"`
			Failed   uint32            `json:"failed"`
			Pending  uint32            `json:"pending"`
			Offered  map[string]string `json:"offered"`
		} `json:"steps"`
	} `json:"rollouts"`
}

// An agent's place in a rollout, as the update contract states it: the first
// eight bytes of the SHA-256 of the rollout, a zero byte and the agent,
// big-endian, modulo 10,000.
func place(rolloutID, agentID string) uint32 {
	sum := sha256.Sum256([]byte(rolloutID + "\x00" + agentID))
	return uint32(binary.BigEndian.Uint64(sum[:8]) % 10000)
}

func TestARecordedPlatformMovesAgentsOnWhatTheInstalledAgentReportedAndPausesOnWhatItWentBackFrom(t *testing.T) {
	scenario, batches := updatesTold(t)
	reports := make(map[string]*agentv1.Status, len(batches))
	for index, batch := range batches {
		var held agentv1.StatusBatch
		if err := proto.Unmarshal(batch, &held); err != nil || len(held.GetReports()) != 1 {
			t.Fatalf("report %d is not one batch of one report: %v", index, err)
		}
		reports[scenario.Reports[index].Batch] = held.GetReports()[0]
	}
	manifests, err := filepath.Glob(filepath.Join("testdata", "*", "rollout.json"))
	if err != nil || len(manifests) == 0 {
		t.Fatalf("no platform was recorded rolling a release out on what the agent reported: %v", err)
	}
	for _, manifest := range manifests {
		t.Run(filepath.Base(filepath.Dir(manifest)), func(t *testing.T) {
			var recorded rolloutRecording
			content, err := os.ReadFile(manifest)
			if err == nil {
				decoder := json.NewDecoder(bytes.NewReader(content))
				decoder.DisallowUnknownFields()
				err = decoder.Decode(&recorded)
			}
			if err != nil || recorded.Agent != scenario.AgentID || len(recorded.Rollouts) != 2 || !slices.Contains(recorded.Agents, recorded.Agent) {
				t.Fatalf("read %s: %v", manifest, err)
			}
			if first := reports[scenario.Reports[0].Batch]; first.GetBuild().GetVersion() != recorded.Base {
				t.Errorf("the platform took the agent to run %s, and it reported %s", recorded.Base, first.GetBuild().GetVersion())
			}
			var sent []string
			for _, rollout := range recorded.Rollouts {
				for _, step := range rollout.Steps {
					sent = append(sent, step.After)
					report := reports[step.After]
					if report == nil || report.GetSequence() != step.Sequence || report.GetUpdate().GetVersion() != rollout.Version {
						t.Fatalf("%s: a step follows %s, which is not a report the agent sent of its update to %s", rollout.Name, step.After, rollout.Version)
					}
				}
			}
			var told []string
			for _, report := range scenario.Reports {
				told = append(told, report.Batch)
			}
			if !slices.Equal(sent, told) {
				t.Fatalf("the platform read %v of what the agent reported, and the agent reported %v", sent, told)
			}

			forward, broken := recorded.Rollouts[0], recorded.Rollouts[1]
			canary := func(step int, offered map[string]string, version string) {
				t.Helper()
				for _, id := range recorded.Agents {
					if want := map[bool]string{true: version, false: ""}[id == recorded.Agent]; offered[id] != want {
						t.Errorf("%s step %d: %s is asked to run %q", version, step, id, offered[id])
					}
				}
			}
			ran := false
			for index, step := range forward.Steps {
				if reports[step.After].GetBuild().GetVersion() != forward.Version {
					if ran || step.State != updatev1.RolloutRecord_STATE_ACTIVE.String() || step.Wave != 0 {
						t.Errorf("before the canary ran %s the rollout stood %s at wave %d", forward.Version, step.State, step.Wave)
					}
					canary(index, step.Offered, forward.Version)
					continue
				}
				ran = true
				if step.Wave != 1 || step.Running != 1 || step.State != updatev1.RolloutRecord_STATE_ACTIVE.String() || forward.Waves[1].Percent != 50 {
					t.Fatalf("once the canary ran %s the rollout stood %s at wave %d with %d running", forward.Version, step.State, step.Wave, step.Running)
				}
				for _, id := range recorded.Agents {
					want := ""
					if id == recorded.Agent || place(forward.RolloutID, id) < 50*100 {
						want = forward.Version
					}
					if step.Offered[id] != want {
						t.Errorf("at place %d of rollout %s, %s is asked to run %q", place(forward.RolloutID, id), forward.RolloutID, id, step.Offered[id])
					}
				}
			}
			if !ran {
				t.Errorf("the platform never read that the canary ran %s", forward.Version)
			}

			paused := false
			for index, step := range broken.Steps {
				if update := reports[step.After].GetUpdate(); update.GetStage() == agentv1.Status_Update_STAGE_ROLLED_BACK {
					paused = true
					if step.State != updatev1.RolloutRecord_STATE_PAUSED.String() || step.Failed != 1 || step.Wave != 0 || step.Reason == "" {
						t.Errorf("once the canary went back from %s the rollout stood %s at wave %d with %d failed", broken.Version, step.State, step.Wave, step.Failed)
					}
					for id, version := range step.Offered {
						if version != "" {
							t.Errorf("with the rollout paused %s is asked to run %q", id, version)
						}
					}
					continue
				}
				if paused || step.State != updatev1.RolloutRecord_STATE_ACTIVE.String() {
					t.Errorf("before the canary went back from %s the rollout stood %s", broken.Version, step.State)
				}
				canary(index, step.Offered, broken.Version)
			}
			if !paused {
				t.Errorf("the platform never read that the canary went back from %s", broken.Version)
			}
		})
	}
}
