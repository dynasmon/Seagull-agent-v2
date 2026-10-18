package status

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// Whatever the status file holds, what reads as a snapshot is written back as
// bytes that read as the same one, and anything else is refused as damaged or
// newer: the installer judges a release by what it reads here.
func FuzzDecode(f *testing.F) {
	snapshot := Snapshot{Format: Format, WrittenAt: time.Date(2026, time.October, 17, 12, 0, 0, 0, time.UTC), EverySeconds: 30, State: Degraded, Reason: "the platform could not be reached",
		Agent:      Agent{Build: "seagull-agent v0.1.0-rc.1 go1.26.9 linux/amd64", Process: 4242, StartedAt: time.Date(2026, time.October, 17, 11, 0, 0, 0, time.UTC), AgentID: "web-01"},
		Components: []Component{{Name: "delivery", State: Degraded, Reason: "the platform could not be reached", Recovery: "check the network"}}}
	written, err := json.Marshal(snapshot)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(written)
	f.Add([]byte(`{"format": 2}`))
	f.Add([]byte(`{"format": 1, "written_at": "2026-10-17T12:00:00Z", "state": "running", "mood": "fine"}`))
	f.Fuzz(func(t *testing.T, content []byte) {
		held, err := decode(content)
		if err != nil {
			if !errors.Is(err, ErrDamaged) && !errors.Is(err, ErrNewer) {
				t.Fatalf("a refusal that names no reason: %v", err)
			}
			return
		}
		written, err := json.Marshal(held)
		if err != nil {
			t.Fatalf("a snapshot that was read cannot be written: %v", err)
		}
		again, err := decode(written)
		if err != nil {
			t.Fatalf("a snapshot was written as %s, which does not read: %v", written, err)
		}
		if rewritten, err := json.Marshal(again); err != nil || !bytes.Equal(rewritten, written) {
			t.Fatalf("a snapshot was written as %s, and once read again as %s: %v", written, rewritten, err)
		}
	})
}
