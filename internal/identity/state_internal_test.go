package identity

import (
	"bytes"
	"encoding/json"
	"testing"
)

// Whatever the installation state holds, what reads as an installation is
// written back as bytes that read as the same one, and anything else is
// refused with a reason a message can carry.
func FuzzDecode(f *testing.F) {
	for _, seed := range []string{
		`{"format": 1, "installation_id": "5f0b6a1e-3c2d-4b8f-9a7e-1d2c3b4a5f6e", "created_at": "2026-09-16T17:00:00Z"}`,
		`{"format": 1, "installation_id": "5f0b6a1e-3c2d-4b8f-9a7e-1d2c3b4a5f6e", "created_at": "2026-09-16T19:00:00+02:00",
		  "replaces": "0d1c2b3a-4f5e-4a6b-8c7d-9e8f7a6b5c4d",
		  "enrollment": {"agent_id": "web-01", "generation": 2, "key_id": "3f5a0c1d2e4b6a7988796a5b4c3d2e1f0a1b2c3d4e5f60718293a4b5c6d7e8f9",
		    "key_drawn_at": "2026-09-25T12:00:00Z",
		    "certificate": {"subject": "web-01", "serial": "0a1b2c3d", "fingerprint_sha256": "b4c1d2e3f40516273849a5b6c7d8e9f00112233445566778899aabbccddeeff0",
		      "not_before": "2026-09-01T00:00:00Z", "not_after": "2026-11-30T00:00:00Z"}},
		  "request": {"agent_id": "web-01", "key_id": "9f8e7d6c5b4a39281706f5e4d3c2b1a0ffeeddccbbaa99887766554433221100", "requested_at": "2026-09-25T12:00:00Z"},
		  "trust": {"authorities_sha256": "9f8e7d6c5b4a39281706f5e4d3c2b1a0ffeeddccbbaa99887766554433221100",
		    "configured_sha256": "3f5a0c1d2e4b6a7988796a5b4c3d2e1f0a1b2c3d4e5f60718293a4b5c6d7e8f9", "adopted_at": "2026-09-26T08:00:00Z"}}`,
		`{"format": 2}`,
		`{"format": 1} {"format": 1}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, content []byte) {
		held, err := decode(content)
		if err != nil {
			if len(err.Error()) > 1<<10 {
				t.Fatalf("a refusal of %d bytes", len(err.Error()))
			}
			return
		}
		written, err := json.MarshalIndent(held, "", "  ")
		if err != nil {
			t.Fatalf("a state that was read cannot be written: %v", err)
		}
		again, err := decode(written)
		if err != nil {
			t.Fatalf("a state was written as %s, which does not read: %v", written, err)
		}
		if rewritten, err := json.MarshalIndent(again, "", "  "); err != nil || !bytes.Equal(rewritten, written) {
			t.Fatalf("a state was written as %s, and once read again as %s: %v", written, rewritten, err)
		}
	})
}
