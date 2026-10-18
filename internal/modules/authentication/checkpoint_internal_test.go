package authentication

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

// Whatever the place the collector kept holds, what reads as a place in the
// journal is written back as bytes that read as the same place, and anything
// else is refused as damaged or newer, so the collector reads again from a
// moment rather than from somewhere no entry is.
func FuzzDecode(f *testing.F) {
	for _, seed := range []string{
		`{"format":1,"cursor":"s=6b3f0c1d2e4a4b8f9a7e1d2c3b4a5f6e;i=1a2b;b=0f1e2d3c4b5a69788796a5b4c3d2e1f0;m=3c4d5e;t=6129a8b7c6d5e;x=7f8e9dacbbecfd0e","read":"2026-10-01T12:00:00Z"}`,
		`{"format":1,"since":"2026-10-01T12:00:00Z"}`,
		`{"format":1}`,
		`{"format":2,"since":"2026-10-01T12:00:00Z"}`,
		`{"format":1,"cursor":"x","read":"2026-10-01T12:00:00Z"}`,
	} {
		f.Add([]byte(seed))
	}
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
			t.Fatal(err)
		}
		again, err := decode(written)
		if err != nil {
			t.Fatalf("a place was written as %s, which does not read: %v", written, err)
		}
		if rewritten, err := json.Marshal(again); err != nil || !bytes.Equal(rewritten, written) {
			t.Fatalf("a place was written as %s, and once read again as %s: %v", written, rewritten, err)
		}
	})
}
