package update_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-agent-v2/internal/protocol"
	"github.com/dynasmon/Seagull-agent-v2/internal/update"
	updatev1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/update/v1"
)

type provisioned struct {
	anchor *update.Root
	now    time.Time
}

// The roots recorded platforms were provisioned with, at the moment each was
// recorded, so the offers they served are judged as the agent judged them.
func recordedUpdates(f *testing.F) ([]provisioned, [][]byte) {
	f.Helper()
	manifests, err := filepath.Glob("../../tests/compatibility/testdata/backend-*/update.json")
	if err != nil || len(manifests) == 0 {
		f.Fatalf("find the recorded updates: %v", err)
	}
	var anchors []provisioned
	var offers [][]byte
	for _, manifest := range manifests {
		content, err := os.ReadFile(manifest)
		if err != nil {
			f.Fatal(err)
		}
		var recorded struct {
			RecordedAt time.Time `json:"recorded_at"`
			Root       string    `json:"root"`
		}
		if err := json.Unmarshal(content, &recorded); err != nil {
			f.Fatal(err)
		}
		served, err := os.ReadFile(filepath.Join(filepath.Dir(manifest), recorded.Root))
		if err != nil {
			f.Fatal(err)
		}
		anchor, err := update.Anchor(served, recorded.RecordedAt)
		if err != nil {
			f.Fatalf("anchor the root recorded in %s: %v", manifest, err)
		}
		anchors = append(anchors, provisioned{anchor: anchor, now: recorded.RecordedAt})
		offer, err := os.ReadFile(filepath.Join(filepath.Dir(manifest), "update-offered.reply.pb"))
		if err != nil {
			f.Fatal(err)
		}
		offers = append(offers, offer)
	}
	return anchors, offers
}

func FuzzVersion(f *testing.F) {
	for _, seed := range [][2]string{{"v0.2.0", "v0.3.0"}, {"v1.0.0-rc.1", "v1.0.0"}, {"v1.0.0-alpha.10", "v1.0.0-alpha.9"}, {"v0.1.0+build.7", "v0.1.0"},
		{"v1.999.0-gate", "v1.999.1-gate"}, {"v01.0.0", "v1.0.0-"}} {
		f.Add(seed[0], seed[1])
	}
	f.Fuzz(func(t *testing.T, left, right string) {
		first, firstRead := update.ParseVersion(left)
		second, secondRead := update.ParseVersion(right)
		if !firstRead || !secondRead {
			return
		}
		if first.String() != left || first.Compare(first) != 0 {
			t.Fatalf("%q reads as %q, which orders as %d against itself", left, first, first.Compare(first))
		}
		if order, reverse := first.Compare(second), second.Compare(first); order != -reverse || order < -1 || order > 1 {
			t.Fatalf("%q orders as %d against %q, which orders as %d against it", left, order, right, reverse)
		}
	})
}

// Whatever root the agent is provisioned with, it is trusted only when it
// reads back as itself once kept.
func FuzzAnchor(f *testing.F) {
	owner := newSigner(f)
	f.Add(encoded(f, sign(f, rootOf(1, []signer{owner}, 1, []signer{owner}, 1), update.RootPayloadType, owner)))
	f.Add(encoded(f, sign(f, rootOf(1, []signer{owner}, 1, []signer{owner}, 1), update.CatalogPayloadType, owner)))
	roots, err := filepath.Glob("../../tests/compatibility/testdata/backend-*/update-root.pb")
	if err != nil {
		f.Fatal(err)
	}
	for _, root := range roots {
		served, err := os.ReadFile(root)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(served)
	}
	f.Fuzz(func(t *testing.T, served []byte) {
		anchor, err := update.Anchor(served, written)
		if err != nil {
			if !errors.Is(err, update.ErrRoot) {
				t.Fatalf("a refusal that names no reason: %v", err)
			}
			return
		}
		again, err := update.Anchor(anchor.Served(), written)
		if err != nil || again.Version() != anchor.Version() || !bytes.Equal(again.Served(), anchor.Served()) || !again.ExpiresAt().Equal(anchor.ExpiresAt()) {
			t.Fatalf("root %d does not read back as itself once kept: %v", anchor.Version(), err)
		}
	})
}

// Whatever the platform offers, or the agent's account stages, a release is
// installed only when a catalog the trusted roots vouch for names it for this
// agent, and the agent never goes back to a root older than the one it holds.
func FuzzJudge(f *testing.F) {
	land := newEstate(f)
	estates := []provisioned{{anchor: land.anchor, now: written}}
	recorded, offers := recordedUpdates(f)
	estates = append(estates, recorded...)
	for _, offer := range offers {
		f.Add(offer)
	}
	for _, offer := range []*updatev1.Offer{
		land.offer(f, "v0.3.0", catalogOf(7, releaseOf("v0.2.0", 2), releaseOf("v0.3.0", 3))),
		land.offer(f, "v0.1.0", catalogOf(7, releaseOf("v0.2.0", 2), releaseOf("v0.1.0", 1))),
		land.offer(f, "", catalogOf(7, releaseOf("v0.2.0", 2))),
		land.offer(f, "v0.3.0", nil),
	} {
		content, err := proto.Marshal(offer)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(content)
	}
	f.Fuzz(func(t *testing.T, content []byte) {
		var offer updatev1.Offer
		if protocol.Decode(content, &offer, update.MaxOfferValues) != nil {
			return
		}
		ran := running("v0.2.0")
		for _, estate := range estates {
			judged, err := update.Judge(&offer, update.Held{Root: estate.anchor}, ran, estate.now)
			again, againErr := update.Judge(&offer, update.Held{Root: estate.anchor}, ran, estate.now)
			switch {
			case (err == nil) != (againErr == nil) || judged.Root.Version() != again.Root.Version() || !reflect.DeepEqual(judged.Target.GetVersion(), again.Target.GetVersion()):
				t.Fatalf("the same offer was judged twice in two ways: %v, %v", err, againErr)
			case judged.Root.Version() < estate.anchor.Version():
				t.Fatalf("judging an offer went back from root %d to root %d", estate.anchor.Version(), judged.Root.Version())
			case err != nil || judged.Target == nil:
				continue
			}
			target, platform := judged.Target, judged.Target.GetPlatform()
			if target.GetVersion() != offer.GetVersion() || platform.GetOs() != ran.OS || platform.GetArchitecture() != ran.Architecture ||
				platform.GetFormat() != ran.Format || judged.Current.GetVersion() != ran.Version.String() || judged.Catalog == nil {
				t.Fatalf("release %s for %v was judged installable by agent %s", target.GetVersion(), platform, ran.Version)
			}
			var envelope updatev1.Envelope
			if err := proto.Unmarshal(judged.Catalog.Served(), &envelope); err != nil {
				t.Fatal(err)
			}
			if catalog, err := judged.Root.Catalog(&envelope, estate.now); err != nil || catalog.Version() != judged.Catalog.Version() {
				t.Fatalf("the catalog that named release %s does not verify under root %d: %v", target.GetVersion(), judged.Root.Version(), err)
			}
		}
	})
}

func FuzzJournal(f *testing.F) {
	for _, journal := range []update.Journal{
		{Stage: update.Installing, Version: "v0.3.0", Previous: "v0.2.0", PreviousState: 1, Catalog: 7, Root: 2, Started: written, Since: written,
			Target: update.PackageName(bytes.Repeat([]byte{3}, 32)), Fallback: update.PackageName(bytes.Repeat([]byte{2}, 32))},
		{Stage: update.RolledBack, Version: "v0.3.0", Failure: update.Unhealthy, Reason: "it never said it ran", Started: written, Since: written.Add(time.Minute)},
	} {
		held := directory(f)
		if err := update.KeepJournal(held, journal); err != nil {
			f.Fatal(err)
		}
		content, err := os.ReadFile(filepath.Join(held.Name(), "journal.json"))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(content)
	}
	f.Add([]byte(`{"format":2}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, content []byte) {
		held := directory(t)
		if err := os.WriteFile(filepath.Join(held.Name(), "journal.json"), content, 0o644); err != nil {
			t.Fatal(err)
		}
		journal, found, err := update.ReadJournal(held)
		if err != nil {
			if !errors.Is(err, update.ErrDamaged) && !errors.Is(err, update.ErrNewer) {
				t.Fatalf("a refusal that names no reason: %v", err)
			}
			return
		}
		if !found {
			t.Fatal("a journal kept was not found")
		}
		if err := update.KeepJournal(held, journal); err != nil {
			t.Fatalf("a journal read back cannot be kept again: %v", err)
		}
		again, _, err := update.ReadJournal(held)
		if err != nil || !again.Started.Equal(journal.Started) || !again.Since.Equal(journal.Since) {
			t.Fatalf("journal %+v reads as %+v once kept again: %v", journal, again, err)
		}
		again.Started, again.Since, journal.Started, journal.Since, journal.Format = time.Time{}, time.Time{}, time.Time{}, time.Time{}, update.Format
		if again != journal {
			t.Fatalf("journal %+v reads as %+v once kept again", journal, again)
		}
		if _, err := os.Stat(filepath.Join(held.Name(), "pending")); (err == nil) == journal.Done() {
			t.Fatalf("a journal at %s is marked pending: %v", journal.Stage, err == nil)
		}
	})
}
