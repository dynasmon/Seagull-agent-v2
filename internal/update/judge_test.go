package update_test

import (
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-agent-v2/internal/update"
	updatev1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/update/v1"
)

type estate struct {
	owner  signer
	anchor *update.Root
}

func newEstate(t testing.TB) estate {
	t.Helper()
	owner := newSigner(t)
	return estate{owner: owner, anchor: anchored(t, rootOf(1, []signer{owner}, 1, []signer{owner}, 1), owner)}
}

func (e estate) offer(t testing.TB, version string, catalog *updatev1.Catalog) *updatev1.Offer {
	t.Helper()
	offer := &updatev1.Offer{Version: version, Roots: []*updatev1.Envelope{sign(t, rootOf(1, []signer{e.owner}, 1, []signer{e.owner}, 1), update.RootPayloadType, e.owner)}}
	if catalog != nil {
		offer.Catalog = sign(t, catalog, update.CatalogPayloadType, e.owner)
	}
	return offer
}

func running(version string) update.Running {
	parsed, _ := update.ParseVersion(version)
	return update.Running{Version: parsed, OS: "linux", Architecture: "amd64", Format: updatev1.Format_FORMAT_DEB, State: 1}
}

func TestAnAgentInstallsTheReleaseItIsAskedForAndKnowsWhatToGoBackTo(t *testing.T) {
	land := newEstate(t)
	judged, err := update.Judge(land.offer(t, "v0.3.0", catalogOf(7, releaseOf("v0.2.0", 2), releaseOf("v0.3.0", 3))),
		update.Held{Root: land.anchor}, running("v0.2.0"), written)
	switch {
	case err != nil:
		t.Fatalf("an upgrade the catalog allows was refused: %v", err)
	case judged.Target.GetVersion() != "v0.3.0" || judged.Current.GetVersion() != "v0.2.0":
		t.Fatalf("judged a move from %v to %v", judged.Current, judged.Target)
	case judged.Held().Catalog != 7 || judged.Held().Root.Version() != 1:
		t.Fatalf("held catalog %d under root %d", judged.Held().Catalog, judged.Held().Root.Version())
	}
}

func TestNothingIsAskedOfAnAgentAlreadyOnItsReleaseOrAskedForNone(t *testing.T) {
	land := newEstate(t)
	catalog := catalogOf(7, releaseOf("v0.2.0", 2))
	for name, offer := range map[string]*updatev1.Offer{
		"its own release":  land.offer(t, "v0.2.0", catalog),
		"no release":       land.offer(t, "", catalog),
		"nothing at all":   land.offer(t, "", nil),
		"no catalog to go": {Roots: land.offer(t, "", nil).GetRoots()},
	} {
		if judged, err := update.Judge(offer, update.Held{Root: land.anchor}, running("v0.2.0"), written); err != nil || judged.Target != nil {
			t.Errorf("%s asked the agent to install %v: %v", name, judged.Target, err)
		}
	}
}

func TestAnAgentRefusesAReleaseItMayNotInstall(t *testing.T) {
	land := newEstate(t)
	current := releaseOf("v0.2.0", 2)
	recovery := releaseOf("v0.1.9", 1)
	recovery.Replaces = []string{"v0.2.1"}
	gated := releaseOf("v0.4.0", 4)
	gated.Compatibility.MinimumVersion = "v0.3.0"
	newer := releaseOf("v0.3.0", 3)
	newer.Compatibility.StateGeneration = 1
	elsewhere := releaseOf("v0.5.0", 5)
	elsewhere.Platform.Architecture = "arm64"

	for name, asked := range map[string]struct {
		version string
		catalog *updatev1.Catalog
		running update.Running
	}{
		"an older release that does not replace it": {"v0.1.9", catalogOf(7, current, recovery), running("v0.2.0")},
		"a release over a minimum it is below":      {"v0.4.0", catalogOf(7, current, gated), running("v0.2.0")},
		"a release that cannot read its state":      {"v0.3.0", catalogOf(7, current, newer), func() update.Running { held := running("v0.2.0"); held.State = 2; return held }()},
		"a release for another platform":            {"v0.5.0", catalogOf(7, current, elsewhere), running("v0.2.0")},
		"a release the catalog does not name":       {"v0.6.0", catalogOf(7, current), running("v0.2.0")},
		"nothing to go back to":                     {"v0.3.0", catalogOf(7, newer), running("v0.2.0")},
	} {
		t.Run(name, func(t *testing.T) {
			judged, err := update.Judge(land.offer(t, asked.version, asked.catalog), update.Held{Root: land.anchor}, asked.running, written)
			if !errors.Is(err, update.ErrRefused) || judged.Target != nil {
				t.Fatalf("judged %v: %v", judged.Target, err)
			}
			if judged.Held().Catalog != 7 {
				t.Errorf("a refused release kept catalog %d rather than the one verified", judged.Held().Catalog)
			}
		})
	}
}

func TestAnAgentGoesBackOnlyFromAReleaseTheOlderOneNamesItReplaces(t *testing.T) {
	land := newEstate(t)
	recovery := releaseOf("v0.1.9", 1)
	recovery.Replaces = []string{"v0.2.0"}
	judged, err := update.Judge(land.offer(t, "v0.1.9", catalogOf(8, releaseOf("v0.2.0", 2), recovery)), update.Held{Root: land.anchor}, running("v0.2.0"), written)
	if err != nil || judged.Target.GetVersion() != "v0.1.9" {
		t.Fatalf("a recovery naming the running release was refused: %v", err)
	}
}

func TestMetadataThatRanOutOrGoesBackwardsAuthorizesNothing(t *testing.T) {
	land := newEstate(t)
	catalog := catalogOf(7, releaseOf("v0.2.0", 2), releaseOf("v0.3.0", 3))

	if _, err := update.Judge(land.offer(t, "v0.3.0", catalog), update.Held{Root: land.anchor, Catalog: 8}, running("v0.2.0"), written); !errors.Is(err, update.ErrStale) {
		t.Fatalf("a catalog older than the one verified before was taken: %v", err)
	}
	if _, err := update.Judge(land.offer(t, "v0.3.0", catalog), update.Held{Root: land.anchor}, running("v0.2.0"), written.Add(91*24*time.Hour)); !errors.Is(err, update.ErrExpired) {
		t.Fatalf("a catalog that ran out was taken: %v", err)
	}
	if _, err := update.Judge(land.offer(t, "v0.3.0", catalog), update.Held{Root: land.anchor}, running("v0.2.0"), written.Add(181*24*time.Hour)); !errors.Is(err, update.ErrExpired) {
		t.Fatalf("a catalog under a root that ran out was taken: %v", err)
	}
	stranger := newSigner(t)
	forged := land.offer(t, "v0.3.0", nil)
	forged.Catalog = sign(t, catalog, update.CatalogPayloadType, stranger)
	if _, err := update.Judge(forged, update.Held{Root: land.anchor}, running("v0.2.0"), written); !errors.Is(err, update.ErrUnsigned) {
		t.Fatalf("a catalog no role signed was taken: %v", err)
	}
	if _, err := update.Judge(land.offer(t, "v0.3.0", nil), update.Held{Root: land.anchor}, running("v0.2.0"), written); !errors.Is(err, update.ErrMalformed) {
		t.Fatalf("a release asked for with no catalog was taken: %v", err)
	}
	ahead := catalogOf(7, releaseOf("v0.3.0", 3))
	ahead.IssuedAt = timestamppb.New(written.Add(time.Hour))
	if _, err := update.Judge(land.offer(t, "v0.3.0", ahead), update.Held{Root: land.anchor}, running("v0.2.0"), written); !errors.Is(err, update.ErrMalformed) {
		t.Fatalf("a catalog issued ahead of the clock was taken: %v", err)
	}
}
