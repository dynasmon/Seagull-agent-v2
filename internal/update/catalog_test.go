package update_test

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-agent-v2/internal/update"
	updatev1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/update/v1"
)

func releaseOf(version string, content byte) *updatev1.Release {
	return &updatev1.Release{
		Version:       version,
		Platform:      &updatev1.Platform{Os: "linux", Architecture: "amd64", Format: updatev1.Format_FORMAT_DEB},
		Payload:       &updatev1.Payload{Sha256: bytes.Repeat([]byte{content}, 32), Size: 1 << 20},
		Source:        &updatev1.Source{Repository: "github.com/dynasmon/Seagull-agent-v2", Revision: strings.Repeat("ab", 20)},
		Compatibility: &updatev1.Compatibility{StateGeneration: 1},
	}
}

func catalogOf(version uint64, releases ...*updatev1.Release) *updatev1.Catalog {
	return &updatev1.Catalog{
		SchemaVersion: update.SchemaVersion,
		Version:       version,
		IssuedAt:      timestamppb.New(written),
		ExpiresAt:     timestamppb.New(written.Add(90 * 24 * time.Hour)),
		Releases:      releases,
	}
}

func TestACatalogIsTakenOnlyUnderTheCatalogRoleOfTheRoot(t *testing.T) {
	owner, publisher := newSigner(t), newSigner(t)
	trusted := anchored(t, rootOf(1, []signer{owner}, 1, []signer{publisher}, 1), owner)
	catalog := catalogOf(4, releaseOf("v0.2.0", 1))

	taken, err := trusted.Catalog(sign(t, catalog, update.CatalogPayloadType, publisher), written)
	if err != nil || taken.Version() != 4 {
		t.Fatalf("a catalog the catalog role signed was refused: %v", err)
	}
	if _, err := trusted.Catalog(sign(t, catalog, update.CatalogPayloadType, owner), written); !errors.Is(err, update.ErrUnsigned) {
		t.Fatalf("a catalog a root key signed was taken: %v", err)
	}
	if _, err := trusted.Catalog(sign(t, catalog, update.RootPayloadType, publisher), written); !errors.Is(err, update.ErrMalformed) {
		t.Fatalf("a catalog signed as a root was taken: %v", err)
	}
}

func TestAKeyTheNextRootDropsSignsNoCatalogUnderIt(t *testing.T) {
	owner, revoked, replacement := newSigner(t), newSigner(t), newSigner(t)
	first := anchored(t, rootOf(1, []signer{owner}, 1, []signer{revoked}, 1), owner)
	second := first.Walk([]*updatev1.Envelope{sign(t, rootOf(2, []signer{owner}, 1, []signer{replacement}, 1), update.RootPayloadType, owner)}, written)
	signed := sign(t, catalogOf(4, releaseOf("v0.2.0", 1)), update.CatalogPayloadType, revoked)

	if _, err := first.Catalog(signed, written); err != nil {
		t.Fatalf("the catalog was refused under the root that trusted its key: %v", err)
	}
	if _, err := second.Catalog(signed, written); second.Version() != 2 || !errors.Is(err, update.ErrUnsigned) {
		t.Fatalf("a key root %d dropped still signed a catalog: %v", second.Version(), err)
	}
}

func TestACatalogMustStateEveryReleaseWithinItsBounds(t *testing.T) {
	owner := newSigner(t)
	trusted := anchored(t, rootOf(1, []signer{owner}, 1, []signer{owner}, 1), owner)
	for name, change := range map[string]func(*updatev1.Catalog){
		"another schema":               func(c *updatev1.Catalog) { c.SchemaVersion = 2 },
		"version zero":                 func(c *updatev1.Catalog) { c.Version = 0 },
		"no expiry":                    func(c *updatev1.Catalog) { c.ExpiresAt = nil },
		"one release twice":            func(c *updatev1.Catalog) { c.Releases = append(c.Releases, releaseOf("v0.2.0", 2)) },
		"a version without its v":      func(c *updatev1.Catalog) { c.Releases[0].Version = "0.2.0" },
		"an operating system Go lacks": func(c *updatev1.Catalog) { c.Releases[0].Platform.Os = "Linux" },
		"no format":                    func(c *updatev1.Catalog) { c.Releases[0].Platform.Format = updatev1.Format_FORMAT_UNSPECIFIED },
		"a digest that is no SHA-256":  func(c *updatev1.Catalog) { c.Releases[0].Payload.Sha256 = c.Releases[0].Payload.Sha256[:31] },
		"a package beyond the ceiling": func(c *updatev1.Catalog) { c.Releases[0].Payload.Size = update.MaxPackageBytes + 1 },
		"a revision in capitals":       func(c *updatev1.Catalog) { c.Releases[0].Source.Revision = strings.Repeat("AB", 20) },
		"no state generation":          func(c *updatev1.Catalog) { c.Releases[0].Compatibility.StateGeneration = 0 },
		"a minimum later than itself":  func(c *updatev1.Catalog) { c.Releases[0].Compatibility.MinimumVersion = "v0.3.0" },
		"replacing an earlier release": func(c *updatev1.Catalog) { c.Releases[0].Replaces = []string{"v0.1.0"} },
		"more releases than it names": func(c *updatev1.Catalog) {
			for index := range update.MaxReleases {
				c.Releases = append(c.Releases, releaseOf(fmt.Sprintf("v1.0.%d", index), 3))
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			catalog := catalogOf(1, releaseOf("v0.2.0", 1))
			change(catalog)
			if _, err := trusted.Catalog(sign(t, catalog, update.CatalogPayloadType, owner), written); !errors.Is(err, update.ErrMalformed) {
				t.Fatalf("taken: %v", err)
			}
		})
	}
}

func TestACatalogNamesAReleaseByItsVersionAndItsPlatform(t *testing.T) {
	owner := newSigner(t)
	trusted := anchored(t, rootOf(1, []signer{owner}, 1, []signer{owner}, 1), owner)
	arm := releaseOf("v0.2.0", 2)
	arm.Platform.Architecture = "arm64"
	catalog, err := trusted.Catalog(sign(t, catalogOf(1, releaseOf("v0.2.0", 1), arm), update.CatalogPayloadType, owner), written)
	if err != nil {
		t.Fatal(err)
	}
	if found := catalog.Release("v0.2.0", "linux", "arm64", updatev1.Format_FORMAT_DEB); found == nil || found.GetPayload().GetSha256()[0] != 2 {
		t.Fatalf("the arm64 package of v0.2.0 was found as %v", found)
	}
	for _, asked := range [][3]string{{"v0.3.0", "linux", "amd64"}, {"v0.2.0", "darwin", "amd64"}} {
		if found := catalog.Release(asked[0], asked[1], asked[2], updatev1.Format_FORMAT_DEB); found != nil {
			t.Errorf("%v was found as %v", asked, found)
		}
	}
}
