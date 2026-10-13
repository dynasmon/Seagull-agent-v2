package update

import (
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-agent-v2/internal/secrets"
	updatev1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/update/v1"
)

type Catalog struct {
	catalog *updatev1.Catalog
	served  []byte
}

func (c *Catalog) Version() uint64 { return c.catalog.GetVersion() }

func (c *Catalog) ExpiresAt() time.Time { return c.catalog.GetExpiresAt().AsTime() }

func (c *Catalog) Expired(at time.Time) bool { return !at.Before(c.ExpiresAt()) }

func (c *Catalog) Served() []byte { return c.served }

func (c *Catalog) Release(version, os, architecture string, format updatev1.Format) *updatev1.Release {
	for _, release := range c.catalog.GetReleases() {
		platform := release.GetPlatform()
		if release.GetVersion() == version && platform.GetOs() == os && platform.GetArchitecture() == architecture && platform.GetFormat() == format {
			cloned, _ := proto.Clone(release).(*updatev1.Release)
			return cloned
		}
	}
	return nil
}

// The catalog role of this root must have signed it before any of it is
// decoded.
func (r *Root) Catalog(envelope *updatev1.Envelope, now time.Time) (*Catalog, error) {
	if _, err := signedBy(r.keys, r.root.GetCatalog(), CatalogPayloadType, envelope); err != nil {
		return nil, fmt.Errorf("the catalog keys of root %d did not sign it: %w", r.Version(), err)
	}
	var catalog updatev1.Catalog
	if err := proto.Unmarshal(envelope.GetPayload(), &catalog); err != nil {
		return nil, fmt.Errorf("%w: its payload is not a catalog", ErrMalformed)
	}
	if err := known(catalog.ProtoReflect()); err != nil {
		return nil, err
	}
	if err := validateCatalog(&catalog, now); err != nil {
		return nil, err
	}
	kept, err := encode(envelope)
	if err != nil {
		return nil, err
	}
	return &Catalog{catalog: &catalog, served: kept}, nil
}

func validateCatalog(catalog *updatev1.Catalog, now time.Time) error {
	switch {
	case catalog.GetSchemaVersion() != SchemaVersion:
		return fmt.Errorf("%w: the catalog is written to schema %d, and this agent reads %d", ErrMalformed, catalog.GetSchemaVersion(), SchemaVersion)
	case catalog.GetVersion() == 0:
		return fmt.Errorf("%w: a catalog is counted from version 1", ErrMalformed)
	case len(catalog.GetReleases()) > MaxReleases:
		return fmt.Errorf("%w: a catalog names at most %d releases, and this one names %d", ErrMalformed, MaxReleases, len(catalog.GetReleases()))
	}
	if err := lifetime("the catalog", catalog.GetIssuedAt(), catalog.GetExpiresAt(), now); err != nil {
		return err
	}
	seen := make(map[string]bool, len(catalog.GetReleases()))
	for _, release := range catalog.GetReleases() {
		if err := validateRelease(release); err != nil {
			return err
		}
		platform := release.GetPlatform()
		named := release.GetVersion() + " for " + platform.GetOs() + "/" + platform.GetArchitecture() + " " + platform.GetFormat().String()
		if seen[named] {
			return fmt.Errorf("%w: the catalog names %s twice", ErrMalformed, named)
		}
		seen[named] = true
	}
	return nil
}

func validateRelease(release *updatev1.Release) error {
	version, valid := ParseVersion(release.GetVersion())
	if !valid {
		return fmt.Errorf("%w: release %s is not a semantic version with a leading v of at most %d bytes", ErrMalformed, secrets.Shown(release.GetVersion()), MaxVersionLength)
	}
	failed := func(reason string, arguments ...any) error {
		return fmt.Errorf("%w: release %s %s", ErrMalformed, version, fmt.Sprintf(reason, arguments...))
	}
	platform, payload, source := release.GetPlatform(), release.GetPayload(), release.GetSource()
	switch {
	case !platformName(platform.GetOs()) || !platformName(platform.GetArchitecture()):
		return failed("does not name an operating system and an architecture as Go names them")
	case platform.GetFormat() == updatev1.Format_FORMAT_UNSPECIFIED || updatev1.Format_name[int32(platform.GetFormat())] == "":
		return failed("is packaged in no format the contract declares")
	case len(payload.GetSha256()) != 32:
		return failed("does not carry the SHA-256 of its package")
	case payload.GetSize() == 0 || payload.GetSize() > MaxPackageBytes:
		return failed("says its package holds %d bytes, and a package holds between 1 and %d", payload.GetSize(), MaxPackageBytes)
	case source.GetRepository() == "" || len(source.GetRepository()) > MaxRepositoryLength:
		return failed("does not name the repository it was built from in at most %d bytes", MaxRepositoryLength)
	case !revision(source.GetRevision()):
		return failed("does not name the revision it was built from as 40 or 64 lowercase hex characters")
	case release.GetCompatibility().GetStateGeneration() == 0:
		return failed("does not say which generation of local state it keeps")
	case len(release.GetReplaces()) > MaxReplaced:
		return failed("replaces %d versions, and a release replaces at most %d", len(release.GetReplaces()), MaxReplaced)
	}
	if minimum := release.GetCompatibility().GetMinimumVersion(); minimum != "" {
		oldest, valid := ParseVersion(minimum)
		if !valid || oldest.Compare(version) > 0 {
			return failed("may only be installed over %s, which is no version up to itself", secrets.Shown(minimum))
		}
	}
	for index, named := range release.GetReplaces() {
		later, valid := ParseVersion(named)
		if !valid || later.Compare(version) <= 0 || slices.Contains(release.GetReplaces()[:index], named) {
			return failed("replaces %s, which is no other later version", secrets.Shown(named))
		}
	}
	return nil
}

func platformName(name string) bool {
	return name != "" && len(name) <= MaxPlatformLength && strings.TrimLeft(name, "abcdefghijklmnopqrstuvwxyz0123456789") == ""
}

func revision(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}
