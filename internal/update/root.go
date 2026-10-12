package update

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"fmt"
	"slices"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-agent-v2/internal/secrets"
	updatev1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/update/v1"
)

type Root struct {
	root   *updatev1.Root
	served []byte
	keys   map[string]*ecdsa.PublicKey
}

func (r *Root) Version() uint64 { return r.root.GetVersion() }

func (r *Root) ExpiresAt() time.Time { return r.root.GetExpiresAt().AsTime() }

func (r *Root) Expired(at time.Time) bool { return !at.Before(r.ExpiresAt()) }

func (r *Root) Served() []byte { return r.served }

// The root the agent was provisioned with is trusted for where it came from,
// and still held to its own root role, so a file that is not a root its own
// keys signed is refused rather than trusted. It may have run out: a root that
// ran out still leads to the next one.
func Anchor(served []byte, now time.Time) (*Root, error) {
	envelope, err := decode(served)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRoot, err)
	}
	if envelope.GetPayloadType() != RootPayloadType {
		return nil, fmt.Errorf("%w: its payload is declared as %s, and a root is %s", ErrRoot, secrets.Shown(envelope.GetPayloadType()), RootPayloadType)
	}
	root, keys, err := decodeRoot(envelope.GetPayload(), now)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRoot, err)
	}
	if _, err := signedBy(keys, root.GetRoot(), RootPayloadType, envelope); err != nil {
		return nil, fmt.Errorf("%w: its own root keys did not sign it: %v", ErrRoot, err)
	}
	kept, err := encode(envelope)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRoot, err)
	}
	return &Root{root: root, served: kept, keys: keys}, nil
}

func (r *Root) Next(envelope *updatev1.Envelope, now time.Time) (*Root, error) {
	if _, err := signedBy(r.keys, r.root.GetRoot(), RootPayloadType, envelope); err != nil {
		return nil, fmt.Errorf("the root keys of version %d did not sign it: %w", r.Version(), err)
	}
	root, keys, err := decodeRoot(envelope.GetPayload(), now)
	if err != nil {
		return nil, err
	}
	switch {
	case root.GetVersion() <= r.Version():
		return nil, fmt.Errorf("%w: it is root %d, and root %d is already trusted", ErrStale, root.GetVersion(), r.Version())
	case root.GetVersion() != r.Version()+1:
		return nil, fmt.Errorf("%w: it is root %d, and the root after version %d is version %d", ErrMalformed, root.GetVersion(), r.Version(), r.Version()+1)
	}
	if _, err := signedBy(keys, root.GetRoot(), RootPayloadType, envelope); err != nil {
		return nil, fmt.Errorf("its own root keys did not sign it: %w", err)
	}
	kept, err := encode(envelope)
	if err != nil {
		return nil, err
	}
	return &Root{root: root, served: kept, keys: keys}, nil
}

// Roots are handed oldest first. One the newest trusted root does not lead to,
// an older one included, is passed over and never trusted, so the walk ends at
// the newest root the chain vouches for, however much else it was handed.
func (r *Root) Walk(roots []*updatev1.Envelope, now time.Time) *Root {
	current := r
	for _, envelope := range roots {
		if next, err := current.Next(envelope, now); err == nil {
			current = next
		}
	}
	return current
}

func decodeRoot(payload []byte, now time.Time) (*updatev1.Root, map[string]*ecdsa.PublicKey, error) {
	var root updatev1.Root
	if err := proto.Unmarshal(payload, &root); err != nil {
		return nil, nil, fmt.Errorf("%w: its payload is not a root", ErrMalformed)
	}
	if err := known(root.ProtoReflect()); err != nil {
		return nil, nil, err
	}
	switch {
	case root.GetSchemaVersion() != SchemaVersion:
		return nil, nil, fmt.Errorf("%w: the root is written to schema %d, and this agent reads %d", ErrMalformed, root.GetSchemaVersion(), SchemaVersion)
	case root.GetVersion() == 0:
		return nil, nil, fmt.Errorf("%w: a root is counted from version 1", ErrMalformed)
	}
	if err := lifetime("the root", root.GetIssuedAt(), root.GetExpiresAt(), now); err != nil {
		return nil, nil, err
	}
	keys, err := publicKeys(root.GetKeys())
	if err != nil {
		return nil, nil, err
	}
	for name, held := range map[string]*updatev1.Role{"root": root.GetRoot(), "catalog": root.GetCatalog()} {
		if err := role(name, held, keys); err != nil {
			return nil, nil, err
		}
	}
	return &root, keys, nil
}

func publicKeys(named []*updatev1.Key) (map[string]*ecdsa.PublicKey, error) {
	if len(named) == 0 || len(named) > MaxKeys {
		return nil, fmt.Errorf("%w: a root names between 1 and %d keys, and this one names %d", ErrMalformed, MaxKeys, len(named))
	}
	keys := make(map[string]*ecdsa.PublicKey, len(named))
	for _, key := range named {
		id := key.GetKeyid()
		if id != KeyID(key.GetPublicKey()) {
			return nil, fmt.Errorf("%w: key %s is not the SHA-256 of the key it names", ErrMalformed, secrets.Shown(id))
		}
		if _, listed := keys[id]; listed {
			return nil, fmt.Errorf("%w: key %s is named twice", ErrMalformed, id)
		}
		parsed, err := x509.ParsePKIXPublicKey(key.GetPublicKey())
		if err != nil {
			return nil, fmt.Errorf("%w: key %s does not parse", ErrMalformed, id)
		}
		public, ecdsaKey := parsed.(*ecdsa.PublicKey)
		if !ecdsaKey || public.Curve != elliptic.P256() {
			return nil, fmt.Errorf("%w: key %s is not ECDSA over P-256", ErrMalformed, id)
		}
		keys[id] = public
	}
	return keys, nil
}

func role(name string, held *updatev1.Role, keys map[string]*ecdsa.PublicKey) error {
	ids := held.GetKeyids()
	switch {
	case held == nil:
		return fmt.Errorf("%w: the root names no %s role", ErrMalformed, name)
	case len(ids) == 0 || len(ids) > MaxRoleKeys:
		return fmt.Errorf("%w: the %s role names between 1 and %d keys, and this one names %d", ErrMalformed, name, MaxRoleKeys, len(ids))
	case held.GetThreshold() == 0 || held.GetThreshold() > uint32(len(ids)):
		return fmt.Errorf("%w: the %s role needs between 1 and %d signatures, and asks for %d", ErrMalformed, name, len(ids), held.GetThreshold())
	}
	for index, id := range ids {
		if _, found := keys[id]; !found {
			return fmt.Errorf("%w: the %s role names key %s, which the root does not hold", ErrMalformed, name, secrets.Shown(id))
		}
		if slices.Contains(ids[:index], id) {
			return fmt.Errorf("%w: the %s role names key %s twice", ErrMalformed, name, id)
		}
	}
	return nil
}

func lifetime(what string, issued, expires *timestamppb.Timestamp, now time.Time) error {
	switch {
	case issued == nil || !issued.IsValid():
		return fmt.Errorf("%w: %s does not say when it was issued", ErrMalformed, what)
	case expires == nil || !expires.IsValid():
		return fmt.Errorf("%w: %s does not say when it runs out", ErrMalformed, what)
	case issued.AsTime().After(now.Add(MaxAhead)):
		return fmt.Errorf("%w: %s was issued more than %s ahead of the agent's clock", ErrMalformed, what, MaxAhead)
	case !expires.AsTime().After(issued.AsTime()):
		return fmt.Errorf("%w: %s runs out before it was issued", ErrMalformed, what)
	case expires.AsTime().Sub(issued.AsTime()) > MaxLifetime:
		return fmt.Errorf("%w: %s is vouched for longer than %s", ErrMalformed, what, MaxLifetime)
	}
	return nil
}
