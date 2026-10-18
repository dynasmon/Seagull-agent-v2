package update_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-agent-v2/internal/dsse"
	"github.com/dynasmon/Seagull-agent-v2/internal/update"
	updatev1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/update/v1"
)

var written = time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)

type signer struct {
	key *ecdsa.PrivateKey
	id  string
	der []byte
}

func newSigner(t testing.TB) signer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate a signing key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("encode a public key: %v", err)
	}
	return signer{key: key, id: update.KeyID(der), der: der}
}

func rootOf(version uint64, rootKeys []signer, rootThreshold uint32, catalogKeys []signer, catalogThreshold uint32) *updatev1.Root {
	root := &updatev1.Root{
		SchemaVersion: update.SchemaVersion,
		Version:       version,
		IssuedAt:      timestamppb.New(written),
		ExpiresAt:     timestamppb.New(written.Add(180 * 24 * time.Hour)),
		Root:          &updatev1.Role{Threshold: rootThreshold},
		Catalog:       &updatev1.Role{Threshold: catalogThreshold},
	}
	held := map[string]bool{}
	for _, key := range append(append([]signer{}, rootKeys...), catalogKeys...) {
		if !held[key.id] {
			held[key.id] = true
			root.Keys = append(root.Keys, &updatev1.Key{Keyid: key.id, PublicKey: key.der})
		}
	}
	for _, key := range rootKeys {
		root.Root.Keyids = append(root.Root.Keyids, key.id)
	}
	for _, key := range catalogKeys {
		root.Catalog.Keyids = append(root.Catalog.Keyids, key.id)
	}
	return root
}

func sign(t testing.TB, message proto.Message, payloadType string, keys ...signer) *updatev1.Envelope {
	t.Helper()
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	digest := sha256.Sum256(dsse.PAE(payloadType, payload))
	envelope := &updatev1.Envelope{Payload: payload, PayloadType: payloadType}
	for _, key := range keys {
		signature, err := ecdsa.SignASN1(rand.Reader, key.key, digest[:])
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		envelope.Signatures = append(envelope.Signatures, &updatev1.Signature{Sig: signature, Keyid: key.id})
	}
	return envelope
}

func encoded(t testing.TB, envelope *updatev1.Envelope) []byte {
	t.Helper()
	served, err := proto.MarshalOptions{Deterministic: true}.Marshal(envelope)
	if err != nil {
		t.Fatalf("encode an envelope: %v", err)
	}
	return served
}

func anchored(t testing.TB, root *updatev1.Root, keys ...signer) *update.Root {
	t.Helper()
	trusted, err := update.Anchor(encoded(t, sign(t, root, update.RootPayloadType, keys...)), written)
	if err != nil {
		t.Fatalf("anchor root %d: %v", root.GetVersion(), err)
	}
	return trusted
}

func TestTheAgentTrustsTheRootItWasProvisionedWithOnlyWhenItsOwnRootKeysSignedIt(t *testing.T) {
	owner, stranger := newSigner(t), newSigner(t)
	root := rootOf(1, []signer{owner}, 1, []signer{owner}, 1)

	served := encoded(t, sign(t, root, update.RootPayloadType, owner))
	if trusted, err := update.Anchor(served, written); err != nil || trusted.Version() != 1 || !bytes.Equal(trusted.Served(), served) {
		t.Fatalf("the provisioned root was not trusted as it was given: %v", err)
	}
	for name, served := range map[string][]byte{
		"signed by a stranger": encoded(t, sign(t, root, update.RootPayloadType, stranger)),
		"signed as a catalog":  encoded(t, sign(t, root, update.CatalogPayloadType, owner)),
		"no envelope at all":   []byte("not an envelope"),
	} {
		if _, err := update.Anchor(served, written); !errors.Is(err, update.ErrRoot) {
			t.Errorf("a root %s was trusted: %v", name, err)
		}
	}
}

func TestARootMustStateItsKeysAndRolesWithinTheirBounds(t *testing.T) {
	owner, other := newSigner(t), newSigner(t)
	wide, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wideDER, err := x509.MarshalPKIXPublicKey(&wide.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*updatev1.Root){
		"another schema":                 func(r *updatev1.Root) { r.SchemaVersion = 2 },
		"version zero":                   func(r *updatev1.Root) { r.Version = 0 },
		"issued ahead of the clock":      func(r *updatev1.Root) { r.IssuedAt = timestamppb.New(written.Add(6 * time.Minute)) },
		"vouched for more than 366 days": func(r *updatev1.Root) { r.ExpiresAt = timestamppb.New(written.Add(367 * 24 * time.Hour)) },
		"no expiry":                      func(r *updatev1.Root) { r.ExpiresAt = nil },
		"a key id that is not its hash":  func(r *updatev1.Root) { r.Keys[0].Keyid = other.id },
		"a key named twice":              func(r *updatev1.Root) { r.Keys = append(r.Keys, r.Keys[0]) },
		"a key off P-256": func(r *updatev1.Root) {
			r.Keys = append(r.Keys, &updatev1.Key{Keyid: update.KeyID(wideDER), PublicKey: wideDER})
		},
		"no catalog role":              func(r *updatev1.Root) { r.Catalog = nil },
		"a role naming a key it lacks": func(r *updatev1.Root) { r.Catalog.Keyids = []string{other.id} },
		"a threshold of zero":          func(r *updatev1.Root) { r.Root.Threshold = 0 },
		"a threshold beyond its keys":  func(r *updatev1.Root) { r.Catalog.Threshold = 2 },
	} {
		t.Run(name, func(t *testing.T) {
			root := rootOf(1, []signer{owner}, 1, []signer{owner}, 1)
			change(root)
			if _, err := update.Anchor(encoded(t, sign(t, root, update.RootPayloadType, owner)), written); !errors.Is(err, update.ErrRoot) {
				t.Fatalf("taken: %v", err)
			}
		})
	}
}

func TestTheNextRootIsTrustedOnlyWhenTheThresholdsOfBothRootsSignedIt(t *testing.T) {
	before, after := newSigner(t), newSigner(t)
	trusted := anchored(t, rootOf(1, []signer{before}, 1, []signer{before}, 1), before)
	next := rootOf(2, []signer{after}, 1, []signer{after}, 1)

	if rotated, err := trusted.Next(sign(t, next, update.RootPayloadType, before, after), written); err != nil || rotated.Version() != 2 {
		t.Fatalf("a rotation both roots signed was refused: %v", err)
	}
	for name, signers := range map[string][]signer{"the old keys alone": {before}, "the new keys alone": {after}} {
		if _, err := trusted.Next(sign(t, next, update.RootPayloadType, signers...), written); !errors.Is(err, update.ErrUnsigned) {
			t.Errorf("a rotation signed by %s was trusted: %v", name, err)
		}
	}

	pair := []signer{before, after}
	strict := anchored(t, rootOf(1, pair, 2, pair, 1), pair...)
	twice := sign(t, rootOf(2, pair, 2, pair, 1), update.RootPayloadType, before)
	twice.Signatures = append(twice.Signatures, twice.GetSignatures()[0])
	if _, err := strict.Next(twice, written); !errors.Is(err, update.ErrUnsigned) {
		t.Fatalf("one key signing twice reached a threshold of two: %v", err)
	}
}

func TestAWalkEndsAtTheNewestRootTheChainVouchesForAndPassesOverTheRest(t *testing.T) {
	first, second, third, stranger := newSigner(t), newSigner(t), newSigner(t), newSigner(t)
	one := rootOf(1, []signer{first}, 1, []signer{first}, 1)
	two := rootOf(2, []signer{second}, 1, []signer{second}, 1)
	three := rootOf(3, []signer{third}, 1, []signer{third}, 1)
	chain := []*updatev1.Envelope{
		sign(t, one, update.RootPayloadType, first),
		sign(t, two, update.RootPayloadType, first, second),
		sign(t, three, update.RootPayloadType, second, third),
	}

	if newest := anchored(t, one, first).Walk(chain, written); newest.Version() != 3 {
		t.Fatalf("walking the whole chain from root 1 ended at root %d", newest.Version())
	}
	if newest := anchored(t, two, second).Walk(chain, written); newest.Version() != 3 {
		t.Fatalf("walking from root 2, past the older root, ended at root %d", newest.Version())
	}
	forged := sign(t, rootOf(2, []signer{stranger}, 1, []signer{stranger}, 1), update.RootPayloadType, stranger)
	if newest := anchored(t, one, first).Walk([]*updatev1.Envelope{forged, chain[2]}, written); newest.Version() != 1 {
		t.Fatalf("a root nobody trusted vouched for moved the walk to root %d", newest.Version())
	}
	if newest := anchored(t, one, first).Walk([]*updatev1.Envelope{chain[2]}, written); newest.Version() != 1 {
		t.Fatalf("a chain with a gap moved the walk to root %d", newest.Version())
	}
}

func TestARootThatRanOutStillLeadsToTheNext(t *testing.T) {
	old, current := newSigner(t), newSigner(t)
	expired := rootOf(1, []signer{old}, 1, []signer{old}, 1)
	expired.IssuedAt = timestamppb.New(written.Add(-400 * 24 * time.Hour))
	expired.ExpiresAt = timestamppb.New(written.Add(-40 * 24 * time.Hour))
	trusted := anchored(t, expired, old)
	if !trusted.Expired(written) {
		t.Fatal("a root that ran out reads as in force")
	}
	next, err := trusted.Next(sign(t, rootOf(2, []signer{current}, 1, []signer{current}, 1), update.RootPayloadType, old, current), written)
	if err != nil || next.Expired(written) {
		t.Fatalf("a root that ran out did not lead to the next in force: %v", err)
	}
}
