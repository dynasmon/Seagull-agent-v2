package policy_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-agent-v2/internal/dsse"
	"github.com/dynasmon/Seagull-agent-v2/internal/policy"
	policyv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/policy/v1"
)

var written = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

func signingKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("draw a signing key: %v", err)
	}
	return key
}

func verifier(t *testing.T, keys ...*ecdsa.PrivateKey) *policy.Verifier {
	t.Helper()
	public := make([]*ecdsa.PublicKey, 0, len(keys))
	for _, key := range keys {
		public = append(public, &key.PublicKey)
	}
	held, err := policy.NewVerifier(public)
	if err != nil {
		t.Fatalf("build a verifier: %v", err)
	}
	return held
}

func named(revision uint64, targets ...string) *policyv1.Policy {
	return &policyv1.Policy{
		SchemaVersion: policy.SchemaVersion,
		PolicyId:      "linux-web",
		Revision:      revision,
		Targets:       &policyv1.Targets{AgentIds: targets},
		IssuedAt:      timestamppb.New(written),
		ExpiresAt:     timestamppb.New(written.Add(30 * 24 * time.Hour)),
		Settings:      &policyv1.Settings{LogLevel: policyv1.LogLevel_LOG_LEVEL_WARN},
	}
}

func sealed(t *testing.T, payloadType string, payload []byte, keys ...*ecdsa.PrivateKey) []byte {
	t.Helper()
	digest := sha256.Sum256(dsse.PAE(payloadType, payload))
	envelope := &policyv1.SignedPolicy{Payload: payload, PayloadType: payloadType}
	for _, key := range keys {
		signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		id, err := policy.KeyID(&key.PublicKey)
		if err != nil {
			t.Fatalf("name the key: %v", err)
		}
		envelope.Signatures = append(envelope.Signatures, &policyv1.Signature{Sig: signature, Keyid: id})
	}
	served, err := proto.Marshal(envelope)
	if err != nil {
		t.Fatalf("encode the envelope: %v", err)
	}
	return served
}

func signed(t *testing.T, held *policyv1.Policy, keys ...*ecdsa.PrivateKey) []byte {
	t.Helper()
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(held)
	if err != nil {
		t.Fatalf("encode the policy: %v", err)
	}
	return sealed(t, policy.PayloadType, payload, keys...)
}

func TestAPolicyIsVerifiedUnderAKeyTheAgentAccepts(t *testing.T) {
	key := signingKey(t)
	served := signed(t, named(7, "web-01"), key)
	verified, err := verifier(t, key).Verify(served)
	if err != nil {
		t.Fatalf("a policy signed by an accepted key was refused: %v", err)
	}
	id, _ := policy.KeyID(&key.PublicKey)
	sum := sha256.Sum256(served)
	switch {
	case !proto.Equal(verified.Policy, named(7, "web-01")):
		t.Fatalf("the agent read %v out of what was signed", verified.Policy)
	case !slices.Equal(verified.SignedBy, []string{id}):
		t.Fatalf("the policy is said to be signed by %v", verified.SignedBy)
	case verified.Digest != hex.EncodeToString(sum[:]) || !slices.Equal(verified.Envelope, served):
		t.Fatalf("the envelope is held as %s", verified.Digest)
	}
}

func TestOnlyAnUnchangedPolicySignedByAnAcceptedKeyIsRead(t *testing.T) {
	key, stranger := signingKey(t), signingKey(t)
	accepted := verifier(t, key)
	payload, err := proto.Marshal(named(7, "web-01"))
	if err != nil {
		t.Fatal(err)
	}
	unsigned, err := proto.Marshal(&policyv1.SignedPolicy{Payload: payload, PayloadType: policy.PayloadType})
	if err != nil {
		t.Fatal(err)
	}
	changed := slices.Clone(payload)
	changed[len(changed)-1] ^= 0x01
	var claimed policyv1.SignedPolicy
	if err := proto.Unmarshal(sealed(t, policy.PayloadType, payload, stranger), &claimed); err != nil {
		t.Fatal(err)
	}
	claimed.Signatures[0].Keyid, _ = policy.KeyID(&key.PublicKey)
	claimedBytes, err := proto.Marshal(&claimed)
	if err != nil {
		t.Fatal(err)
	}
	var reused policyv1.SignedPolicy
	if err := proto.Unmarshal(sealed(t, policy.PayloadType, payload, key), &reused); err != nil {
		t.Fatal(err)
	}
	reused.Payload = changed
	reusedBytes, err := proto.Marshal(&reused)
	if err != nil {
		t.Fatal(err)
	}
	crowded := sealed(t, policy.PayloadType, payload, key, key, key, key, key)
	unknown := protowire.AppendVarint(protowire.AppendTag(slices.Clone(payload), 99, protowire.VarintType), 1)

	for name, refused := range map[string]struct {
		served []byte
		want   error
	}{
		"signed by a key the agent was not given":     {served: sealed(t, policy.PayloadType, payload, stranger), want: policy.ErrUnsigned},
		"a signature claiming an accepted key's id":   {served: claimedBytes, want: policy.ErrUnsigned},
		"a payload changed after it was signed":       {served: reusedBytes, want: policy.ErrUnsigned},
		"no signature":                                {served: unsigned, want: policy.ErrUnsigned},
		"a signature over another payload type":       {served: retyped(t, payload, key), want: policy.ErrUnsigned},
		"an envelope declaring another payload type":  {served: sealed(t, "application/json", payload, key), want: policy.ErrMalformed},
		"more signatures than a policy carries":       {served: crowded, want: policy.ErrMalformed},
		"a signed payload holding a setting it lacks": {served: sealed(t, policy.PayloadType, unknown, key), want: policy.ErrMalformed},
		"a signed payload that is not a policy":       {served: sealed(t, policy.PayloadType, []byte{0xff, 0xff}, key), want: policy.ErrMalformed},
		"something that is not an envelope":           {served: []byte{0xff, 0x01}, want: policy.ErrMalformed},
		"an envelope longer than a policy is":         {served: make([]byte, policy.MaxEnvelopeBytes+1), want: policy.ErrMalformed},
		"a payload longer than a policy is":           {served: sealed(t, policy.PayloadType, make([]byte, policy.MaxPayloadBytes+1), key), want: policy.ErrMalformed},
		"an envelope carrying no payload":             {served: sealed(t, policy.PayloadType, nil, key), want: policy.ErrMalformed},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := accepted.Verify(refused.served); !errors.Is(err, refused.want) {
				t.Fatalf("the envelope was answered %v, and %v was expected", err, refused.want)
			}
		})
	}
}

func retyped(t *testing.T, payload []byte, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	var envelope policyv1.SignedPolicy
	if err := proto.Unmarshal(sealed(t, "application/vnd.seagull.release.v1+protobuf", payload, key), &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.PayloadType = policy.PayloadType
	served, err := proto.Marshal(&envelope)
	if err != nil {
		t.Fatal(err)
	}
	return served
}

func TestOneAcceptedSignatureIsEnoughWhileASignerIsRotated(t *testing.T) {
	previous, next := signingKey(t), signingKey(t)
	served := signed(t, named(7, "web-01"), previous, next)
	for name, accepted := range map[string][]*ecdsa.PrivateKey{
		"the previous key": {previous},
		"the next key":     {next},
		"both":             {previous, next},
	} {
		t.Run(name, func(t *testing.T) {
			verified, err := verifier(t, accepted...).Verify(served)
			if err != nil || len(verified.SignedBy) != len(accepted) {
				t.Fatalf("an agent holding %s read the policy as signed by %v: %v", name, verified.SignedBy, err)
			}
		})
	}
}

func TestAVerifierHoldsP256KeysAndAtLeastOne(t *testing.T) {
	wider, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policy.NewVerifier(nil); err == nil {
		t.Fatal("a verifier was built with no key")
	}
	if _, err := policy.NewVerifier([]*ecdsa.PublicKey{&wider.PublicKey}); err == nil {
		t.Fatal("a verifier was built with a P-384 key")
	}
}
