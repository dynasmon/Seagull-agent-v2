// Package policy is what the agent makes of a policy the platform hands it: it
// verifies the signature under the keys the agent was provisioned with, judges
// whether the policy is one for this agent and newer than the one it holds,
// makes the configuration it would run on out of its own and the policy's
// settings, keeps the policy it applied across restarts, and asks the
// platform for the newest one. It holds no key that signs, and nothing the
// platform says decides whose signature counts.
package policy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/dynasmon/Seagull-agent-v2/internal/dsse"
	"github.com/dynasmon/Seagull-agent-v2/internal/secrets"
	policyv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/policy/v1"
)

const (
	Path             = "/v1/agents/policy"
	PayloadType      = "application/vnd.seagull.policy.v1+protobuf"
	SchemaVersion    = 1
	MaxPayloadBytes  = 1 << 20
	MaxEnvelopeBytes = MaxPayloadBytes + 4<<10
	MaxSignatures    = 4
)

var (
	ErrUnsigned     = errors.New("no signature on the policy was made by a key the agent accepts")
	ErrMalformed    = errors.New("the policy is not one the contract describes")
	ErrNotNamed     = errors.New("the policy does not name this agent")
	ErrOlder        = errors.New("the policy is older than the one the agent applied")
	ErrExpired      = errors.New("the policy has expired")
	ErrInapplicable = errors.New("the agent does not run on the configuration the policy would make")
)

type Verifier struct {
	keys []signer
}

type signer struct {
	id  string
	key *ecdsa.PublicKey
}

func NewVerifier(keys []*ecdsa.PublicKey) (*Verifier, error) {
	held := &Verifier{}
	for _, key := range keys {
		if key == nil || key.Curve != elliptic.P256() {
			return nil, errors.New("a policy is verified under ECDSA keys over P-256")
		}
		id, err := KeyID(key)
		if err != nil {
			return nil, err
		}
		held.keys = append(held.keys, signer{id: id, key: key})
	}
	if len(held.keys) == 0 {
		return nil, errors.New("a policy is verified under at least one key")
	}
	return held, nil
}

func KeyID(key *ecdsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", fmt.Errorf("name a signer: %w", err)
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}

type Verified struct {
	Policy   *policyv1.Policy
	Envelope []byte
	Digest   string
	SignedBy []string
}

// The signature is checked over the payload exactly as it arrived, and before
// any of it is decoded: a payload no accepted key signed is never parsed, and
// nothing has to be encoded again to be checked.
func (v *Verifier) Verify(served []byte) (Verified, error) {
	if len(served) > MaxEnvelopeBytes {
		return Verified{}, fmt.Errorf("%w: it is longer than %d bytes", ErrMalformed, MaxEnvelopeBytes)
	}
	var envelope policyv1.SignedPolicy
	if err := proto.Unmarshal(served, &envelope); err != nil {
		return Verified{}, fmt.Errorf("%w: it is not a signed policy", ErrMalformed)
	}
	payload, signatures := envelope.GetPayload(), envelope.GetSignatures()
	switch {
	case envelope.GetPayloadType() != PayloadType:
		return Verified{}, fmt.Errorf("%w: its payload is declared as %s, and a policy is %s",
			ErrMalformed, secrets.Shown(envelope.GetPayloadType()), PayloadType)
	case len(payload) == 0 || len(payload) > MaxPayloadBytes:
		return Verified{}, fmt.Errorf("%w: its payload holds %d bytes, and a policy holds between 1 and %d", ErrMalformed, len(payload), MaxPayloadBytes)
	case len(signatures) == 0:
		return Verified{}, ErrUnsigned
	case len(signatures) > MaxSignatures:
		return Verified{}, fmt.Errorf("%w: it carries %d signatures, and a policy carries at most %d", ErrMalformed, len(signatures), MaxSignatures)
	}

	digest := sha256.Sum256(dsse.PAE(PayloadType, payload))
	var signedBy []string
	for _, signature := range signatures {
		for _, candidate := range v.keys {
			if !slices.Contains(signedBy, candidate.id) && ecdsa.VerifyASN1(candidate.key, digest[:], signature.GetSig()) {
				signedBy = append(signedBy, candidate.id)
			}
		}
	}
	if len(signedBy) == 0 {
		return Verified{}, ErrUnsigned
	}
	slices.Sort(signedBy)

	var policy policyv1.Policy
	if err := proto.Unmarshal(payload, &policy); err != nil {
		return Verified{}, fmt.Errorf("%w: its payload is not a policy", ErrMalformed)
	}
	if err := known(policy.ProtoReflect()); err != nil {
		return Verified{}, err
	}
	whole := sha256.Sum256(served)
	return Verified{Policy: &policy, Envelope: served, Digest: hex.EncodeToString(whole[:]), SignedBy: signedBy}, nil
}

func known(message protoreflect.Message) error {
	if len(message.GetUnknown()) > 0 {
		return fmt.Errorf("%w: its %s holds settings this agent does not know", ErrMalformed, message.Descriptor().Name())
	}
	var found error
	message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		switch {
		case field.Message() == nil:
		case field.IsList():
			for index := range value.List().Len() {
				if found = known(value.List().Get(index).Message()); found != nil {
					return false
				}
			}
		default:
			found = known(value.Message())
		}
		return found == nil
	})
	return found
}
