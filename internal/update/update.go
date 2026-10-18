// Package update is what the agent makes of a release the platform asks it to
// run: it walks the roots it is handed from the one it was provisioned with,
// verifies the catalog of releases under the newest of them, judges whether a
// release is one this agent may install, fetches and stages its package, and,
// in the installer that holds the privilege the agent lacks, verifies all of it
// again, installs it, checks that it runs and goes back when it does not. It
// holds no key that signs, and nothing the platform says decides whose
// signature counts.
package update

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/dynasmon/Seagull-agent-v2/internal/dsse"
	"github.com/dynasmon/Seagull-agent-v2/internal/protocol"
	"github.com/dynasmon/Seagull-agent-v2/internal/secrets"
	updatev1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/update/v1"
)

const (
	SchemaVersion      = 1
	RootPayloadType    = "application/vnd.seagull.update.v1.root+protobuf"
	CatalogPayloadType = "application/vnd.seagull.update.v1.catalog+protobuf"
	Path               = "/v1/agents/update"
	PackagesPath       = "/v1/agents/update/packages/"

	MaxPayloadBytes     = 1 << 20
	MaxEnvelopeBytes    = MaxPayloadBytes + 16<<10
	MaxOfferBytes       = 4 << 20
	MaxSignatures       = 16
	MaxRoots            = 64
	MaxOfferValues      = (MaxRoots + 1) * protocol.MaxAnswerValues
	MaxCatalogValues    = MaxReleases * 256
	MaxKeys             = 16
	MaxRoleKeys         = 8
	MaxReleases         = 256
	MaxReplaced         = 16
	MaxPackageBytes     = 256 << 20
	MaxVersionLength    = 128
	MaxPlatformLength   = 32
	MaxRepositoryLength = 256
	MaxReasonBytes      = 1 << 10
	MaxLifetime         = 366 * 24 * time.Hour
	MaxAhead            = 5 * time.Minute

	StateGeneration = 1
)

var (
	ErrUnsigned  = errors.New("not enough keys of the role that signs the metadata signed it")
	ErrMalformed = errors.New("the update metadata is not one the agent reads")
	ErrExpired   = errors.New("the update metadata has run out")
	ErrStale     = errors.New("the update metadata is older than what the agent already verified")
	ErrRoot      = errors.New("the update root the agent was provisioned with is not usable")
	ErrRefused   = errors.New("the release is authorized and not one this agent may install")
)

func KeyID(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

func signedBy(keys map[string]*ecdsa.PublicKey, role *updatev1.Role, payloadType string, envelope *updatev1.Envelope) ([]string, error) {
	payload, signatures := envelope.GetPayload(), envelope.GetSignatures()
	switch {
	case envelope.GetPayloadType() != payloadType:
		return nil, fmt.Errorf("%w: its payload is declared as %s, and %s was expected",
			ErrMalformed, secrets.Shown(envelope.GetPayloadType()), payloadType)
	case len(payload) == 0 || len(payload) > MaxPayloadBytes:
		return nil, fmt.Errorf("%w: its payload holds %d bytes, and metadata holds between 1 and %d", ErrMalformed, len(payload), MaxPayloadBytes)
	case len(signatures) == 0:
		return nil, fmt.Errorf("%w: it carries no signature", ErrUnsigned)
	case len(signatures) > MaxSignatures:
		return nil, fmt.Errorf("%w: it carries %d signatures, and metadata carries at most %d", ErrMalformed, len(signatures), MaxSignatures)
	}
	digest := sha256.Sum256(dsse.PAE(payloadType, payload))
	var signed []string
	for _, signature := range signatures {
		for _, id := range role.GetKeyids() {
			key := keys[id]
			if key != nil && !slices.Contains(signed, id) && ecdsa.VerifyASN1(key, digest[:], signature.GetSig()) {
				signed = append(signed, id)
			}
		}
	}
	if uint32(len(signed)) < role.GetThreshold() {
		return nil, fmt.Errorf("%w: %d of its keys signed, and %d must", ErrUnsigned, len(signed), role.GetThreshold())
	}
	slices.Sort(signed)
	return signed, nil
}

func decode(served []byte) (*updatev1.Envelope, error) {
	if len(served) > MaxEnvelopeBytes {
		return nil, fmt.Errorf("%w: the envelope is longer than %d bytes", ErrMalformed, MaxEnvelopeBytes)
	}
	var envelope updatev1.Envelope
	if err := protocol.Decode(served, &envelope, protocol.MaxAnswerValues); err != nil {
		return nil, fmt.Errorf("%w: it is not an envelope", ErrMalformed)
	}
	return &envelope, nil
}

func encode(envelope *updatev1.Envelope) ([]byte, error) {
	served, err := proto.MarshalOptions{Deterministic: true}.Marshal(envelope)
	if err != nil || len(served) > MaxEnvelopeBytes {
		return nil, fmt.Errorf("%w: the envelope cannot be kept within %d bytes", ErrMalformed, MaxEnvelopeBytes)
	}
	return served, nil
}

func known(message protoreflect.Message) error {
	if len(message.GetUnknown()) > 0 {
		return fmt.Errorf("%w: its %s holds fields this agent does not know", ErrMalformed, message.Descriptor().Name())
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

func explained(reason string) string {
	reason = strings.ToValidUTF8(reason, "?")
	if len(reason) <= MaxReasonBytes {
		return reason
	}
	cut := MaxReasonBytes - len("...")
	for cut > 0 && !utf8.RuneStart(reason[cut]) {
		cut--
	}
	return reason[:cut] + "..."
}
