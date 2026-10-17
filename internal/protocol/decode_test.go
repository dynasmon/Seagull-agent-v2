package protocol_test

import (
	"errors"
	"runtime"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-agent-v2/internal/protocol"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
	controlv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/control/v1"
	ingestv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/ingest/v1"
	policyv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/policy/v1"
	updatev1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/update/v1"
)

func offered(roots int) *updatev1.Offer {
	offer := &updatev1.Offer{Version: "v0.3.0", Catalog: &updatev1.Envelope{PayloadType: "catalog", Payload: []byte("signed"),
		Signatures: []*updatev1.Signature{{Keyid: "catalog-key", Sig: []byte("signature")}}}}
	for range roots {
		offer.Roots = append(offer.Roots, &updatev1.Envelope{})
	}
	return offer
}

func emptyValues(field protowire.Number, size int) []byte {
	var content []byte
	for len(content)+2 <= size {
		content = protowire.AppendVarint(protowire.AppendTag(content, field, protowire.BytesType), 0)
	}
	return content
}

func TestAMessageWithinItsBudgetIsDecodedAsTheContractsDecodeIt(t *testing.T) {
	for _, message := range []proto.Message{
		offered(3),
		&ingestv1.BatchAck{Accepted: true, Durable: true, Received: 7},
		&ingestv1.Rejection{Code: "invalid_record", Detail: "refused", EventIndex: 1, Field: "time.event_time"},
		&controlv1.Refusal{Code: "illegal_move", Detail: "the certificate was already replaced"},
		&agentv1.IssuedCertificate{CertificatePem: []byte("certificate"), Identity: &agentv1.Identity{Subject: "web-01", Serial: "01"}},
		&policyv1.SignedPolicy{Payload: []byte("policy"), PayloadType: "policy", Signatures: []*policyv1.Signature{{Sig: []byte("signature"), Keyid: "key"}}},
		&updatev1.Root{Version: 2, IssuedAt: timestamppb.New(time.Date(2026, time.October, 17, 12, 0, 0, 0, time.UTC)), Keys: []*updatev1.Key{{Keyid: "root-key"}}},
	} {
		content, err := proto.Marshal(message)
		if err != nil {
			t.Fatal(err)
		}
		decoded := message.ProtoReflect().New().Interface()
		if err := protocol.Decode(content, decoded, protocol.MaxAnswerValues); err != nil || !proto.Equal(decoded, message) {
			t.Fatalf("%s was decoded as %v: %v", message.ProtoReflect().Descriptor().FullName(), decoded, err)
		}
	}
}

func TestAMessageOfMoreValuesThanItsBudgetIsRefusedBeforeAnyOfItIsDecoded(t *testing.T) {
	offer := offered(5)
	content, err := proto.Marshal(offer)
	if err != nil {
		t.Fatal(err)
	}
	const values = 1 + 6 + 5
	var decoded updatev1.Offer
	if err := protocol.Decode(content, &decoded, values); err != nil || !proto.Equal(&decoded, offer) {
		t.Fatalf("an offer of %d values was not decoded within as many: %v", values, err)
	}
	decoded.Reset()
	if err := protocol.Decode(content, &decoded, values-1); !errors.Is(err, protocol.ErrExcessive) || !proto.Equal(&decoded, &updatev1.Offer{}) {
		t.Fatalf("an offer of %d values was decoded within %d as %v: %v", values, values-1, &decoded, err)
	}
}

func TestEachElementOfAPackedListCounts(t *testing.T) {
	location := &descriptorpb.SourceCodeInfo_Location{Path: []int32{1, 200, 3, 40000}, Span: []int32{7, 8, 9}}
	content, err := proto.Marshal(location)
	if err != nil {
		t.Fatal(err)
	}
	var decoded descriptorpb.SourceCodeInfo_Location
	if err := protocol.Decode(content, &decoded, 7); err != nil || !proto.Equal(&decoded, location) {
		t.Fatalf("seven packed elements were not decoded within seven values: %v", err)
	}
	if err := protocol.Decode(content, &decoded, 6); !errors.Is(err, protocol.ErrExcessive) {
		t.Fatalf("seven packed elements were decoded within six values: %v", err)
	}
}

func TestAMessageWrittenToCostMemoryIsRefusedWithoutCostingAny(t *testing.T) {
	for name, built := range map[string]struct {
		content []byte
		into    proto.Message
	}{
		"an offer of four mebibytes of empty roots":   {emptyValues(1, 4<<20), &updatev1.Offer{}},
		"a signed policy of a mebibyte of signatures": {emptyValues(3, 1<<20), &policyv1.SignedPolicy{}},
		"a refusal of a mebibyte of unknown fields":   {emptyValues(99, 1<<20), &ingestv1.Rejection{}},
	} {
		t.Run(name, func(t *testing.T) {
			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)
			err := protocol.Decode(built.content, built.into, protocol.MaxAnswerValues)
			runtime.ReadMemStats(&after)
			if !errors.Is(err, protocol.ErrExcessive) {
				t.Fatalf("decoded: %v", err)
			}
			if spent := after.TotalAlloc - before.TotalAlloc; spent > 64<<10 {
				t.Fatalf("refusing %d bytes allocated %d", len(built.content), spent)
			}
		})
	}
}

func TestMessagesNestedDeeperThanTheContractsDecodeAreRefused(t *testing.T) {
	content := []byte{}
	for range protowire.DefaultRecursionLimit + 1 {
		content = protowire.AppendBytes(protowire.AppendTag(nil, 3, protowire.BytesType), content)
	}
	var decoded descriptorpb.DescriptorProto
	if err := protocol.Decode(content, &decoded, len(content)); err == nil {
		t.Fatal("messages nested past the recursion limit were decoded")
	}
}

// Whatever the bytes, the walk takes what the contracts would decode and
// refuses what they would refuse, so a budget the bytes fit within changes
// nothing but what costs memory.
func FuzzDecode(f *testing.F) {
	for _, message := range []proto.Message{
		offered(2),
		&ingestv1.Rejection{Code: "invalid_record", EventIndex: 1},
		&policyv1.SignedPolicy{Payload: []byte("policy"), Signatures: []*policyv1.Signature{{Sig: []byte("signature")}}},
		&descriptorpb.SourceCodeInfo_Location{Path: []int32{1, 200, 3}},
	} {
		content, err := proto.Marshal(message)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(content)
	}
	f.Add(emptyValues(1, 64))
	f.Fuzz(func(t *testing.T, content []byte) {
		for _, empty := range []proto.Message{&updatev1.Offer{}, &ingestv1.Rejection{}, &policyv1.SignedPolicy{}, &updatev1.Catalog{}, &descriptorpb.SourceCodeInfo_Location{}} {
			reference := empty.ProtoReflect().New().Interface()
			refused := proto.Unmarshal(content, reference)
			decoded := empty.ProtoReflect().New().Interface()
			err := protocol.Decode(content, decoded, len(content)+1)
			switch {
			case (err == nil) != (refused == nil):
				t.Fatalf("%s: the contracts said %v and the agent %v", empty.ProtoReflect().Descriptor().FullName(), refused, err)
			case err == nil && !proto.Equal(decoded, reference):
				t.Fatalf("%s: the agent decoded %v, and the contracts %v", empty.ProtoReflect().Descriptor().FullName(), decoded, reference)
			}
			if err := protocol.Decode(content, empty.ProtoReflect().New().Interface(), 0); err == nil && len(content) > 0 {
				t.Fatalf("%s: %d bytes were decoded within no value at all", empty.ProtoReflect().Descriptor().FullName(), len(content))
			}
		}
	})
}
