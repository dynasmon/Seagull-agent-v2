package compatibility_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/dynasmon/Seagull-agent-v2/internal/protocol"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	ingestv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/ingest/v1"
	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
)

const (
	contractsModule = "github.com/dynasmon/Seagull-contracts"
	eventsRoute     = "POST /v1/events"
	inventoryRoute  = "POST /v1/inventory"
)

// Each directory under testdata was recorded from the ingest gateway of one
// platform commit, built with the contracts it names: the bytes of every batch
// sent and of the answer it got. The agent claims compatibility with a platform
// only where such a recording backs the claim.
type recording struct {
	directory string
	Platform  struct {
		Repository string `json:"repository"`
		Commit     string `json:"commit"`
		Contracts  string `json:"contracts"`
	} `json:"platform"`
	Exchanges []exchange `json:"exchanges"`
}

type exchange struct {
	Name   string `json:"name"`
	Route  string `json:"route"`
	Status int    `json:"status"`
}

func TestTheContractsTheAgentIsBuiltWithWereRecordedAgainstAPlatform(t *testing.T) {
	command := exec.CommandContext(t.Context(), "go", "list", "-m", "-f", "{{.Version}}", contractsModule)
	command.Env = append(os.Environ(), "GOWORK=off")
	output, err := command.Output()
	if err != nil {
		t.Fatalf("read the contracts release go.mod pins: %v", err)
	}
	pinned := strings.TrimSpace(string(output))
	for _, recorded := range recordings(t) {
		if recorded.Platform.Contracts == pinned {
			return
		}
	}
	t.Fatalf("go.mod pins the contracts at %s and no platform built with them was recorded: record one before the agent claims to speak them", pinned)
}

func TestEveryRecordedPlatformDurablyAcceptsTheVersionsTheAgentSpeaks(t *testing.T) {
	for _, recorded := range recordings(t) {
		t.Run(recorded.name(), func(t *testing.T) {
			var events, inventory bool
			for _, sent := range recorded.Exchanges {
				if sent.Status != http.StatusOK {
					continue
				}
				var acknowledgement ingestv1.BatchAck
				recorded.decode(t, sent.Name, "reply", &acknowledgement)
				switch batch := recorded.batch(t, sent).(type) {
				case *ingestv1.EventBatch:
					events = events || batch.GetProtocolVersion() == protocol.Version &&
						durable(&acknowledgement, len(batch.GetEvents())) &&
						!slices.ContainsFunc(batch.GetEvents(), func(event *eventv1.Event) bool {
							return event.GetSchemaVersion() != protocol.EventSchemaVersion
						})
				case *inventoryv1.RecordBatch:
					inventory = inventory || batch.GetProtocolVersion() == protocol.Version &&
						durable(&acknowledgement, len(batch.GetRecords())) &&
						!slices.ContainsFunc(batch.GetRecords(), func(record *inventoryv1.Record) bool {
							return record.GetSchemaVersion() != protocol.InventorySchemaVersion
						})
				}
			}
			if !events {
				t.Errorf("no recorded exchange shows %s durably accepting event schema %d in a batch of protocol %d",
					recorded.Platform.Commit, protocol.EventSchemaVersion, protocol.Version)
			}
			if !inventory {
				t.Errorf("no recorded exchange shows %s durably accepting inventory schema %d in a batch of protocol %d",
					recorded.Platform.Commit, protocol.InventorySchemaVersion, protocol.Version)
			}
		})
	}
}

func TestARecordedRefusalOfAVersionABatchCarriesIsAnIncompatibility(t *testing.T) {
	cases := []struct {
		exchange string
		field    string
		value    string
		record   int
	}{
		{exchange: "events-protocol-2", field: "protocol_version", value: "2", record: -1},
		{exchange: "events-schema-2", field: "schema_version", value: "2", record: 1},
		{exchange: "inventory-protocol-2", field: "protocol_version", value: "2", record: -1},
		{exchange: "inventory-schema-2", field: "schema_version", value: "2", record: 1},
	}
	for _, recorded := range recordings(t) {
		for _, c := range cases {
			t.Run(recorded.name()+"/"+c.exchange, func(t *testing.T) {
				sent := recorded.exchange(t, c.exchange)
				reply := recorded.payload(t, sent.Name, "reply")
				expectIncompatibility(t, recorded.batch(t, sent), reply, c.field, c.value, c.record)
			})
		}
	}
}

func TestARecordedRefusalOfARecordTheAgentBuiltWrongIsNoIncompatibility(t *testing.T) {
	names := []string{
		"events-invalid-record",
		"events-unknown-class",
		"events-unknown-transport",
		"inventory-invalid-record",
		"inventory-unknown-kind",
		"inventory-unknown-mode",
		"inventory-unknown-service-state",
	}
	for _, recorded := range recordings(t) {
		for _, name := range names {
			t.Run(recorded.name()+"/"+name, func(t *testing.T) {
				sent := recorded.exchange(t, name)
				if found, incompatible := incompatibility(t, recorded.batch(t, sent), recorded.payload(t, sent.Name, "reply")); incompatible {
					t.Fatalf("read an incompatibility, %+v, from a refusal of a value no contracts declare or of a record no platform admits", *found)
				}
			})
		}
	}
}

// A gateway refuses a value its contracts do not declare the same way whether
// or not the sender's contracts declare it. So a platform built from contracts
// older than the agent's answers a value only the agent's declare with the
// refusal recorded here for a value no contracts declare.
func TestARecordedRefusalOfAValueTheAgentDeclaresIsAnIncompatibility(t *testing.T) {
	cases := []struct {
		exchange string
		declare  func(proto.Message)
		field    string
		value    string
		record   int
	}{
		{
			exchange: "events-unknown-class",
			declare: func(batch proto.Message) {
				batch.(*ingestv1.EventBatch).GetEvents()[0].EventClass = eventv1.EventClass_EVENT_CLASS_AUTHENTICATION
			},
			field: "event_class", value: "EVENT_CLASS_AUTHENTICATION", record: 0,
		},
		{
			exchange: "events-unknown-transport",
			declare: func(batch proto.Message) {
				batch.(*ingestv1.EventBatch).GetEvents()[1].GetAuthentication().GetNetwork().Transport = eventv1.Transport_TRANSPORT_UDP
			},
			field: "authentication.network.transport", value: "TRANSPORT_UDP", record: 1,
		},
		{
			exchange: "inventory-unknown-kind",
			declare: func(batch proto.Message) {
				batch.(*inventoryv1.RecordBatch).GetRecords()[0].Kind = inventoryv1.Kind_KIND_PACKAGE
			},
			field: "kind", value: "KIND_PACKAGE", record: 0,
		},
		{
			exchange: "inventory-unknown-mode",
			declare: func(batch proto.Message) {
				batch.(*inventoryv1.RecordBatch).GetRecords()[0].Mode = inventoryv1.Mode_MODE_SNAPSHOT
			},
			field: "mode", value: "MODE_SNAPSHOT", record: 0,
		},
		{
			exchange: "inventory-unknown-service-state",
			declare: func(batch proto.Message) {
				batch.(*inventoryv1.RecordBatch).GetRecords()[0].GetItems()[1].GetService().State = inventoryv1.Service_STATE_FAILED
			},
			field: "items[1].service.state", value: "STATE_FAILED", record: 0,
		},
	}
	for _, recorded := range recordings(t) {
		for _, c := range cases {
			t.Run(recorded.name()+"/"+c.exchange, func(t *testing.T) {
				sent := recorded.exchange(t, c.exchange)
				batch := recorded.batch(t, sent)
				c.declare(batch)
				expectIncompatibility(t, batch, recorded.payload(t, sent.Name, "reply"), c.field, c.value, c.record)
			})
		}
	}
}

func TestFieldsALaterContractsReleaseAddsToAReplyChangeNothingTheAgentReads(t *testing.T) {
	later := slices.Concat(
		[]byte(wire{}.varint(1000, 1).text(1001, "added by a later contracts release").message(1002, wire{}.varint(1, 7))),
		protowire.AppendFixed64(protowire.AppendTag(nil, 1003, protowire.Fixed64Type), 7),
	)
	for _, recorded := range recordings(t) {
		for _, sent := range recorded.Exchanges {
			t.Run(recorded.name()+"/"+sent.Name, func(t *testing.T) {
				reply := recorded.payload(t, sent.Name, "reply")
				extended := slices.Concat(later, reply, later)
				if sent.Status == http.StatusOK {
					var recordedAck, extendedAck ingestv1.BatchAck
					unmarshal(t, reply, &recordedAck)
					unmarshal(t, extended, &extendedAck)
					if extendedAck.GetAccepted() != recordedAck.GetAccepted() || extendedAck.GetDurable() != recordedAck.GetDurable() ||
						extendedAck.GetReceived() != recordedAck.GetReceived() {
						t.Fatalf("read %v with the later fields, %v without them", &extendedAck, &recordedAck)
					}
					return
				}
				var recordedRefusal, extendedRefusal ingestv1.Rejection
				unmarshal(t, reply, &recordedRefusal)
				unmarshal(t, extended, &extendedRefusal)
				if extendedRefusal.GetCode() != recordedRefusal.GetCode() || extendedRefusal.GetDetail() != recordedRefusal.GetDetail() ||
					extendedRefusal.GetField() != recordedRefusal.GetField() || extendedRefusal.GetEventIndex() != recordedRefusal.GetEventIndex() {
					t.Fatalf("read %v with the later fields, %v without them", &extendedRefusal, &recordedRefusal)
				}
				batch := recorded.batch(t, sent)
				want, wasIncompatible := incompatibility(t, batch, reply)
				found, incompatible := incompatibility(t, batch, extended)
				if incompatible != wasIncompatible || (incompatible && *found != *want) {
					t.Fatalf("read the incompatibility %t (%v) with the later fields, %t (%v) without them", incompatible, found, wasIncompatible, want)
				}
			})
		}
	}
}

func TestNoReplyTheAgentReadsCarriesAnEnum(t *testing.T) {
	for _, reply := range []proto.Message{&ingestv1.BatchAck{}, &ingestv1.Rejection{}} {
		descriptor := reply.ProtoReflect().Descriptor()
		if enum := enumWithin(descriptor, map[protoreflect.FullName]bool{}); enum != "" {
			t.Errorf("%s carries the enum %s: decide how the agent reads a value its contracts do not declare before a reply depends on one",
				descriptor.FullName(), enum)
		}
	}
}

func recordings(t *testing.T) []recording {
	t.Helper()
	manifests, err := filepath.Glob(filepath.Join("testdata", "*", "exchanges.json"))
	if err != nil {
		t.Fatalf("find the recorded exchanges: %v", err)
	}
	if len(manifests) == 0 {
		t.Fatal("no platform was recorded, so the agent has nothing to claim compatibility with")
	}
	found := make([]recording, 0, len(manifests))
	for _, manifest := range manifests {
		encoded, err := os.ReadFile(manifest)
		if err != nil {
			t.Fatalf("read %s: %v", manifest, err)
		}
		decoder := json.NewDecoder(bytes.NewReader(encoded))
		decoder.DisallowUnknownFields()
		recorded := recording{directory: filepath.Dir(manifest)}
		if err := decoder.Decode(&recorded); err != nil {
			t.Fatalf("decode %s: %v", manifest, err)
		}
		if recorded.Platform.Repository == "" || recorded.Platform.Commit == "" || recorded.Platform.Contracts == "" {
			t.Fatalf("%s does not say which platform, commit and contracts it was recorded from", manifest)
		}
		found = append(found, recorded)
	}
	return found
}

func (r recording) name() string { return filepath.Base(r.directory) }

func (r recording) exchange(t *testing.T, name string) exchange {
	t.Helper()
	index := slices.IndexFunc(r.Exchanges, func(recorded exchange) bool { return recorded.Name == name })
	if index < 0 {
		t.Fatalf("%s recorded no %s exchange", r.name(), name)
	}
	return r.Exchanges[index]
}

func (r recording) payload(t *testing.T, name, part string) []byte {
	t.Helper()
	encoded, err := os.ReadFile(filepath.Join(r.directory, name+"."+part+".pb"))
	if err != nil {
		t.Fatalf("read the %s of %s: %v", part, name, err)
	}
	return encoded
}

func (r recording) decode(t *testing.T, name, part string, message proto.Message) {
	t.Helper()
	unmarshal(t, r.payload(t, name, part), message)
}

func (r recording) batch(t *testing.T, sent exchange) proto.Message {
	t.Helper()
	var batch proto.Message
	switch sent.Route {
	case eventsRoute:
		batch = &ingestv1.EventBatch{}
	case inventoryRoute:
		batch = &inventoryv1.RecordBatch{}
	default:
		t.Fatalf("%s was sent to %s, where the agent delivers nothing", sent.Name, sent.Route)
	}
	r.decode(t, sent.Name, "request", batch)
	return batch
}

func expectIncompatibility(t *testing.T, batch proto.Message, reply []byte, field, value string, record int) {
	t.Helper()
	var refusal ingestv1.Rejection
	unmarshal(t, reply, &refusal)
	want := protocol.Incompatibility{Field: field, Value: value, Record: record, Detail: refusal.GetDetail()}
	first, incompatible := incompatibility(t, batch, reply)
	if !incompatible {
		t.Fatalf("read no incompatibility from %v, want %+v", &refusal, want)
	}
	if *first != want {
		t.Fatalf("read %+v from %v, want %+v", *first, &refusal, want)
	}
	if again, stillIncompatible := incompatibility(t, batch, reply); !stillIncompatible || again.Error() != first.Error() {
		t.Fatalf("read the same refusal as %q and then as %v", first, again)
	}
}

func incompatibility(t *testing.T, batch proto.Message, reply []byte) (*protocol.Incompatibility, bool) {
	t.Helper()
	var refusal ingestv1.Rejection
	unmarshal(t, reply, &refusal)
	switch batch := batch.(type) {
	case *ingestv1.EventBatch:
		return protocol.IncompatibleEvents(batch, &refusal)
	case *inventoryv1.RecordBatch:
		return protocol.IncompatibleInventory(batch, &refusal)
	}
	t.Fatalf("the agent delivers no %T", batch)
	return nil, false
}

func durable(acknowledgement *ingestv1.BatchAck, sent int) bool {
	return sent > 0 && acknowledgement.GetAccepted() && acknowledgement.GetDurable() && int(acknowledgement.GetReceived()) == sent
}

func unmarshal(t *testing.T, encoded []byte, message proto.Message) {
	t.Helper()
	if err := proto.Unmarshal(encoded, message); err != nil {
		t.Fatalf("decode a %s: %v", message.ProtoReflect().Descriptor().FullName(), err)
	}
}

func enumWithin(message protoreflect.MessageDescriptor, visited map[protoreflect.FullName]bool) string {
	if visited[message.FullName()] {
		return ""
	}
	visited[message.FullName()] = true
	fields := message.Fields()
	for index := range fields.Len() {
		field := fields.Get(index)
		switch field.Kind() {
		case protoreflect.EnumKind:
			return string(field.FullName())
		case protoreflect.MessageKind, protoreflect.GroupKind:
			if enum := enumWithin(field.Message(), visited); enum != "" {
				return enum
			}
		}
	}
	return ""
}
