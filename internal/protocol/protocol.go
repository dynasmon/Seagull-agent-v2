package protocol

import (
	"fmt"
	"strconv"
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	ingestv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/ingest/v1"
	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
)

// What the agent writes on the wire, each changing on its own: Version on every
// batch, EventSchemaVersion on every event and InventorySchemaVersion on every
// inventory record. None of them is the release of the agent.
const (
	Version                = 1
	EventSchemaVersion     = 1
	InventorySchemaVersion = 1
)

const (
	unsupportedProtocol = "unsupported_protocol_version"
	schemaVersion       = "schema_version"
	maxFieldPath        = 256
)

type Incompatibility struct {
	Field  string
	Value  string
	Record int
	Detail string
}

func (i *Incompatibility) Error() string {
	if i.Record < 0 {
		return fmt.Sprintf("the platform does not accept %s %s: %s", i.Field, i.Value, i.Detail)
	}
	return fmt.Sprintf("the platform does not accept %s %s in record %d: %s", i.Field, i.Value, i.Record, i.Detail)
}

func IncompatibleEvents(batch *ingestv1.EventBatch, refusal *ingestv1.Rejection) (*Incompatibility, bool) {
	return incompatible(batch.GetProtocolVersion(), batch.GetEvents(), refusal)
}

func IncompatibleInventory(batch *inventoryv1.RecordBatch, refusal *ingestv1.Rejection) (*Incompatibility, bool) {
	return incompatible(batch.GetProtocolVersion(), batch.GetRecords(), refusal)
}

// A refusal is an incompatibility only when it refuses what the agent meant to
// send: a version it set, or a value its contracts declare. The platform then
// does not speak it yet, and the records stay valid for one that does. A
// refused value left unset, or one no contract declares, is the agent's mistake.
func incompatible[R proto.Message](version uint32, records []R, refusal *ingestv1.Rejection) (*Incompatibility, bool) {
	if refusal.GetCode() == unsupportedProtocol {
		if version == 0 {
			return nil, false
		}
		return &Incompatibility{
			Field:  "protocol_version",
			Value:  strconv.FormatUint(uint64(version), 10),
			Record: -1,
			Detail: refusal.GetDetail(),
		}, true
	}
	index := int(refusal.GetEventIndex())
	if index < 0 || index >= len(records) {
		return nil, false
	}
	value, meant := refused(records[index].ProtoReflect(), refusal.GetField())
	if !meant {
		return nil, false
	}
	return &Incompatibility{Field: refusal.GetField(), Value: value, Record: index, Detail: refusal.GetDetail()}, true
}

// The platform names a refused field by its path in the record: the contracts'
// field names joined by dots, with the position of an element of a repeated field.
func refused(record protoreflect.Message, path string) (string, bool) {
	if !record.IsValid() || len(path) > maxFieldPath {
		return "", false
	}
	if path == schemaVersion {
		field := record.Descriptor().Fields().ByName(schemaVersion)
		if field == nil || field.Kind() != protoreflect.Uint32Kind {
			return "", false
		}
		if version := record.Get(field).Uint(); version != 0 {
			return strconv.FormatUint(version, 10), true
		}
		return "", false
	}
	message := record
	for {
		segment, rest, nested := strings.Cut(path, ".")
		field, value, found := element(message, segment)
		switch {
		case !found:
			return "", false
		case !nested:
			return declared(field, value)
		case field.Kind() != protoreflect.MessageKind || !value.Message().IsValid():
			return "", false
		}
		message, path = value.Message(), rest
	}
}

func element(message protoreflect.Message, segment string) (protoreflect.FieldDescriptor, protoreflect.Value, bool) {
	name, position, listed := strings.Cut(segment, "[")
	field := message.Descriptor().Fields().ByName(protoreflect.Name(name))
	if field == nil || field.IsMap() || field.IsList() != listed {
		return nil, protoreflect.Value{}, false
	}
	if !listed {
		return field, message.Get(field), true
	}
	digits, closed := strings.CutSuffix(position, "]")
	index, err := strconv.Atoi(digits)
	list := message.Get(field).List()
	if !closed || err != nil || index < 0 || index >= list.Len() {
		return nil, protoreflect.Value{}, false
	}
	return field, list.Get(index), true
}

func declared(field protoreflect.FieldDescriptor, value protoreflect.Value) (string, bool) {
	if field.Kind() != protoreflect.EnumKind || value.Enum() == 0 {
		return "", false
	}
	named := field.Enum().Values().ByNumber(value.Enum())
	if named == nil {
		return "", false
	}
	return string(named.Name()), true
}
