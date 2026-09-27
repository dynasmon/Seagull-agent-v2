package protocol

import (
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	ingestv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/ingest/v1"
	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
)

const ContentType = "application/x-protobuf"

var ErrMalformed = errors.New("the record is not a well-formed message of its route")

// A Route is where the platform takes one kind of record, and the shape of the
// batches it takes them in: an event is one record of the events route, and
// what one asset has of one kind is one record of the inventory route.
type Route int

const (
	Events Route = iota + 1
	Inventory
)

func (r Route) String() string {
	switch r {
	case Events:
		return "events"
	case Inventory:
		return "inventory"
	default:
		return fmt.Sprintf("route(%d)", int(r))
	}
}

type shape struct {
	path     string
	batchID  protowire.Number
	version  protowire.Number
	records  protowire.Number
	recordID protowire.Number
	items    protowire.Number
	record   func() proto.Message
	refusing string
	maxAge   time.Duration
}

var shapes = map[Route]shape{
	Events: {
		path:     "/v1/events",
		batchID:  number(&ingestv1.EventBatch{}, "batch_id"),
		version:  number(&ingestv1.EventBatch{}, "protocol_version"),
		records:  number(&ingestv1.EventBatch{}, "events"),
		recordID: number(&eventv1.Event{}, "event_id"),
		record:   func() proto.Message { return &eventv1.Event{} },
		refusing: "invalid_event",
		maxAge:   MaxEventAge,
	},
	Inventory: {
		path:     "/v1/inventory",
		batchID:  number(&inventoryv1.RecordBatch{}, "batch_id"),
		version:  number(&inventoryv1.RecordBatch{}, "protocol_version"),
		records:  number(&inventoryv1.RecordBatch{}, "records"),
		recordID: number(&inventoryv1.Record{}, "record_id"),
		items:    number(&inventoryv1.Record{}, "items"),
		record:   func() proto.Message { return &inventoryv1.Record{} },
		refusing: "invalid_record",
		maxAge:   MaxInventoryAge,
	},
}

func number(message proto.Message, name protoreflect.Name) protowire.Number {
	return message.ProtoReflect().Descriptor().Fields().ByName(name).Number()
}

func (r Route) shape() shape { return shapes[r] }

func (r Route) Path() string { return r.shape().path }

// Batch is a batch of the route as the platform reads it: its identifier, the
// protocol version, and each record framed as one element of the batch, byte
// for byte as it was admitted. A record is never decoded to be sent, so the
// bytes of a record are the same in every batch that carries it.
func (r Route) Batch(id string, records [][]byte) []byte {
	shape := r.shape()
	size := r.Envelope(id)
	for _, record := range records {
		size += r.Framed(len(record))
	}
	body := make([]byte, 0, size)
	body = protowire.AppendTag(body, shape.batchID, protowire.BytesType)
	body = protowire.AppendString(body, id)
	body = protowire.AppendTag(body, shape.version, protowire.VarintType)
	body = protowire.AppendVarint(body, Version)
	for _, record := range records {
		body = protowire.AppendTag(body, shape.records, protowire.BytesType)
		body = protowire.AppendBytes(body, record)
	}
	return body
}

func (r Route) Records(batch []byte) [][]byte {
	shape := r.shape()
	var records [][]byte
	for rest := batch; len(rest) > 0; {
		field, kind, read := protowire.ConsumeTag(rest)
		if read < 0 {
			return records
		}
		rest = rest[read:]
		if field == shape.records && kind == protowire.BytesType {
			record, read := protowire.ConsumeBytes(rest)
			if read < 0 {
				return records
			}
			records = append(records, record[:len(record):len(record)])
			rest = rest[read:]
			continue
		}
		read = protowire.ConsumeFieldValue(field, kind, rest)
		if read < 0 {
			return records
		}
		rest = rest[read:]
	}
	return records
}

func (r Route) Envelope(id string) int {
	shape := r.shape()
	return protowire.SizeTag(shape.batchID) + protowire.SizeBytes(len(id)) + protowire.SizeTag(shape.version) + protowire.SizeVarint(Version)
}

func (r Route) Framed(record int) int {
	return protowire.SizeTag(r.shape().records) + protowire.SizeBytes(record)
}

type Identity struct {
	ID    string
	Items int
}

// Identify reads what a batch needs to know of a record without decoding it:
// the identifier it carries and, on the inventory route, how many items. A
// record that is not a sequence of well-formed fields, or that carries no
// identifier, could never be read out of a batch.
func (r Route) Identify(record []byte) (Identity, error) {
	shape := r.shape()
	var found Identity
	named := false
	for rest := record; len(rest) > 0; {
		field, kind, read := protowire.ConsumeTag(rest)
		if read < 0 {
			return Identity{}, fmt.Errorf("%w: %v", ErrMalformed, protowire.ParseError(read))
		}
		rest = rest[read:]
		if field == shape.recordID && kind == protowire.BytesType {
			value, read := protowire.ConsumeBytes(rest)
			if read < 0 {
				return Identity{}, fmt.Errorf("%w: %v", ErrMalformed, protowire.ParseError(read))
			}
			found.ID, named = string(value), true
			rest = rest[read:]
			continue
		}
		if field == shape.items && kind == protowire.BytesType {
			found.Items++
		}
		read = protowire.ConsumeFieldValue(field, kind, rest)
		if read < 0 {
			return Identity{}, fmt.Errorf("%w: %v", ErrMalformed, protowire.ParseError(read))
		}
		rest = rest[read:]
	}
	switch {
	case !named || found.ID == "":
		return Identity{}, fmt.Errorf("%w: it carries no identifier", ErrMalformed)
	case !utf8.ValidString(found.ID):
		return Identity{}, fmt.Errorf("%w: its identifier is not text", ErrMalformed)
	}
	return found, nil
}
