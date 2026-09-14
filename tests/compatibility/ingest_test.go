package compatibility_test

import (
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	ingestv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/ingest/v1"
)

// Every message here is written from the wire format rather than with the
// generated types, so a contracts release that renumbers or retypes a field the
// agent depends on fails this suite instead of changing what the agent reads.
type wire []byte

func (w wire) varint(number protowire.Number, value uint64) wire {
	return protowire.AppendVarint(protowire.AppendTag(w, number, protowire.VarintType), value)
}

func (w wire) int32(number protowire.Number, value int32) wire {
	return w.varint(number, uint64(int64(value)))
}

func (w wire) text(number protowire.Number, value string) wire {
	return protowire.AppendString(protowire.AppendTag(w, number, protowire.BytesType), value)
}

func (w wire) message(number protowire.Number, value wire) wire {
	return protowire.AppendBytes(protowire.AppendTag(w, number, protowire.BytesType), value)
}

func TestTheGatewayAcknowledgementReadsAsItWasWritten(t *testing.T) {
	cases := []struct {
		name     string
		reply    wire
		accepted bool
		durable  bool
		received uint32
	}{
		{
			name:     "a durable batch of three records",
			reply:    wire{}.varint(1, 1).varint(2, 1).varint(3, 3),
			accepted: true,
			durable:  true,
			received: 3,
		},
		{
			name:     "an accepted batch the backbone did not make durable",
			reply:    wire{}.varint(1, 1).varint(3, 3),
			accepted: true,
			received: 3,
		},
		{
			name: "an empty reply",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var ack ingestv1.BatchAck
			if err := proto.Unmarshal(c.reply, &ack); err != nil {
				t.Fatalf("decode the acknowledgement: %v", err)
			}
			if ack.GetAccepted() != c.accepted || ack.GetDurable() != c.durable || ack.GetReceived() != c.received {
				t.Fatalf("read accepted=%t durable=%t received=%d, written accepted=%t durable=%t received=%d",
					ack.GetAccepted(), ack.GetDurable(), ack.GetReceived(), c.accepted, c.durable, c.received)
			}
		})
	}
}

func TestARejectionNamesTheRecordItRefused(t *testing.T) {
	cases := []struct {
		name  string
		reply wire
		code  string
		field string
		index int32
	}{
		{
			name:  "the batch as a whole",
			reply: wire{}.text(1, "unsupported_protocol_version").text(2, "this gateway speaks protocol 1..1").int32(4, -1),
			code:  "unsupported_protocol_version",
			index: -1,
		},
		{
			name:  "one record of the batch",
			reply: wire{}.text(1, "invalid_event").text(2, "the event time is too old").text(3, "time.event_time").int32(4, 2),
			code:  "invalid_event",
			field: "time.event_time",
			index: 2,
		},
		{
			name:  "the first record, whose index the wire leaves out",
			reply: wire{}.text(1, "invalid_event").text(2, "the event has no identifier").text(3, "event_id"),
			code:  "invalid_event",
			field: "event_id",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var rejection ingestv1.Rejection
			if err := proto.Unmarshal(c.reply, &rejection); err != nil {
				t.Fatalf("decode the rejection: %v", err)
			}
			if rejection.GetCode() != c.code || rejection.GetField() != c.field || rejection.GetEventIndex() != c.index {
				t.Fatalf("read code=%q field=%q index=%d, written code=%q field=%q index=%d",
					rejection.GetCode(), rejection.GetField(), rejection.GetEventIndex(), c.code, c.field, c.index)
			}
		})
	}
}

func TestTheEventBatchEnvelopeKeepsItsFieldNumbers(t *testing.T) {
	request := wire{}.
		text(1, "0190f5d2-7c3e-7a41-9b6e-2f4d8c1a3e57").
		varint(2, 1).
		message(3, wire{}.text(1, "first")).
		message(3, wire{}.text(1, "second"))

	var batch ingestv1.EventBatch
	if err := proto.Unmarshal(request, &batch); err != nil {
		t.Fatalf("decode the batch: %v", err)
	}
	if batch.GetBatchId() != "0190f5d2-7c3e-7a41-9b6e-2f4d8c1a3e57" || batch.GetProtocolVersion() != 1 {
		t.Fatalf("read batch_id=%q protocol_version=%d", batch.GetBatchId(), batch.GetProtocolVersion())
	}
	events := batch.GetEvents()
	if len(events) != 2 || events[0].GetEventId() != "first" || events[1].GetEventId() != "second" {
		t.Fatalf("read %d events in the batch: %v", len(events), events)
	}
}
