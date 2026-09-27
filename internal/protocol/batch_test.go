package protocol_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-agent-v2/internal/protocol"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	ingestv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/ingest/v1"
	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
)

const batchID = "8f0c2d5e-4b1a-4c3d-9e2f-1a2b3c4d5e6f"

func encoded(t testing.TB, message proto.Message) []byte {
	t.Helper()
	content, err := proto.Marshal(message)
	if err != nil {
		t.Fatalf("encode %T: %v", message, err)
	}
	return content
}

func numberedEvents(count int) []*eventv1.Event {
	at := timestamppb.New(time.Date(2026, time.September, 27, 12, 0, 0, 0, time.UTC))
	var found []*eventv1.Event
	for i := range count {
		event := authentication()
		event.EventId = strings.Repeat("e", 8) + string(rune('a'+i))
		event.Time = &eventv1.Timestamps{EventTime: at, ObservedTime: at}
		event.GetAuthentication().RawRecord = strings.Repeat("sshd[812]: Failed password for root ", i*40)
		found = append(found, event)
	}
	return found
}

func TestABatchCarriesEachRecordByteForByteAsTheContractsWouldWriteIt(t *testing.T) {
	events := numberedEvents(3)
	payloads := make([][]byte, len(events))
	for i, event := range events {
		payloads[i] = encoded(t, event)
	}
	body := protocol.Events.Batch(batchID, payloads)
	written := encoded(t, &ingestv1.EventBatch{BatchId: batchID, ProtocolVersion: protocol.Version, Events: events})
	if !bytes.Equal(body, written) {
		t.Fatalf("the agent framed a batch of %d bytes that the contracts write as %d", len(body), len(written))
	}
	var read ingestv1.EventBatch
	if err := proto.Unmarshal(body, &read); err != nil {
		t.Fatalf("decode the batch: %v", err)
	}
	carried := protocol.Events.Records(body)
	if len(carried) != len(payloads) || len(read.GetEvents()) != len(payloads) {
		t.Fatalf("a batch of %d events carries %d, and the contracts read %d", len(payloads), len(carried), len(read.GetEvents()))
	}
	for i, event := range read.GetEvents() {
		if !bytes.Equal(encoded(t, event), payloads[i]) || !bytes.Equal(carried[i], payloads[i]) {
			t.Errorf("event %d reads back as other bytes than it was admitted as", i)
		}
	}

	records := []*inventoryv1.Record{services(inventoryv1.Service_STATE_RUNNING), services(), services(inventoryv1.Service_STATE_STOPPED, inventoryv1.Service_STATE_RUNNING)}
	payloads = payloads[:0]
	for _, record := range records {
		payloads = append(payloads, encoded(t, record))
	}
	body = protocol.Inventory.Batch(batchID, payloads)
	if written := encoded(t, &inventoryv1.RecordBatch{BatchId: batchID, ProtocolVersion: protocol.Version, Records: records}); !bytes.Equal(body, written) {
		t.Fatalf("the agent framed an inventory batch of %d bytes that the contracts write as %d", len(body), len(written))
	}
}

func TestTheSizeOfABatchIsKnownBeforeItIsBuilt(t *testing.T) {
	for _, route := range []protocol.Route{protocol.Events, protocol.Inventory} {
		for _, lengths := range [][]int{nil, {1}, {127, 128}, {16383, 16384, 1}, {2097151, 2097152}, {8 << 20}} {
			records := make([][]byte, len(lengths))
			want := route.Envelope(batchID)
			for i, length := range lengths {
				records[i] = bytes.Repeat([]byte{0x0a}, length)
				want += route.Framed(length)
			}
			if built := len(route.Batch(batchID, records)); built != want {
				t.Errorf("%s: a batch of records of %v bytes was built as %d bytes, and its size was reckoned as %d", route, lengths, built, want)
			}
		}
	}
}

func TestOneRecordAndTheEnvelopeAroundItTakeLessThanTheBatchEnvelope(t *testing.T) {
	longest := strings.Repeat("b", 64)
	for _, route := range []protocol.Route{protocol.Events, protocol.Inventory} {
		for _, length := range []int{1, 1 << 10, 8 << 20} {
			if around := route.Envelope(longest) + route.Framed(length) - length; around >= protocol.BatchEnvelopeBytes {
				t.Errorf("%s: a record of %d bytes takes %d bytes of envelope around it", route, length, around)
			}
		}
	}
}

func TestARecordIsIdentifiedWithoutBeingDecoded(t *testing.T) {
	event := authentication()
	if found, err := protocol.Events.Identify(encoded(t, event)); err != nil || found.ID != event.GetEventId() || found.Items != 0 {
		t.Fatalf("an event was identified as %+v, %v", found, err)
	}
	for _, items := range []int{0, 1, 3} {
		record := services()
		for range items {
			record.Items = append(record.Items, &inventoryv1.Item{Body: &inventoryv1.Item_Service{Service: &inventoryv1.Service{Name: "sshd.service"}}})
		}
		found, err := protocol.Inventory.Identify(encoded(t, record))
		if err != nil || found.ID != record.GetRecordId() || found.Items != items {
			t.Fatalf("a record of %d items was identified as %+v, %v", items, found, err)
		}
	}
	twice := protowire.AppendString(protowire.AppendTag(encoded(t, event), 1, protowire.BytesType), "the-later-identifier")
	var read eventv1.Event
	if err := proto.Unmarshal(twice, &read); err != nil {
		t.Fatalf("decode an event that names itself twice: %v", err)
	}
	if found, err := protocol.Events.Identify(twice); err != nil || found.ID != read.GetEventId() {
		t.Fatalf("an event the contracts read as %q was identified as %+v, %v", read.GetEventId(), found, err)
	}
}

func TestARecordNoBatchCouldCarryIsRefused(t *testing.T) {
	unnamed := authentication()
	unnamed.EventId = ""
	for name, record := range map[string][]byte{
		"nothing":                   nil,
		"a tag cut short":           {0x80},
		"a wire type nobody writes": {0x0f},
		"a field longer than it is": protowire.AppendVarint(protowire.AppendTag(nil, 1, protowire.BytesType), 64),
		"no identifier":             encoded(t, unnamed),
		"an identifier as a number": protowire.AppendVarint(protowire.AppendTag(nil, 1, protowire.VarintType), 7),
		"an identifier that is not text": protowire.AppendBytes(protowire.AppendTag(nil, 1, protowire.BytesType),
			[]byte{0xff, 0xfe}),
	} {
		t.Run(name, func(t *testing.T) {
			if found, err := protocol.Events.Identify(record); !errors.Is(err, protocol.ErrMalformed) {
				t.Fatalf("identified %+v, %v", found, err)
			}
		})
	}
}

func FuzzIdentify(f *testing.F) {
	f.Add(encoded(f, authentication()))
	f.Add(encoded(f, services(inventoryv1.Service_STATE_RUNNING)))
	f.Add([]byte{0x0a, 0x02, 'i', 'd', 0x4a, 0x00, 0x4a, 0x00})
	f.Fuzz(func(t *testing.T, record []byte) {
		var event eventv1.Event
		if proto.Unmarshal(record, &event) == nil && event.GetEventId() != "" {
			if found, err := protocol.Events.Identify(record); err != nil || found.ID != event.GetEventId() {
				t.Fatalf("the contracts read event %q and the agent identified %+v, %v", event.GetEventId(), found, err)
			}
		}
		var inventory inventoryv1.Record
		if proto.Unmarshal(record, &inventory) == nil && inventory.GetRecordId() != "" {
			found, err := protocol.Inventory.Identify(record)
			if err != nil || found.ID != inventory.GetRecordId() || found.Items != len(inventory.GetItems()) {
				t.Fatalf("the contracts read record %q of %d items and the agent identified %+v, %v",
					inventory.GetRecordId(), len(inventory.GetItems()), found, err)
			}
		}
		for _, route := range []protocol.Route{protocol.Events, protocol.Inventory} {
			if _, err := route.Identify(record); err != nil {
				continue
			}
			carried := route.Records(route.Batch(batchID, [][]byte{record, record}))
			if len(carried) != 2 || !bytes.Equal(carried[0], record) || !bytes.Equal(carried[1], record) {
				t.Fatalf("%s: a batch carried %d records, not the one it was given twice", route, len(carried))
			}
		}
	})
}
