package protocol_test

import (
	"strings"
	"testing"

	"github.com/dynasmon/Seagull-agent-v2/internal/protocol"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	ingestv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/ingest/v1"
	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
)

func authentication() *eventv1.Event {
	return &eventv1.Event{
		EventId:       "0190f5d2-7c3e-7a41-9b6e-2f4d8c1a3e01",
		SchemaVersion: protocol.EventSchemaVersion,
		EventClass:    eventv1.EventClass_EVENT_CLASS_AUTHENTICATION,
		Body: &eventv1.Event_Authentication{Authentication: &eventv1.Authentication{
			Activity: eventv1.Authentication_ACTIVITY_LOGOFF,
			Outcome:  eventv1.Outcome_OUTCOME_SUCCESS,
			User:     &eventv1.User{Name: "root"},
			Network:  &eventv1.Network{Transport: eventv1.Transport_TRANSPORT_UDP},
		}},
	}
}

func events(records ...*eventv1.Event) *ingestv1.EventBatch {
	return &ingestv1.EventBatch{BatchId: "batch-events", ProtocolVersion: protocol.Version, Events: records}
}

func services(states ...inventoryv1.Service_State) *inventoryv1.Record {
	record := &inventoryv1.Record{
		RecordId:      "0190f5d2-7c3e-7a41-9b6e-2f4d8c1a3f01",
		SchemaVersion: protocol.InventorySchemaVersion,
		Kind:          inventoryv1.Kind_KIND_SERVICE,
		Mode:          inventoryv1.Mode_MODE_DELTA,
	}
	for _, state := range states {
		record.Items = append(record.Items, &inventoryv1.Item{Body: &inventoryv1.Item_Service{
			Service: &inventoryv1.Service{Name: "ssh.service", State: state},
		}})
	}
	return record
}

func inventory(records ...*inventoryv1.Record) *inventoryv1.RecordBatch {
	return &inventoryv1.RecordBatch{BatchId: "batch-inventory", ProtocolVersion: protocol.Version, Records: records}
}

func refusal(field string, record int32) *ingestv1.Rejection {
	return &ingestv1.Rejection{Code: "invalid_record", Detail: field + " is not accepted here", Field: field, EventIndex: record}
}

func TestAPlatformThatDoesNotSpeakTheProtocolIsIncompatible(t *testing.T) {
	refused := &ingestv1.Rejection{Code: "unsupported_protocol_version", Detail: "this gateway speaks protocol 2..3", EventIndex: -1}
	want := protocol.Incompatibility{Field: "protocol_version", Value: "1", Record: -1, Detail: "this gateway speaks protocol 2..3"}

	found, incompatible := protocol.IncompatibleEvents(events(authentication()), refused)
	if !incompatible || *found != want {
		t.Errorf("an event batch refused for its protocol read as %+v, want %+v", found, want)
	}
	found, incompatible = protocol.IncompatibleInventory(inventory(services(inventoryv1.Service_STATE_RUNNING)), refused)
	if !incompatible || *found != want {
		t.Errorf("an inventory batch refused for its protocol read as %+v, want %+v", found, want)
	}
}

func TestARecordSchemaThePlatformDoesNotAcceptIsIncompatible(t *testing.T) {
	newer := authentication()
	newer.SchemaVersion = 2
	found, incompatible := protocol.IncompatibleEvents(events(authentication(), newer), refusal("schema_version", 1))
	if want := (protocol.Incompatibility{Field: "schema_version", Value: "2", Record: 1, Detail: "schema_version is not accepted here"}); !incompatible || *found != want {
		t.Errorf("a refused event schema read as %+v, want %+v", found, want)
	}

	found, incompatible = protocol.IncompatibleInventory(inventory(services()), refusal("schema_version", 0))
	if want := (protocol.Incompatibility{Field: "schema_version", Value: "1", Record: 0, Detail: "schema_version is not accepted here"}); !incompatible || *found != want {
		t.Errorf("a refused inventory schema read as %+v, want %+v", found, want)
	}
}

func TestAValueTheContractsDeclareThatThePlatformRefusesIsIncompatible(t *testing.T) {
	cases := []struct {
		field string
		value string
		read  func(*ingestv1.Rejection) (*protocol.Incompatibility, bool)
	}{
		{"event_class", "EVENT_CLASS_AUTHENTICATION", eventsOf(authentication())},
		{"authentication.activity", "ACTIVITY_LOGOFF", eventsOf(authentication())},
		{"authentication.network.transport", "TRANSPORT_UDP", eventsOf(authentication())},
		{"kind", "KIND_SERVICE", inventoryOf(services())},
		{"mode", "MODE_DELTA", inventoryOf(services())},
		{"items[1].service.state", "STATE_FAILED", inventoryOf(services(inventoryv1.Service_STATE_RUNNING, inventoryv1.Service_STATE_FAILED))},
	}
	for _, c := range cases {
		t.Run(c.field, func(t *testing.T) {
			found, incompatible := c.read(refusal(c.field, 0))
			want := protocol.Incompatibility{Field: c.field, Value: c.value, Record: 0, Detail: c.field + " is not accepted here"}
			if !incompatible || *found != want {
				t.Fatalf("read %+v, want %+v", found, want)
			}
		})
	}
}

func TestARefusalOfWhatTheAgentGotWrongIsNoIncompatibility(t *testing.T) {
	unsetProtocol := events(authentication())
	unsetProtocol.ProtocolVersion = 0
	unsetSchema := authentication()
	unsetSchema.SchemaVersion = 0
	unsetClass := authentication()
	unsetClass.EventClass = eventv1.EventClass_EVENT_CLASS_UNSPECIFIED
	undeclaredClass := authentication()
	undeclaredClass.EventClass = eventv1.EventClass(42)
	undeclaredKind := services()
	undeclaredKind.Kind = inventoryv1.Kind(42)
	unsetMode := services()
	unsetMode.Mode = inventoryv1.Mode_MODE_UNSPECIFIED

	cases := []struct {
		name    string
		read    func(*ingestv1.Rejection) (*protocol.Incompatibility, bool)
		refusal *ingestv1.Rejection
	}{
		{"a protocol version left unset", func(r *ingestv1.Rejection) (*protocol.Incompatibility, bool) {
			return protocol.IncompatibleEvents(unsetProtocol, r)
		}, &ingestv1.Rejection{Code: "unsupported_protocol_version", EventIndex: -1}},
		{"a schema version left unset", eventsOf(unsetSchema), refusal("schema_version", 0)},
		{"an event class left unset", eventsOf(unsetClass), refusal("event_class", 0)},
		{"an event class no contract declares", eventsOf(undeclaredClass), refusal("event_class", 0)},
		{"an inventory kind no contract declares", inventoryOf(undeclaredKind), refusal("kind", 0)},
		{"an inventory mode left unset", inventoryOf(unsetMode), refusal("mode", 0)},
		{"a service state left unset", inventoryOf(services(inventoryv1.Service_STATE_UNSPECIFIED)), refusal("items[0].service.state", 0)},
		{"a field that is not an enum", eventsOf(authentication()), refusal("authentication.user.name", 0)},
		{"a record that is not an enum", eventsOf(authentication()), refusal("authentication", 0)},
		{"a record identifier", eventsOf(authentication()), refusal("event_id", 0)},
		{"an item that carries the wrong body", inventoryOf(services(inventoryv1.Service_STATE_RUNNING)), refusal("items[0]", 0)},
		{"a body the record does not carry", inventoryOf(services(inventoryv1.Service_STATE_RUNNING)), refusal("items[0].network_interface.state", 0)},
		{"a record beyond the batch", eventsOf(authentication()), refusal("event_class", 1)},
		{"a record before the batch", eventsOf(authentication()), refusal("event_class", -2)},
		{"a record missing from the batch", eventsOf(nil), refusal("event_class", 0)},
		{"the batch as a whole", eventsOf(authentication()), refusal("event_class", -1)},
		{"an identifier refused for the batch", eventsOf(authentication()), &ingestv1.Rejection{Code: "malformed_batch_id", Field: "batch_id", EventIndex: -1}},
		{"a batch above the ceiling", eventsOf(authentication()), &ingestv1.Rejection{Code: "batch_too_large", EventIndex: -1}},
		{"an agent the platform no longer admits", eventsOf(authentication()), &ingestv1.Rejection{Code: "agent_not_admitted", EventIndex: -1}},
		{"no refusal at all", eventsOf(authentication()), nil},
		{"no field", eventsOf(authentication()), refusal("", 0)},
		{"a field the contracts do not have", eventsOf(authentication()), refusal("event_severity", 0)},
		{"an empty segment", eventsOf(authentication()), refusal("authentication..activity", 0)},
		{"a trailing dot", eventsOf(authentication()), refusal("event_class.", 0)},
		{"a path through a value", eventsOf(authentication()), refusal("event_class.name", 0)},
		{"a position on a single value", eventsOf(authentication()), refusal("event_class[0]", 0)},
		{"a repeated field without a position", inventoryOf(services(inventoryv1.Service_STATE_RUNNING)), refusal("items.service.state", 0)},
		{"a position beyond the items", inventoryOf(services(inventoryv1.Service_STATE_RUNNING)), refusal("items[1].service.state", 0)},
		{"a negative position", inventoryOf(services(inventoryv1.Service_STATE_RUNNING)), refusal("items[-1].service.state", 0)},
		{"a position that is not a number", inventoryOf(services(inventoryv1.Service_STATE_RUNNING)), refusal("items[first].service.state", 0)},
		{"an unclosed position", inventoryOf(services(inventoryv1.Service_STATE_RUNNING)), refusal("items[0.service.state", 0)},
		{"a position too large to count", inventoryOf(services(inventoryv1.Service_STATE_RUNNING)), refusal("items[99999999999999999999].service.state", 0)},
		{"a path longer than any record", eventsOf(authentication()), refusal(strings.Repeat("authentication.", 64)+"activity", 0)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if found, incompatible := c.read(c.refusal); incompatible || found != nil {
				t.Fatalf("read %+v as an incompatibility", found)
			}
		})
	}
}

func TestAnIncompatibilityNamesWhatThePlatformRefused(t *testing.T) {
	cases := map[string]protocol.Incompatibility{
		"the platform does not accept protocol_version 1: this gateway speaks protocol 2..3": {
			Field: "protocol_version", Value: "1", Record: -1, Detail: "this gateway speaks protocol 2..3",
		},
		"the platform does not accept event_class EVENT_CLASS_AUTHENTICATION in record 0: event_class is unspecified or unknown": {
			Field: "event_class", Value: "EVENT_CLASS_AUTHENTICATION", Record: 0, Detail: "event_class is unspecified or unknown",
		},
	}
	for want, incompatibility := range cases {
		if message := incompatibility.Error(); message != want {
			t.Errorf("reads %q, want %q", message, want)
		}
	}
}

func FuzzAnyRefusalIsReadTheSameWayEveryTime(f *testing.F) {
	f.Add("unsupported_protocol_version", "", int32(-1))
	f.Add("invalid_event", "schema_version", int32(1))
	f.Add("invalid_event", "authentication.network.transport", int32(0))
	f.Add("invalid_record", "items[1].service.state", int32(1))
	f.Add("invalid_record", "items[0].network_interface.addresses[0]", int32(0))
	f.Add("invalid_record", "items[18446744073709551616].service.state", int32(1))
	f.Add("invalid_record", "items[1].service.state.", int32(1))
	f.Add("invalid_record", "items[[1]].service", int32(1))

	batch := events(authentication(), nil, authentication())
	records := inventory(services(), nil, services(inventoryv1.Service_STATE_RUNNING, inventoryv1.Service_State(42)))
	f.Fuzz(func(t *testing.T, code, field string, index int32) {
		refused := &ingestv1.Rejection{Code: code, Detail: "refused", Field: field, EventIndex: index}
		for stream, read := range map[string]func() (*protocol.Incompatibility, bool){
			"events":    func() (*protocol.Incompatibility, bool) { return protocol.IncompatibleEvents(batch, refused) },
			"inventory": func() (*protocol.Incompatibility, bool) { return protocol.IncompatibleInventory(records, refused) },
		} {
			first, incompatible := read()
			again, stillIncompatible := read()
			if incompatible != stillIncompatible || (incompatible && *first != *again) {
				t.Fatalf("%s: the same refusal read as %+v and then as %+v", stream, first, again)
			}
			if incompatible && first.Value == "" {
				t.Fatalf("%s: an incompatibility names no value: %+v", stream, first)
			}
			if incompatible && first.Record != -1 && (first.Record != int(index) || first.Field != field) {
				t.Fatalf("%s: an incompatibility names %s of record %d, the platform refused %s of record %d",
					stream, first.Field, first.Record, field, index)
			}
		}
	})
}

func eventsOf(records ...*eventv1.Event) func(*ingestv1.Rejection) (*protocol.Incompatibility, bool) {
	return func(refused *ingestv1.Rejection) (*protocol.Incompatibility, bool) {
		return protocol.IncompatibleEvents(events(records...), refused)
	}
}

func inventoryOf(records ...*inventoryv1.Record) func(*ingestv1.Rejection) (*protocol.Incompatibility, bool) {
	return func(refused *ingestv1.Rejection) (*protocol.Incompatibility, bool) {
		return protocol.IncompatibleInventory(inventory(records...), refused)
	}
}
