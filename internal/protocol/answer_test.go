package protocol_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-agent-v2/internal/protocol"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
	ingestv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/ingest/v1"
	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
)

var answeredAt = time.Date(2026, time.September, 27, 14, 3, 9, 0, time.UTC)

func sentEvents(t *testing.T, events ...*eventv1.Event) []protocol.Sent {
	t.Helper()
	sent := make([]protocol.Sent, len(events))
	for i, event := range events {
		sent[i] = protocol.Sent{Record: encoded(t, event), Admitted: event.GetTime().GetObservedTime().AsTime()}
	}
	return sent
}

func stamped(event *eventv1.Event, at time.Time) *eventv1.Event {
	event.Time = &eventv1.Timestamps{EventTime: timestamppb.New(at), ObservedTime: timestamppb.New(at)}
	return event
}

func acknowledging(t *testing.T, acknowledgement *ingestv1.BatchAck) protocol.Answer {
	t.Helper()
	return protocol.Answer{Status: 200, ContentType: protocol.ContentType, Body: encoded(t, acknowledgement), Date: answeredAt}
}

func refusing(t *testing.T, status int, code, field string, index int32) protocol.Answer {
	t.Helper()
	body := encoded(t, &ingestv1.Rejection{Code: code, Detail: "as the gateway explains it", Field: field, EventIndex: index})
	return protocol.Answer{Status: status, ContentType: "application/x-protobuf", Body: body, Date: answeredAt}
}

func TestOnlyAnAcknowledgementOfEveryRecordSentIsDurable(t *testing.T) {
	sent := sentEvents(t, numberedEvents(3)...)
	for name, c := range map[string]struct {
		answer protocol.Answer
		want   protocol.Outcome
	}{
		"accepted, durable and every record": {answer: acknowledging(t, &ingestv1.BatchAck{Accepted: true, Durable: true, Received: 3}), want: protocol.Durable},
		"not accepted":                       {answer: acknowledging(t, &ingestv1.BatchAck{Durable: true, Received: 3}), want: protocol.Unconfirmed},
		"accepted and not durable":           {answer: acknowledging(t, &ingestv1.BatchAck{Accepted: true, Received: 3}), want: protocol.Unconfirmed},
		"fewer records than were sent":       {answer: acknowledging(t, &ingestv1.BatchAck{Accepted: true, Durable: true, Received: 2}), want: protocol.Unconfirmed},
		"more records than were sent":        {answer: acknowledging(t, &ingestv1.BatchAck{Accepted: true, Durable: true, Received: 4}), want: protocol.Unconfirmed},
		"nothing at all":                     {answer: protocol.Answer{Status: 200, ContentType: protocol.ContentType}, want: protocol.Unconfirmed},
		"a refusal sent as a success":        {answer: protocol.Answer{Status: 200, ContentType: protocol.ContentType, Body: refusing(t, 422, "invalid_event", "event_id", 0).Body}, want: protocol.Unconfirmed},
		"the other media type the gateway reads": {answer: protocol.Answer{Status: 200, ContentType: "application/protobuf; charset=binary",
			Body: encoded(t, &ingestv1.BatchAck{Accepted: true, Durable: true, Received: 3})}, want: protocol.Durable},
		"a page of text":            {answer: protocol.Answer{Status: 200, ContentType: "text/html", Body: []byte("<html>ok</html>")}, want: protocol.Unexpected},
		"bytes that are no message": {answer: protocol.Answer{Status: 200, ContentType: protocol.ContentType, Body: []byte{0xff}}, want: protocol.Unexpected},
	} {
		t.Run(name, func(t *testing.T) {
			verdict := protocol.Events.Judge(sent, c.answer)
			if verdict.Outcome != c.want || verdict.Record != -1 {
				t.Fatalf("judged %v (record %d, %v), want %v", verdict.Outcome, verdict.Record, verdict.Reason, c.want)
			}
			if (verdict.Reason == nil) != (c.want == protocol.Durable) {
				t.Fatalf("a %v verdict carries the reason %v", verdict.Outcome, verdict.Reason)
			}
			if c.want == protocol.Unexpected && !errors.Is(verdict.Reason, protocol.ErrNoAcknowledgement) {
				t.Fatalf("a success that acknowledges nothing reads as %v", verdict.Reason)
			}
		})
	}
	inventory := []protocol.Sent{{Record: encoded(t, services(inventoryv1.Service_STATE_RUNNING, inventoryv1.Service_STATE_STOPPED))}}
	if verdict := protocol.Inventory.Judge(inventory, acknowledging(t, &ingestv1.BatchAck{Accepted: true, Durable: true, Received: 2})); verdict.Outcome != protocol.Unconfirmed {
		t.Fatalf("an acknowledgement counting the items of one inventory record was judged %v", verdict.Outcome)
	}
}

func TestARefusalOfTheBatchAsAWholeKeepsEveryRecord(t *testing.T) {
	sent := sentEvents(t, numberedEvents(2)...)
	for name, c := range map[string]struct {
		answer protocol.Answer
		want   protocol.Outcome
	}{
		"an agent the certificate does not name": {answer: refusing(t, 403, "unauthenticated_agent", "", -1), want: protocol.AgentRefused},
		"an agent nobody registered":             {answer: refusing(t, 403, "agent_not_registered", "", -1), want: protocol.AgentRefused},
		"an agent no longer admitted":            {answer: refusing(t, 403, "agent_not_admitted", "", -1), want: protocol.AgentRefused},
		"a protocol the platform does not speak": {answer: refusing(t, 426, "unsupported_protocol_version", "", -1), want: protocol.Incompatible},
		"an agent sending too fast":              {answer: refusing(t, 429, "rate_limited", "", -1), want: protocol.Unconfirmed},
		"a gateway holding all it may":           {answer: refusing(t, 503, "gateway_at_capacity", "", -1), want: protocol.Unconfirmed},
		"a backbone that did not take it":        {answer: refusing(t, 503, "backbone_unavailable", "", -1), want: protocol.Unconfirmed},
		"a body the gateway could not read":      {answer: refusing(t, 400, "unreadable_body", "", -1), want: protocol.Unconfirmed},
		"a body above the gateway's ceiling":     {answer: refusing(t, 413, "batch_body_too_large", "", -1), want: protocol.BatchTooLarge},
		"more records than a batch takes":        {answer: refusing(t, 422, "batch_too_large", "", -1), want: protocol.BatchTooLarge},
		"a batch that does not decode":           {answer: refusing(t, 400, "malformed_payload", "", -1), want: protocol.BatchUndecodable},
		"a batch without records":                {answer: refusing(t, 422, "empty_batch", "", -1), want: protocol.Unexpected},
		"a batch identifier refused":             {answer: refusing(t, 422, "malformed_batch_id", "batch_id", -1), want: protocol.Unexpected},
		"a media type refused":                   {answer: refusing(t, 415, "unsupported_media_type", "", -1), want: protocol.Unexpected},
		"a code nobody recorded, as a failure":   {answer: refusing(t, 502, "backbone_on_fire", "", -1), want: protocol.Unconfirmed},
		"a code nobody recorded, as a refusal":   {answer: refusing(t, 422, "record_disliked", "", 0), want: protocol.Unexpected},
		"the other route's record refusal":       {answer: refusing(t, 422, "invalid_record", "kind", 0), want: protocol.Unexpected},
		"a record the batch does not hold":       {answer: refusing(t, 422, "invalid_event", "event_id", 2), want: protocol.Unexpected},
		"no record at all":                       {answer: refusing(t, 422, "invalid_event", "event_id", -1), want: protocol.Unexpected},
		"a proxy that timed out":                 {answer: protocol.Answer{Status: 504, ContentType: "text/html", Body: []byte("gateway timeout")}, want: protocol.Unconfirmed},
		"a proxy with a lower ceiling":           {answer: protocol.Answer{Status: 413, ContentType: "text/html", Body: []byte("too large")}, want: protocol.BatchTooLarge},
		"a listener that is not the gateway":     {answer: protocol.Answer{Status: 404, ContentType: "text/plain", Body: []byte("404 page not found")}, want: protocol.Unexpected},
		"a request that took too long":           {answer: protocol.Answer{Status: 408}, want: protocol.Unconfirmed},
	} {
		t.Run(name, func(t *testing.T) {
			verdict := protocol.Events.Judge(sent, c.answer)
			if verdict.Outcome != c.want || verdict.Record != -1 || verdict.Reason == nil {
				t.Fatalf("judged %v (record %d, %v), want %v about the whole batch", verdict.Outcome, verdict.Record, verdict.Reason, c.want)
			}
		})
	}

	var exclusion *protocol.Exclusion
	if verdict := protocol.Events.Judge(sent, refusing(t, 403, "agent_not_admitted", "", -1)); !errors.As(verdict.Reason, &exclusion) || exclusion.Reason != protocol.Unadmitted {
		t.Fatalf("a refusal of the agent reads as %v", verdict.Reason)
	}
	var incompatibility *protocol.Incompatibility
	if verdict := protocol.Events.Judge(sent, refusing(t, 426, "unsupported_protocol_version", "", -1)); !errors.As(verdict.Reason, &incompatibility) ||
		*incompatibility != (protocol.Incompatibility{Field: "protocol_version", Value: "1", Record: -1, Detail: "as the gateway explains it"}) {
		t.Fatalf("a refused protocol reads as %v", verdict.Reason)
	}
}

func TestARecordRefusedForWhatItHoldsIsRefusedForGood(t *testing.T) {
	events := numberedEvents(3)
	sent := sentEvents(t, events...)
	verdict := protocol.Events.Judge(sent, refusing(t, 422, "invalid_event", "origin.host.ip", 1))
	var said *protocol.Refusal
	if verdict.Outcome != protocol.RecordRefused || verdict.Record != 1 || !errors.As(verdict.Reason, &said) {
		t.Fatalf("judged %v (record %d, %v)", verdict.Outcome, verdict.Record, verdict.Reason)
	}
	if *said != (protocol.Refusal{Status: 422, Code: "invalid_event", Field: "origin.host.ip", Record: 1, Detail: "as the gateway explains it"}) {
		t.Fatalf("the refusal reads as %+v", *said)
	}
	unreadable := append(sent[:1:1], protocol.Sent{Record: []byte{0x0a, 0x02, 'i', 'd', 0x1a, 0x01}})
	if verdict := protocol.Events.Judge(unreadable, refusing(t, 422, "invalid_event", "event_class", 1)); verdict.Outcome != protocol.RecordRefused || verdict.Record != 1 {
		t.Fatalf("a record the platform read and the agent cannot was judged %v", verdict.Outcome)
	}
}

func TestARecordCarryingWhatThePlatformDoesNotSpeakIsIncompatible(t *testing.T) {
	event := authentication()
	newer := authentication()
	newer.SchemaVersion = protocol.EventSchemaVersion + 1
	sent := sentEvents(t, event, newer)
	for field, index := range map[string]int32{"authentication.network.transport": 0, "schema_version": 1} {
		verdict := protocol.Events.Judge(sent, refusing(t, 422, "invalid_event", field, index))
		var incompatibility *protocol.Incompatibility
		if verdict.Outcome != protocol.Incompatible || verdict.Record != int(index) || !errors.As(verdict.Reason, &incompatibility) || incompatibility.Field != field {
			t.Fatalf("a refusal of %s judged %v (record %d, %v)", field, verdict.Outcome, verdict.Record, verdict.Reason)
		}
	}
	record := protocol.Sent{Record: encoded(t, services(inventoryv1.Service_STATE_RUNNING, inventoryv1.Service_STATE_FAILED))}
	verdict := protocol.Inventory.Judge([]protocol.Sent{record}, refusing(t, 422, "invalid_record", "items[1].service.state", 0))
	if verdict.Outcome != protocol.Incompatible || verdict.Record != 0 {
		t.Fatalf("a record holding a service state the platform lacks was judged %v", verdict.Outcome)
	}
}

func TestARecordRefusedForAMomentThePlatformHasNotReachedWaitsForTheClocksToAgree(t *testing.T) {
	for name, c := range map[string]struct {
		at       time.Time
		admitted time.Time
		date     time.Time
		want     protocol.Outcome
	}{
		"a host whose clock runs ahead of the platform's": {
			at: answeredAt.Add(9 * time.Minute), admitted: answeredAt.Add(9 * time.Minute), date: answeredAt, want: protocol.Disputed,
		},
		"a platform that did not say what its clock read": {
			at: answeredAt.Add(-30 * 24 * time.Hour), admitted: answeredAt.Add(-30 * 24 * time.Hour), want: protocol.Disputed,
		},
		"a platform that did not say, and a record older than it admits when it was admitted": {
			at: answeredAt.Add(-30 * 24 * time.Hour), admitted: answeredAt, want: protocol.RecordRefused,
		},
		"a moment the platform's clock has passed": {
			at: answeredAt.Add(-8 * 24 * time.Hour), admitted: answeredAt.Add(-8 * 24 * time.Hour), date: answeredAt, want: protocol.RecordRefused,
		},
		"a moment later than the agent admitted the record at": {
			at: answeredAt.Add(365 * 24 * time.Hour), admitted: answeredAt, date: answeredAt, want: protocol.RecordRefused,
		},
		"a moment within the skew the platform allows": {
			at: answeredAt.Add(4 * time.Minute), admitted: answeredAt, date: answeredAt, want: protocol.Disputed,
		},
	} {
		t.Run(name, func(t *testing.T) {
			event := stamped(authentication(), c.at)
			sent := []protocol.Sent{{Record: encoded(t, event), Admitted: c.admitted}}
			answer := refusing(t, 422, "invalid_event", "time.event_time", 0)
			answer.Date = c.date
			verdict := protocol.Events.Judge(sent, answer)
			if verdict.Outcome != c.want || verdict.Record != 0 {
				t.Fatalf("judged %v (record %d, %v), want %v", verdict.Outcome, verdict.Record, verdict.Reason, c.want)
			}
			var dispute *protocol.Dispute
			if c.want == protocol.Disputed && (!errors.As(verdict.Reason, &dispute) || !dispute.At.Equal(c.at) || dispute.Field != "time.event_time") {
				t.Fatalf("the dispute reads as %v", verdict.Reason)
			}
		})
	}

	untimed := authentication()
	sent := []protocol.Sent{{Record: encoded(t, untimed), Admitted: answeredAt}}
	if verdict := protocol.Events.Judge(sent, refusing(t, 422, "invalid_event", "time", 0)); verdict.Outcome != protocol.RecordRefused {
		t.Fatalf("an event without its times was judged %v", verdict.Outcome)
	}
	if verdict := protocol.Events.Judge(sent, refusing(t, 422, "invalid_event", "time.observed_time", 0)); verdict.Outcome != protocol.RecordRefused {
		t.Fatalf("an event without the time the platform refused was judged %v", verdict.Outcome)
	}

	record := services()
	record.CollectedAt = timestamppb.New(answeredAt.Add(20 * time.Minute))
	collected := []protocol.Sent{{Record: encoded(t, record), Admitted: answeredAt.Add(20 * time.Minute)}}
	if verdict := protocol.Inventory.Judge(collected, refusing(t, 422, "invalid_record", "collected_at", 0)); verdict.Outcome != protocol.Disputed {
		t.Fatalf("inventory collected by a clock ahead of the platform's was judged %v", verdict.Outcome)
	}
}

func TestWhatThePlatformSaysIsBoundedWhereTheAgentRepeatsIt(t *testing.T) {
	sent := sentEvents(t, numberedEvents(1)...)
	long := strings.Repeat("the platform explains at length ", 400)
	for _, answer := range []protocol.Answer{
		{Status: 422, ContentType: protocol.ContentType, Body: encoded(t, &ingestv1.Rejection{Code: long, Detail: long, Field: long, EventIndex: 0})},
		{Status: 403, ContentType: protocol.ContentType, Body: encoded(t, &ingestv1.Rejection{Code: "agent_not_admitted", Detail: long, EventIndex: -1})},
		{Status: 426, ContentType: protocol.ContentType, Body: encoded(t, &ingestv1.Rejection{Code: "unsupported_protocol_version", Detail: long, EventIndex: -1})},
		{Status: 422, ContentType: protocol.ContentType, Body: encoded(t, &ingestv1.Rejection{Code: "invalid_event", Detail: long, Field: "event_id", EventIndex: 0})},
	} {
		verdict := protocol.Events.Judge(sent, answer)
		if said := verdict.Reason.Error(); len(said) > 512 {
			t.Errorf("a %v verdict repeats %d bytes of what the platform said", verdict.Outcome, len(said))
		}
	}
}

func TestEveryOutcomeHasAName(t *testing.T) {
	for outcome := protocol.Durable; outcome <= protocol.Unexpected; outcome++ {
		if name := outcome.String(); strings.HasPrefix(name, "outcome(") || strings.ContainsAny(name, " -") {
			t.Errorf("outcome %d is called %q", int(outcome), name)
		}
	}
}
