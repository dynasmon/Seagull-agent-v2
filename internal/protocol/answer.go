package protocol

import (
	"errors"
	"fmt"
	"mime"
	"slices"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-agent-v2/internal/secrets"
	ingestv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/ingest/v1"
)

type Outcome int

const (
	Durable Outcome = iota + 1
	Unconfirmed
	RecordRefused
	BatchTooLarge
	BatchUndecodable
	AgentRefused
	Incompatible
	Disputed
	Unexpected
)

func (o Outcome) String() string {
	switch o {
	case Durable:
		return "durable"
	case Unconfirmed:
		return "unconfirmed"
	case RecordRefused:
		return "record_refused"
	case BatchTooLarge:
		return "batch_too_large"
	case BatchUndecodable:
		return "batch_undecodable"
	case AgentRefused:
		return "agent_refused"
	case Incompatible:
		return "incompatible"
	case Disputed:
		return "disputed"
	case Unexpected:
		return "unexpected"
	default:
		return fmt.Sprintf("outcome(%d)", int(o))
	}
}

const (
	statusOK              = 200
	statusRequestTimeout  = 408
	statusTooLarge        = 413
	statusTooManyRequests = 429
	statusServerError     = 500
)

// What the recorded gateway refuses a batch with when it could not take the
// batch then, when the batch is larger than it takes, and when it could not
// decode the batch at all. None of them refuses a record for what it holds.
var (
	unavailable = []string{"rate_limited", "gateway_at_capacity", "backbone_unavailable", "unreadable_body"}
	oversized   = []string{"batch_body_too_large", "batch_too_large"}
	undecodable = "malformed_payload"
)

var ErrNoAcknowledgement = errors.New("the platform answered with success and no acknowledgement the agent reads")

type Answer struct {
	Status      int
	ContentType string
	Body        []byte
	Date        time.Time
}

type Sent struct {
	Record   []byte
	Admitted time.Time
}

// A Verdict is what an answer lets the agent do with the batch it answered.
// Only a durable one lets it drop the records, and only a refused record is
// the platform's final word on that record; everything else leaves the batch
// to be sent again, now or once whatever held it back has changed.
type Verdict struct {
	Outcome Outcome
	Record  int
	Reason  error
}

type Refusal struct {
	Status int
	Code   string
	Field  string
	Record int
	Detail string
}

func (r *Refusal) Error() string {
	said := fmt.Sprintf("the platform answered %d", r.Status)
	if r.Code != "" {
		said += " " + r.Code
	}
	if r.Record >= 0 && r.Field != "" {
		said += fmt.Sprintf(" about %s of record %d", r.Field, r.Record)
	}
	if r.Detail != "" {
		said += ": " + r.Detail
	}
	return said
}

type Dispute struct {
	Field    string
	Record   int
	At       time.Time
	Platform time.Time
	Detail   string
}

func (d *Dispute) Error() string {
	clock := "a clock it did not name"
	if !d.Platform.IsZero() {
		clock = "its clock at " + d.Platform.UTC().Format(time.RFC3339)
	}
	return fmt.Sprintf("the platform refuses %s of record %d, %s, which the agent's clock admitted and %s has not reached: %s",
		d.Field, d.Record, d.At.UTC().Format(time.RFC3339Nano), clock, d.Detail)
}

func (r Route) Judge(sent []Sent, answer Answer) Verdict {
	if answer.Status == statusOK {
		return acknowledged(len(sent), answer)
	}
	said := &Refusal{Status: answer.Status, Record: -1}
	refusal, read := refusalIn(answer)
	if !read {
		switch {
		case answer.Status == statusTooLarge:
			return Verdict{Outcome: BatchTooLarge, Record: -1, Reason: said}
		case passing(answer.Status):
			return Verdict{Outcome: Unconfirmed, Record: -1, Reason: said}
		}
		return Verdict{Outcome: Unexpected, Record: -1, Reason: said}
	}
	said.Code, said.Field, said.Detail = secrets.Bounded(refusal.GetCode()), secrets.Bounded(refusal.GetField()), secrets.Bounded(refusal.GetDetail())
	if exclusion, excluded := Excluded(refusal); excluded {
		exclusion.Detail = said.Detail
		return Verdict{Outcome: AgentRefused, Record: -1, Reason: exclusion}
	}
	switch code := refusal.GetCode(); {
	case code == unsupportedProtocol:
		return Verdict{Outcome: Incompatible, Record: -1, Reason: &Incompatibility{
			Field: "protocol_version", Value: strconv.Itoa(Version), Record: -1, Detail: said.Detail}}
	case slices.Contains(unavailable, code):
		return Verdict{Outcome: Unconfirmed, Record: -1, Reason: said}
	case slices.Contains(oversized, code):
		return Verdict{Outcome: BatchTooLarge, Record: -1, Reason: said}
	case code == undecodable:
		return Verdict{Outcome: BatchUndecodable, Record: -1, Reason: said}
	case code == r.shape().refusing:
		return r.refused(sent, refusal, said, answer.Date)
	case passing(answer.Status):
		return Verdict{Outcome: Unconfirmed, Record: -1, Reason: said}
	}
	return Verdict{Outcome: Unexpected, Record: -1, Reason: said}
}

func acknowledged(sent int, answer Answer) Verdict {
	if !protobuf(answer.ContentType) {
		return Verdict{Outcome: Unexpected, Record: -1, Reason: fmt.Errorf("%w: it answered %d with %s", ErrNoAcknowledgement, answer.Status, secrets.Shown(answer.ContentType))}
	}
	var acknowledgement ingestv1.BatchAck
	if err := proto.Unmarshal(answer.Body, &acknowledgement); err != nil {
		return Verdict{Outcome: Unexpected, Record: -1, Reason: fmt.Errorf("%w: %s", ErrNoAcknowledgement, secrets.Bounded(err.Error()))}
	}
	var missing string
	switch {
	case !acknowledgement.GetAccepted():
		missing = "did not accept it"
	case !acknowledgement.GetDurable():
		missing = "accepted it without making it durable"
	case int64(acknowledgement.GetReceived()) != int64(sent):
		missing = fmt.Sprintf("acknowledged %d records of the %d it carried", acknowledgement.GetReceived(), sent)
	default:
		return Verdict{Outcome: Durable, Record: -1}
	}
	return Verdict{Outcome: Unconfirmed, Record: -1, Reason: fmt.Errorf("the platform answered the batch and %s", missing)}
}

// A refused record is refused for good unless the platform does not speak what
// it carries yet, or refuses one of its times as a moment its clock has not
// reached although the agent's clock had when it admitted the record: then the
// two clocks disagree, and the record is as valid as it was. A platform that
// does not say what its clock reads is taken to have passed a moment older
// than it admits records for, counted from when the agent admitted the record.
func (r Route) refused(sent []Sent, refusal *ingestv1.Rejection, said *Refusal, date time.Time) Verdict {
	index := int(refusal.GetEventIndex())
	if index < 0 || index >= len(sent) {
		return Verdict{Outcome: Unexpected, Record: -1, Reason: said}
	}
	said.Record = index
	record := r.shape().record()
	if err := proto.Unmarshal(sent[index].Record, record); err != nil {
		return Verdict{Outcome: RecordRefused, Record: index, Reason: said}
	}
	if incompatibility, unspoken := unspoken(record.ProtoReflect(), index, refusal); unspoken {
		incompatibility.Detail = said.Detail
		return Verdict{Outcome: Incompatible, Record: index, Reason: incompatibility}
	}
	at, timed := instant(record.ProtoReflect(), refusal.GetField())
	admitted := sent[index].Admitted
	switch {
	case !timed,
		at.After(admitted.Add(MaxClockSkew)),
		!date.IsZero() && !at.After(date),
		date.IsZero() && at.Before(admitted.Add(-r.shape().maxAge)):
		return Verdict{Outcome: RecordRefused, Record: index, Reason: said}
	}
	return Verdict{Outcome: Disputed, Record: index, Reason: &Dispute{Field: said.Field, Record: index, At: at, Platform: date, Detail: said.Detail}}
}

func instant(record protoreflect.Message, path string) (time.Time, bool) {
	if !record.IsValid() || len(path) > maxFieldPath {
		return time.Time{}, false
	}
	message := record
	for {
		segment, rest, nested := strings.Cut(path, ".")
		field, value, found := element(message, segment)
		if !found || field.Kind() != protoreflect.MessageKind || !value.Message().IsValid() {
			return time.Time{}, false
		}
		if nested {
			message, path = value.Message(), rest
			continue
		}
		held, stamped := value.Message().Interface().(*timestamppb.Timestamp)
		if !stamped || held.CheckValid() != nil {
			return time.Time{}, false
		}
		return held.AsTime(), true
	}
}

func refusalIn(answer Answer) (*ingestv1.Rejection, bool) {
	var refusal ingestv1.Rejection
	if !protobuf(answer.ContentType) || proto.Unmarshal(answer.Body, &refusal) != nil || refusal.GetCode() == "" {
		return nil, false
	}
	return &refusal, true
}

func protobuf(contentType string) bool {
	media, _, err := mime.ParseMediaType(contentType)
	return err == nil && (media == ContentType || media == "application/protobuf")
}

func passing(status int) bool {
	return status == statusRequestTimeout || status == statusTooManyRequests || status >= statusServerError
}
