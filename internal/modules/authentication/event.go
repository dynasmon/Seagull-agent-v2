package authentication

import (
	"crypto/sha256"
	"fmt"
	"runtime"
	"slices"
	"strconv"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-agent-v2/internal/platform/journal"
	"github.com/dynasmon/Seagull-agent-v2/internal/protocol"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

const (
	Name        = "authentication"
	maxRaw      = 4096
	maxHostname = 255
	invalidUser = "invalid user"
	superuser   = "0"
)

var (
	commands = []string{"sshd", "sshd-session"}
	query    = journal.Query{
		Matches: []journal.Match{{Field: "_COMM", Value: commands[0]}, {Field: "_COMM", Value: commands[1]}, {Field: "_UID", Value: superuser}},
		Fields:  []string{"MESSAGE", "_COMM", "_UID", "_HOSTNAME", "_SOURCE_REALTIME_TIMESTAMP"},
	}
)

type observation int

const (
	unrelated observation = iota + 1
	aged
	observed
)

// An entry is an outcome only when journald says the process that wrote it was
// sshd running as the superuser: anyone may hand journald a line that names
// sshd, and only those two fields are journald's own. Each outcome becomes an
// event named by the installation and the entry, so an entry read again is the
// same event, byte for byte.
func observe(installation string, entry journal.Entry, now time.Time) ([]byte, string, observation) {
	comm, message := entry.Fields["_COMM"], entry.Fields["MESSAGE"]
	if entry.Fields["_UID"] != superuser || !slices.Contains(commands, comm) {
		return nil, "", unrelated
	}
	found, ok := parse(message)
	if !ok {
		return nil, "", unrelated
	}
	happened := entry.Realtime
	if micros, err := strconv.ParseInt(entry.Fields["_SOURCE_REALTIME_TIMESTAMP"], 10, 64); err == nil && micros > 0 {
		happened = time.UnixMicro(micros).UTC()
	}
	if oldest := now.Add(-protocol.MaxEventAge); happened.Before(oldest) || entry.Realtime.Before(oldest) {
		return nil, "", aged
	}
	outcome := eventv1.Outcome_OUTCOME_FAILURE
	if found.accepted {
		outcome = eventv1.Outcome_OUTCOME_SUCCESS
	}
	body := &eventv1.Authentication{
		Activity:  eventv1.Authentication_ACTIVITY_LOGON,
		Outcome:   outcome,
		Method:    found.method,
		Service:   &eventv1.Service{Name: commands[0], Protocol: "ssh"},
		Network:   &eventv1.Network{Transport: eventv1.Transport_TRANSPORT_TCP},
		RawRecord: bounded(message, maxRaw),
	}
	if found.invalid {
		body.OutcomeReason = invalidUser
	}
	if found.user != "" {
		body.User = &eventv1.User{Name: found.user}
	}
	if found.address.IsValid() {
		body.Network.Source = &eventv1.Endpoint{Ip: found.address.String(), Port: found.port}
	}
	id := identify(installation, entry.Cursor)
	event := &eventv1.Event{
		EventId:       id,
		SchemaVersion: protocol.EventSchemaVersion,
		EventClass:    eventv1.EventClass_EVENT_CLASS_AUTHENTICATION,
		Time:          &eventv1.Timestamps{EventTime: timestamppb.New(happened), ObservedTime: timestamppb.New(entry.Realtime)},
		Origin:        &eventv1.Origin{Host: &eventv1.Host{Hostname: bounded(entry.Fields["_HOSTNAME"], maxHostname), Os: "linux", Architecture: runtime.GOARCH}},
		Collection:    &eventv1.Collection{Collector: Name, Source: "journal:" + comm},
		Body:          &eventv1.Event_Authentication{Authentication: body},
	}
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(event)
	if err != nil {
		return nil, "", unrelated
	}
	return payload, id, observed
}

func identify(installation, cursor string) string {
	sum := sha256.Sum256([]byte("seagull-agent/" + Name + "\x00" + installation + "\x00" + cursor))
	sum[6] = sum[6]&0x0f | 0x80
	sum[8] = sum[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", sum[0:4], sum[4:6], sum[6:8], sum[8:10], sum[10:16])
}
