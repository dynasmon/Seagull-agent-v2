package delivery_test

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-agent-v2/internal/delivery"
	"github.com/dynasmon/Seagull-agent-v2/internal/protocol"
	"github.com/dynasmon/Seagull-agent-v2/internal/spool"
	ingestv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/ingest/v1"
	inventoryv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/inventory/v1"
)

func TestEveryRecordIsDeliveredInBoundedBatchesAndSettledOnceAcknowledged(t *testing.T) {
	serving := emulate(t)
	held := spoolIn(t, spoolDirectory(t))
	events := admitEvents(t, held, "event", 2500)
	inventory := admitInventory(t, held, "snapshot", 120, 400)
	deliver(t, held, serving, enrolled(t, serving), func(s *setup) { s.batching.MaxBytes = 64 << 10 })

	eventually(t, "delivering every record", func() bool {
		return outstanding(held, spool.Events).Outstanding == 0 && outstanding(held, spool.Inventory).Outstanding == 0
	})
	if stored := serving.storedIDs(protocol.Events); !slices.Equal(stored, events) {
		t.Fatalf("the platform stores %d events, and %d were admitted", len(stored), len(events))
	}
	if stored := serving.storedIDs(protocol.Inventory); !slices.Equal(stored, inventory) {
		t.Fatalf("the platform stores %d inventory records, and %d were admitted", len(stored), len(inventory))
	}
	seen := map[string]bool{}
	for _, arrived := range serving.received() {
		if seen[arrived.id] || arrived.attempt != 1 {
			t.Fatalf("batch %s arrived again although the platform acknowledged it", arrived.id)
		}
		seen[arrived.id] = true
		if len(arrived.body) > 64<<10 {
			t.Errorf("a batch of %d bytes was sent, and a batch takes 64KiB", len(arrived.body))
		}
		switch arrived.route {
		case protocol.Events:
			if len(arrived.ids) > 1000 {
				t.Errorf("a batch carried %d events", len(arrived.ids))
			}
		case protocol.Inventory:
			var batch inventoryv1.RecordBatch
			if err := proto.Unmarshal(arrived.body, &batch); err != nil {
				t.Fatalf("decode an inventory batch: %v", err)
			}
			items := 0
			for _, record := range batch.GetRecords() {
				items += len(record.GetItems())
			}
			if len(arrived.ids) > 64 || items > protocol.MaxInventoryItemsPerBatch {
				t.Errorf("a batch carried %d inventory records and %d items", len(arrived.ids), items)
			}
		}
	}
	for _, id := range events {
		if published := serving.publications(protocol.Events, id); published != 1 {
			t.Fatalf("event %s was published %d times", id, published)
		}
	}
	if kept := outstanding(held, spool.Events); kept.Delivered != 2500 || kept.Quarantined != 0 {
		t.Fatalf("the spool counts %+v", kept)
	}
	if kept := outstanding(held, spool.Inventory); kept.Delivered != 120 || kept.Quarantined != 0 {
		t.Fatalf("the spool counts %+v", kept)
	}
}

func TestABatchIsSentAgainAsItWasUntilThePlatformAcknowledgesItDurably(t *testing.T) {
	serving := emulate(t)
	held := spoolIn(t, spoolDirectory(t))
	ids := admitEvents(t, held, "event", 10)
	var mu sync.Mutex
	var reclaimed []int
	serving.set(func(w http.ResponseWriter, arrived *received) bool {
		mu.Lock()
		reclaimed = append(reclaimed, int(outstanding(held, spool.Events).Delivered))
		mu.Unlock()
		switch arrived.attempt {
		case 1:
			serving.publish(arrived, 4)
			refuse(w, http.StatusServiceUnavailable, "backbone_unavailable", "", -1)
		case 2:
			acknowledge(w, &ingestv1.BatchAck{Accepted: true, Received: 10})
		case 3:
			acknowledge(w, &ingestv1.BatchAck{Accepted: true, Durable: true, Received: 9})
		case 4:
			acknowledge(w, &ingestv1.BatchAck{Durable: true, Received: 10})
		case 5:
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte("accepted"))
		case 6:
			serving.publish(arrived, len(arrived.ids))
			hijacked, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				hijacked.Close()
			}
		default:
			return false
		}
		return true
	})
	running := deliver(t, held, serving, enrolled(t, serving), nil)

	eventually(t, "delivering the batch", func() bool { return outstanding(held, spool.Events).Outstanding == 0 })
	arrivals := serving.received()
	if len(arrivals) != 7 {
		t.Fatalf("the platform received %d batches", len(arrivals))
	}
	for i, arrived := range arrivals {
		if arrived.id != arrivals[0].id || !bytes.Equal(arrived.body, arrivals[0].body) || arrived.attempt != i+1 {
			t.Fatalf("attempt %d sent batch %s of %d bytes, and the first sent batch %s of %d bytes", i+1, arrived.id, len(arrived.body), arrivals[0].id, len(arrivals[0].body))
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if !slices.Equal(reclaimed, []int{0, 0, 0, 0, 0, 0, 0}) {
		t.Fatalf("the spool had delivered %v records as each attempt arrived", reclaimed)
	}
	if stored := serving.storedIDs(protocol.Events); !slices.Equal(stored, ids) || len(serving.conflicting()) != 0 {
		t.Fatalf("the platform stores %v with conflicts %v", stored, serving.conflicting())
	}
	for i, id := range ids {
		want := 2
		if i < 4 {
			want = 3
		}
		if published := serving.publications(protocol.Events, id); published != want {
			t.Errorf("event %s was published %d times, want %d", id, published, want)
		}
	}
	failures := running.logs.entries(t, "delivery_failed")
	if len(failures) != 6 {
		t.Fatalf("logged %d failed deliveries:\n%s", len(failures), running.logs)
	}
	levels := map[string]string{"unconfirmed": "WARN", "unexpected": "ERROR"}
	for _, failure := range failures {
		if failure["level"] != levels[failure["outcome"].(string)] || failure["batch_id"] != arrivals[0].id || failure["records"] != float64(10) {
			t.Errorf("logged %v", failure)
		}
	}
	eventually(t, "reporting that the delivery resumed", func() bool { return len(running.logs.entries(t, "delivery_resumed")) > 0 })
	if resumed := running.logs.entries(t, "delivery_resumed"); len(resumed) != 1 || resumed[0]["attempts"] != float64(6) {
		t.Errorf("logged %v as the delivery resumed", resumed)
	}
}

func TestARecordThePlatformRefusesForGoodIsQuarantinedAndTheRestDelivered(t *testing.T) {
	serving := emulate(t)
	held := spoolIn(t, spoolDirectory(t))
	ids := admitEvents(t, held, "event", 20)
	refused := []string{"event-000007", "event-000013"}
	var mu sync.Mutex
	refusedIn := map[string]string{}
	serving.set(func(w http.ResponseWriter, arrived *received) bool {
		for i, id := range arrived.ids {
			if slices.Contains(refused, id) {
				mu.Lock()
				refusedIn[id] = arrived.id
				mu.Unlock()
				refuse(w, http.StatusUnprocessableEntity, "invalid_event", "origin.host.ip", i)
				return true
			}
		}
		return false
	})
	running := deliver(t, held, serving, enrolled(t, serving), nil)

	eventually(t, "settling every record", func() bool { return outstanding(held, spool.Events).Outstanding == 0 })
	want := slices.DeleteFunc(slices.Clone(ids), func(id string) bool { return slices.Contains(refused, id) })
	if stored := serving.storedIDs(protocol.Events); !slices.Equal(stored, want) {
		t.Fatalf("the platform stores %v", stored)
	}
	if kept := outstanding(held, spool.Events); kept.Delivered != 18 || kept.Quarantined != 2 {
		t.Fatalf("the spool counts %+v", kept)
	}
	batches := map[string]bool{}
	after := map[string]bool{}
	mu.Lock()
	defer mu.Unlock()
	for _, arrived := range serving.received() {
		if batches[arrived.id] {
			t.Errorf("batch %s arrived twice although nothing failed", arrived.id)
		}
		batches[arrived.id] = true
		for _, id := range arrived.ids {
			if after[id] {
				t.Errorf("record %s was sent in batch %s after the platform refused it", id, arrived.id)
			}
		}
		for id, batch := range refusedIn {
			if batch == arrived.id {
				after[id] = true
			}
		}
	}
	if len(after) != len(refused) {
		t.Fatalf("the platform refused %v", refusedIn)
	}
	for _, id := range want {
		if published := serving.publications(protocol.Events, id); published != 1 {
			t.Errorf("event %s was published %d times", id, published)
		}
	}
	quarantined := running.logs.entries(t, "record_refused")
	if len(quarantined) != 2 || quarantined[0]["record_id"] != `"event-000007"` || !strings.Contains(quarantined[0]["error"].(string), "invalid_event") {
		t.Fatalf("logged %v", quarantined)
	}
}

func TestABatchLargerThanThePlatformTakesIsSplitAndARecordLargerIsQuarantined(t *testing.T) {
	serving := emulate(t)
	held := spoolIn(t, spoolDirectory(t))
	ids := admitEvents(t, held, "event", 40)
	large := event("event-large", time.Now())
	large.GetAuthentication().RawRecord = strings.Repeat("x", 12<<10)
	if _, err := held.Admit(spool.Events, spool.Record{ID: "event-large", Payload: marshal(t, large)}); err != nil {
		t.Fatalf("admit a large event: %v", err)
	}
	serving.set(func(w http.ResponseWriter, arrived *received) bool {
		if len(arrived.body) > 8<<10 {
			refuse(w, http.StatusRequestEntityTooLarge, "batch_body_too_large", "", -1)
			return true
		}
		return false
	})
	running := deliver(t, held, serving, enrolled(t, serving), nil)

	eventually(t, "settling every record", func() bool { return outstanding(held, spool.Events).Outstanding == 0 })
	if stored := serving.storedIDs(protocol.Events); !slices.Equal(stored, ids) {
		t.Fatalf("the platform stores %v", stored)
	}
	if kept := outstanding(held, spool.Events); kept.Delivered != 40 || kept.Quarantined != 1 {
		t.Fatalf("the spool counts %+v", kept)
	}
	if split := running.logs.entries(t, "batch_split"); len(split) == 0 || split[0]["outcome"] != "batch_too_large" {
		t.Fatalf("logged %v as the batch was refused for its size", split)
	}
}

func TestABatchThePlatformCannotDecodeIsNarrowedDownToTheRecordItCannot(t *testing.T) {
	serving := emulate(t)
	held := spoolIn(t, spoolDirectory(t))
	ids := admitEvents(t, held, "event", 11)
	host := protowire.AppendString(protowire.AppendTag(nil, 1, protowire.BytesType), "\xff\xfe")
	origin := protowire.AppendBytes(protowire.AppendTag(nil, 3, protowire.BytesType), host)
	undecodable := protowire.AppendBytes(protowire.AppendTag(marshal(t, event("event-undecodable", time.Now())), 5, protowire.BytesType), origin)
	if _, err := held.Admit(spool.Events, spool.Record{ID: "event-undecodable", Payload: undecodable}); err != nil {
		t.Fatalf("admit an event the platform cannot decode: %v", err)
	}
	more := admitEvents(t, held, "later", 4)
	deliver(t, held, serving, enrolled(t, serving), nil)

	eventually(t, "settling every record", func() bool { return outstanding(held, spool.Events).Outstanding == 0 })
	if stored := serving.storedIDs(protocol.Events); !slices.Equal(stored, append(slices.Clone(ids), more...)) {
		t.Fatalf("the platform stores %v", stored)
	}
	if kept := outstanding(held, spool.Events); kept.Delivered != 15 || kept.Quarantined != 1 {
		t.Fatalf("the spool counts %+v", kept)
	}
}

func TestARefusalThatNeedsSomebodyToActKeepsEveryRecordUntilThePlatformTakesThem(t *testing.T) {
	cases := map[string]struct {
		refuse  func(w http.ResponseWriter)
		at      time.Duration
		outcome string
	}{
		"an agent the platform no longer admits": {
			refuse: func(w http.ResponseWriter) { refuse(w, http.StatusForbidden, "agent_not_admitted", "", -1) }, outcome: "agent_refused",
		},
		"a protocol the platform does not speak": {
			refuse: func(w http.ResponseWriter) {
				refuse(w, http.StatusUpgradeRequired, "unsupported_protocol_version", "", -1)
			}, outcome: "incompatible",
		},
		"a schema the platform does not speak": {
			refuse: func(w http.ResponseWriter) {
				refuse(w, http.StatusUnprocessableEntity, "invalid_event", "schema_version", 0)
			}, outcome: "incompatible",
		},
		"a moment the platform's clock has not reached": {
			refuse: func(w http.ResponseWriter) {
				refuse(w, http.StatusUnprocessableEntity, "invalid_event", "time.event_time", 0)
			},
			at: 3 * time.Minute, outcome: "disputed",
		},
		"a listener that is not the gateway": {
			refuse: func(w http.ResponseWriter) { http.NotFound(w, nil) }, outcome: "unexpected",
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			serving := emulate(t)
			held := spoolIn(t, spoolDirectory(t))
			id := "event-000000"
			if _, err := held.Admit(spool.Events, spool.Record{ID: id, Payload: marshal(t, event(id, time.Now().Add(c.at)))}); err != nil {
				t.Fatalf("admit an event: %v", err)
			}
			serving.set(func(w http.ResponseWriter, arrived *received) bool {
				if arrived.attempt > 3 {
					return false
				}
				c.refuse(w)
				return true
			})
			running := deliver(t, held, serving, enrolled(t, serving), nil)

			eventually(t, "delivering the event", func() bool { return outstanding(held, spool.Events).Outstanding == 0 })
			if kept := outstanding(held, spool.Events); kept.Delivered != 1 || kept.Quarantined != 0 {
				t.Fatalf("the spool counts %+v", kept)
			}
			failures := running.logs.entries(t, "delivery_failed")
			if len(failures) != 3 {
				t.Fatalf("logged %d failed deliveries", len(failures))
			}
			for _, failure := range failures {
				if failure["level"] != "ERROR" || failure["outcome"] != c.outcome || !strings.HasPrefix(failure["recovery"].(string), "recover from ") {
					t.Fatalf("logged %v", failure)
				}
			}
			for _, arrived := range serving.received() {
				if arrived.id != serving.received()[0].id {
					t.Fatalf("the platform received batch %s after batch %s, and nothing split it", arrived.id, serving.received()[0].id)
				}
			}
		})
	}
}

func TestARecordTheAgentCannotReadIsQuarantinedWithoutBeingSent(t *testing.T) {
	serving := emulate(t)
	held := spoolIn(t, spoolDirectory(t))
	records := []spool.Record{
		{ID: "event-000000", Payload: marshal(t, event("event-000000", time.Now()))},
		{ID: "event-garbled", Payload: []byte{0xff, 0xff, 0xff}},
		{ID: "event-renamed", Payload: marshal(t, event("event-other", time.Now()))},
		{ID: "event-000003", Payload: marshal(t, event("event-000003", time.Now()))},
	}
	if _, err := held.Admit(spool.Events, records...); err != nil {
		t.Fatalf("admit: %v", err)
	}
	running := deliver(t, held, serving, enrolled(t, serving), nil)

	eventually(t, "settling every record", func() bool { return outstanding(held, spool.Events).Outstanding == 0 })
	if stored := serving.storedIDs(protocol.Events); !slices.Equal(stored, []string{"event-000000", "event-000003"}) {
		t.Fatalf("the platform stores %v", stored)
	}
	for _, arrived := range serving.received() {
		if len(arrived.ids) != 2 {
			t.Fatalf("the platform received %v", arrived.ids)
		}
	}
	if kept := outstanding(held, spool.Events); kept.Delivered != 2 || kept.Quarantined != 2 {
		t.Fatalf("the spool counts %+v", kept)
	}
	if unread := running.logs.entries(t, "record_not_delivered"); len(unread) != 2 {
		t.Fatalf("logged %v", unread)
	}
}

func TestEventsAreDeliveredWhileThePlatformRefusesInventory(t *testing.T) {
	serving := emulate(t)
	held := spoolIn(t, spoolDirectory(t))
	admitInventory(t, held, "snapshot", 3, 10)
	var mu sync.Mutex
	refusing := true
	serving.set(func(w http.ResponseWriter, arrived *received) bool {
		mu.Lock()
		defer mu.Unlock()
		if arrived.route == protocol.Inventory && refusing {
			refuse(w, http.StatusServiceUnavailable, "backbone_unavailable", "", -1)
			return true
		}
		return false
	})
	deliver(t, held, serving, enrolled(t, serving), nil)
	for round := range 5 {
		admitEvents(t, held, "event-"+string(rune('a'+round)), 20)
		eventually(t, "delivering the events", func() bool { return outstanding(held, spool.Events).Outstanding == 0 })
	}
	if kept := outstanding(held, spool.Inventory); kept.Outstanding != 3 || kept.Delivered != 0 {
		t.Fatalf("while the platform refused inventory, the spool counts %+v", kept)
	}
	mu.Lock()
	refusing = false
	mu.Unlock()
	eventually(t, "delivering the inventory", func() bool { return outstanding(held, spool.Inventory).Outstanding == 0 })
}

func TestALateAnswerSettlesNoRecordButThoseOfTheBatchItAnswers(t *testing.T) {
	serving := emulate(t)
	held := spoolIn(t, spoolDirectory(t))
	first := admitEvents(t, held, "first", 5)
	late := make(chan struct{})
	release := make(chan struct{})
	serving.set(func(w http.ResponseWriter, arrived *received) bool {
		switch {
		case arrived.ids[0] == first[0] && arrived.attempt == 1:
			serving.publish(arrived, len(arrived.ids))
			<-release
			acknowledge(w, &ingestv1.BatchAck{Accepted: true, Durable: true, Received: uint32(len(arrived.ids))})
			close(late)
			return true
		case arrived.ids[0] == first[0]:
			<-late
		}
		return false
	})
	deliver(t, held, serving, enrolled(t, serving), func(s *setup) { s.timeout = 500 * time.Millisecond })

	eventually(t, "the agent giving up on the first answer", func() bool { return len(serving.received()) == 2 })
	second := admitEvents(t, held, "second", 5)
	if kept := outstanding(held, spool.Events); kept.Delivered != 0 || kept.Outstanding != 10 {
		t.Fatalf("before any answer arrived, the spool counts %+v", kept)
	}
	close(release)
	eventually(t, "delivering every record", func() bool { return outstanding(held, spool.Events).Outstanding == 0 })
	arrivals := serving.received()
	if arrivals[0].id != arrivals[1].id || !bytes.Equal(arrivals[0].body, arrivals[1].body) || len(arrivals) != 3 || !slices.Equal(arrivals[2].ids, second) {
		t.Fatalf("the platform received %d batches: %v, %v", len(arrivals), arrivals[0].ids, arrivals[len(arrivals)-1].ids)
	}
	if kept := outstanding(held, spool.Events); kept.Delivered != 10 {
		t.Fatalf("the spool counts %+v", kept)
	}
	for _, id := range first {
		if serving.publications(protocol.Events, id) != 2 {
			t.Errorf("event %s was published %d times, and the answer to its first batch was lost", id, serving.publications(protocol.Events, id))
		}
	}
}

func TestStoppingLeavesTheBatchUnsettledAndReleasesWhatItHeld(t *testing.T) {
	serving := emulate(t)
	held := spoolIn(t, spoolDirectory(t))
	admitEvents(t, held, "event", 3)
	arrived, abandoned := make(chan struct{}), make(chan struct{})
	serving.interceptWith(func(w http.ResponseWriter, r *http.Request) bool {
		io.Copy(io.Discard, r.Body)
		close(arrived)
		<-r.Context().Done()
		close(abandoned)
		return true
	})
	before := runtime.NumGoroutine()
	running := deliver(t, held, serving, enrolled(t, serving), func(s *setup) { s.timeout = time.Minute })
	<-arrived
	began := time.Now()
	running.halt(t)
	if took := time.Since(began); took > time.Second {
		t.Fatalf("stopping took %s while a batch was on its way", took)
	}
	select {
	case <-abandoned:
	case <-time.After(settle):
		t.Fatal("the platform still holds the request of a delivery that stopped")
	}
	if kept := outstanding(held, spool.Events); kept.Outstanding != 3 || kept.Delivered != 0 {
		t.Fatalf("after a stop the spool counts %+v", kept)
	}
	running.client.Close()
	eventually(t, "releasing every goroutine", func() bool { return runtime.NumGoroutine() <= before })
}

func TestARecordAdmittedWhileTheDeliveryWaitsIsSentAtOnce(t *testing.T) {
	serving := emulate(t)
	held := spoolIn(t, spoolDirectory(t))
	deliver(t, held, serving, enrolled(t, serving), nil)
	time.Sleep(200 * time.Millisecond)
	if arrived := serving.received(); len(arrived) != 0 {
		t.Fatalf("an empty spool sent %d batches", len(arrived))
	}
	began := time.Now()
	admitEvents(t, held, "event", 1)
	eventually(t, "delivering the event", func() bool { return outstanding(held, spool.Events).Delivered == 1 })
	if took := time.Since(began); took > time.Second {
		t.Fatalf("an event admitted while the delivery waited took %s to be delivered", took)
	}
}

func TestABatchKeepsToTheLimitsInForceWhenItIsMade(t *testing.T) {
	serving := emulate(t)
	held := spoolIn(t, spoolDirectory(t))
	running := deliver(t, held, serving, enrolled(t, serving), func(s *setup) { s.batching.MaxEvents = 5 })
	admitEvents(t, held, "before", 10)
	eventually(t, "delivering the first records", func() bool { return outstanding(held, spool.Events).Delivered == 10 })
	running.limits.Store(&delivery.Batching{MaxBytes: 4 << 20, MaxEvents: 3, MaxInventoryRecords: 64})
	admitEvents(t, held, "after", 7)
	eventually(t, "delivering the later records", func() bool { return outstanding(held, spool.Events).Delivered == 17 })
	var sizes []int
	for _, arrived := range serving.received() {
		sizes = append(sizes, len(arrived.ids))
	}
	if !slices.Equal(sizes, []int{5, 5, 3, 3, 1}) {
		t.Fatalf("the platform received batches of %v records", sizes)
	}
}

func TestComposingTheDeliveryRefusesWhatItCannotWorkWith(t *testing.T) {
	serving := emulate(t)
	held := spoolIn(t, spoolDirectory(t))
	whole := func(change func(*delivery.Options)) delivery.Options {
		running := deliver(t, held, serving, enrolled(t, serving), nil)
		options := delivery.Options{
			Spool:    held,
			Client:   running.client,
			Governor: running.governor,
			URL:      serving.URL,
			Batching: func() delivery.Batching {
				return delivery.Batching{MaxBytes: 4 << 20, MaxEvents: 1000, MaxInventoryRecords: 64}
			},
			Logger: slog.New(slog.DiscardHandler),
		}
		change(&options)
		return options
	}
	for name, options := range map[string]delivery.Options{
		"no spool":                whole(func(o *delivery.Options) { o.Spool = nil }),
		"no transport":            whole(func(o *delivery.Options) { o.Client = nil }),
		"no governor":             whole(func(o *delivery.Options) { o.Governor = nil }),
		"no batch limits":         whole(func(o *delivery.Options) { o.Batching = nil }),
		"no logger":               whole(func(o *delivery.Options) { o.Logger = nil }),
		"an address in the clear": whole(func(o *delivery.Options) { o.URL = "http://gateway.example:8443" }),
		"an address with no host": whole(func(o *delivery.Options) { o.URL = "https:///v1" }),
		"a negative wait":         whole(func(o *delivery.Options) { o.Policy = delivery.Policy{Retry: -time.Second} }),
		"a wait that shrinks":     whole(func(o *delivery.Options) { o.Policy = delivery.Policy{Hold: time.Hour, HoldLongest: time.Minute} }),
	} {
		t.Run(name, func(t *testing.T) {
			if composed, err := delivery.New(options); err == nil || composed != nil || !strings.Contains(err.Error(), "compose the delivery") {
				t.Fatalf("composed %v, %v", composed, err)
			}
		})
	}
	if composed, err := delivery.New(whole(func(*delivery.Options) {})); err != nil || composed == nil {
		t.Fatalf("a whole set of options was refused: %v", err)
	}
}
