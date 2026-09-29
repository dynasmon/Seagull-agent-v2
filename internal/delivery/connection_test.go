package delivery_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-agent-v2/internal/delivery"
	"github.com/dynasmon/Seagull-agent-v2/internal/governor"
	"github.com/dynasmon/Seagull-agent-v2/internal/link"
	"github.com/dynasmon/Seagull-agent-v2/internal/modules"
	"github.com/dynasmon/Seagull-agent-v2/internal/protocol"
	"github.com/dynasmon/Seagull-agent-v2/internal/spool"
)

func TestAListenerThatFailsIsTriedByOneRequestAtATimeAndReachedByEveryRouteOnceItAnswers(t *testing.T) {
	serving := emulate(t)
	network := between(t, serving)
	network.set(holding)
	held := spoolIn(t, spoolDirectory(t))
	before := time.Now()
	events := admitEvents(t, held, "event", 20)
	snapshots := admitInventory(t, held, "snapshot", 3, 10)
	admitted := time.Now()
	running := deliver(t, held, serving, enrolled(t, serving), func(chosen *setup) {
		chosen.url, chosen.uploads, chosen.timeout = network.url(), 2, 500*time.Millisecond
		chosen.policy = delivery.Policy{Retry: 100 * time.Millisecond, RetryLongest: 200 * time.Millisecond, Hold: time.Second, HoldLongest: time.Second}
	})

	eventually(t, "the listener failing", func() bool {
		return running.delivery.Stats().Listener.Attempts >= 1 && network.open.Load() == 0
	})
	network.most.Store(0)
	eventually(t, "trying the listener again", func() bool { return running.delivery.Stats().Listener.Attempts >= 4 })
	if most := network.most.Load(); most != 1 {
		t.Fatalf("%d connections tried the failing listener at once", most)
	}
	failing := running.delivery.Stats()
	if failing.Listener.Failure != link.Transport || failing.Listener.Failing.IsZero() || !failing.Listener.Answered.IsZero() || failing.Listener.Listener != "ingest" {
		t.Fatalf("while nothing answered, the listener stands at %+v", failing.Listener)
	}
	for _, route := range failing.Routes {
		if route.Oldest.Before(before) || route.Oldest.After(admitted) || !route.Delivered.IsZero() || route.Attempts < 1 || route.Failure != link.Transport {
			t.Fatalf("while nothing answered, route %s stands at %+v", route.Stream, route)
		}
	}

	network.set(passing)
	eventually(t, "delivering both routes", func() bool {
		return outstanding(held, spool.Events).Outstanding == 0 && outstanding(held, spool.Inventory).Outstanding == 0
	})
	if stored := serving.storedIDs(protocol.Events); !slices.Equal(stored, events) {
		t.Fatalf("the platform stores events %v", stored)
	}
	if stored := serving.storedIDs(protocol.Inventory); !slices.Equal(stored, snapshots) {
		t.Fatalf("the platform stores inventory %v", stored)
	}
	eventually(t, "noting what was delivered", func() bool {
		for _, route := range running.delivery.Stats().Routes {
			if route.Delivered.IsZero() {
				return false
			}
		}
		return true
	})
	delivered := running.delivery.Stats()
	if !delivered.Listener.Failing.IsZero() || delivered.Listener.Answered.IsZero() {
		t.Fatalf("once it answered, the listener stands at %+v", delivered.Listener)
	}
	for _, route := range delivered.Routes {
		if !route.Oldest.IsZero() || route.Attempts != 0 || !route.Failing.IsZero() {
			t.Fatalf("once it delivered, route %s stands at %+v", route.Stream, route)
		}
	}
	lost, restored := running.logs.entries(t, "connection_failing"), running.logs.entries(t, "connection_restored")
	if len(lost) != 1 || lost[0]["failure"] != "transport" || lost[0]["level"] != "WARN" {
		t.Fatalf("logged %v as the listener failed", lost)
	}
	if len(restored) != 1 || restored[0]["attempts"].(float64) < 4 {
		t.Fatalf("logged %v as the listener answered again", restored)
	}
	for _, failure := range running.logs.entries(t, "delivery_failed") {
		if failure["failure"] != "transport" || failure["outcome"] != "unconfirmed" || failure["level"] != "WARN" {
			t.Fatalf("logged %v", failure)
		}
	}
}

func TestAGatewayThatAsksTheAgentToWaitIsSentNothingSooner(t *testing.T) {
	serving := emulate(t)
	held := spoolIn(t, spoolDirectory(t))
	admitEvents(t, held, "event", 10)
	admitInventory(t, held, "snapshot", 2, 10)
	var mu sync.Mutex
	var arrivals []time.Time
	serving.set(func(w http.ResponseWriter, arrived *received) bool {
		mu.Lock()
		defer mu.Unlock()
		arrivals = append(arrivals, time.Now())
		if len(arrivals) > 1 {
			return false
		}
		w.Header().Set("Retry-After", "1")
		refuse(w, http.StatusTooManyRequests, "rate_limited", "", -1)
		return true
	})
	running := deliver(t, held, serving, enrolled(t, serving), func(chosen *setup) {
		chosen.uploads = 1
		chosen.policy = delivery.Policy{Retry: 5 * time.Millisecond, RetryLongest: 5 * time.Second, Hold: 10 * time.Millisecond, HoldLongest: 40 * time.Millisecond}
	})

	eventually(t, "delivering both routes", func() bool {
		return outstanding(held, spool.Events).Outstanding == 0 && outstanding(held, spool.Inventory).Outstanding == 0
	})
	mu.Lock()
	defer mu.Unlock()
	if len(arrivals) < 3 {
		t.Fatalf("the gateway received %d batches", len(arrivals))
	}
	if waited := arrivals[1].Sub(arrivals[0]); waited < time.Second || waited > 3*time.Second {
		t.Fatalf("asked to wait a second, the agent sent its next batch %s later", waited)
	}
	failures := running.logs.entries(t, "delivery_failed")
	if len(failures) != 1 || failures[0]["outcome"] != "busy" || failures[0]["failure"] != "capacity" || failures[0]["level"] != "WARN" {
		t.Fatalf("logged %v", failures)
	}
	if lost := running.logs.entries(t, "connection_failing"); len(lost) != 1 || lost[0]["failure"] != "capacity" {
		t.Fatalf("logged %v as the gateway asked the agent to wait", lost)
	}
}

func TestARequestTheListenerTookAndNeverAnsweredHoldsItsRouteAlone(t *testing.T) {
	serving := emulate(t)
	held := spoolIn(t, spoolDirectory(t))
	admitInventory(t, held, "snapshot", 3, 10)
	var mu sync.Mutex
	dropping := true
	serving.set(func(w http.ResponseWriter, arrived *received) bool {
		mu.Lock()
		defer mu.Unlock()
		if arrived.route != protocol.Inventory || !dropping {
			return false
		}
		if hijacked, _, err := w.(http.Hijacker).Hijack(); err == nil {
			hijacked.Close()
		}
		return true
	})
	running := deliver(t, held, serving, enrolled(t, serving), nil)
	for round := range 5 {
		admitEvents(t, held, fmt.Sprintf("event-%d", round), 20)
		eventually(t, "delivering the events", func() bool { return outstanding(held, spool.Events).Outstanding == 0 })
	}
	if kept := outstanding(held, spool.Inventory); kept.Outstanding != 3 {
		t.Fatalf("while the platform dropped inventory, the spool counts %+v", kept)
	}
	if listener := running.delivery.Stats().Listener; !listener.Failing.IsZero() || len(running.logs.entries(t, "connection_failing")) != 0 {
		t.Fatalf("a route the platform does not answer held the listener at %+v", listener)
	}
	failures := running.logs.entries(t, "delivery_failed")
	if len(failures) == 0 {
		t.Fatal("logged no failed delivery of inventory")
	}
	for _, failure := range failures {
		if failure["stream"] != "inventory" || failure["failure"] != "transport" || failure["outcome"] != "unconfirmed" || failure["level"] != "WARN" {
			t.Fatalf("logged %v", failure)
		}
	}
	mu.Lock()
	dropping = false
	mu.Unlock()
	eventually(t, "delivering the inventory", func() bool { return outstanding(held, spool.Inventory).Outstanding == 0 })
}

func TestTryingAFlappingListenerOverAndOverLeavesNothingBehind(t *testing.T) {
	if _, err := os.ReadDir("/proc/self/fd"); err != nil {
		t.Skip("the descriptors a process holds are counted on linux")
	}
	serving := emulate(t)
	network := between(t, serving)
	held := spoolIn(t, spoolDirectory(t))
	presented := enrolled(t, serving)
	goroutines, descriptors := runtime.NumGoroutine(), opened(t)
	running := deliver(t, held, serving, presented, func(chosen *setup) {
		chosen.url, chosen.timeout = network.url(), 300*time.Millisecond
	})
	var ids []string
	for cycle := range 12 {
		network.set([]int32{holding, closing, passing}[cycle%3])
		ids = append(ids, admitEvents(t, held, fmt.Sprintf("event-%02d", cycle), 5)...)
		time.Sleep(150 * time.Millisecond)
	}
	network.set(passing)
	eventually(t, "delivering every event", func() bool { return outstanding(held, spool.Events).Outstanding == 0 })
	if stored := serving.storedIDs(protocol.Events); !slices.Equal(stored, ids) || len(serving.conflicting()) != 0 {
		t.Fatalf("the platform stores %v with conflicts %v", stored, serving.conflicting())
	}
	if uploads := running.governor.Stats().Uploads; uploads != (governor.Use{}) {
		t.Fatalf("with nothing left to send, the uploads stand at %+v", uploads)
	}
	if arrived := network.arrived.Load(); arrived < 4 {
		t.Fatalf("the listener was reached %d times over twelve flaps", arrived)
	}

	running.halt(t)
	running.client.Close()
	eventually(t, "ending every goroutine the delivery started", func() bool { return runtime.NumGoroutine() <= goroutines })
	eventually(t, "closing every descriptor the delivery opened", func() bool { return opened(t) <= descriptors })
}

func TestACollectorAdmitsAtItsOwnPaceWhileTheListenerFails(t *testing.T) {
	serving := emulate(t)
	network := between(t, serving)
	network.set(holding)
	held := spoolIn(t, spoolDirectory(t))
	var mu sync.Mutex
	var ids []string
	var slowest time.Duration
	collection, err := modules.New(slog.New(slog.DiscardHandler), modules.Policy{}, modules.Module{
		Name:    "auth",
		Enabled: true,
		Collect: func(ctx context.Context) error {
			for i := 0; ; i++ {
				select {
				case <-ctx.Done():
					return nil
				case <-time.After(10 * time.Millisecond):
				}
				id := fmt.Sprintf("event-%06d", i)
				payload, err := proto.Marshal(event(id, time.Now()))
				if err != nil {
					return err
				}
				began := time.Now()
				if _, err := held.Admit(spool.Events, spool.Record{ID: id, Payload: payload}); err != nil {
					return err
				}
				mu.Lock()
				ids, slowest = append(ids, id), max(slowest, time.Since(began))
				mu.Unlock()
			}
		},
	})
	if err != nil {
		t.Fatalf("compose the collection: %v", err)
	}
	running := deliver(t, held, serving, enrolled(t, serving), func(chosen *setup) {
		chosen.url, chosen.timeout = network.url(), time.Second
	})
	ctx, stop := context.WithCancel(t.Context())
	collected := make(chan error, 1)
	go func() { collected <- collection.Run(ctx) }()

	eventually(t, "the listener failing twice", func() bool { return running.delivery.Stats().Listener.Attempts >= 2 })
	mu.Lock()
	during, slow := len(ids), slowest
	mu.Unlock()
	if health := collection.Health(); len(health) != 1 || health[0].State != modules.Running {
		t.Fatalf("while the listener failed, the collection stood at %+v", health)
	}
	if during < 20 || slow >= time.Second {
		t.Fatalf("while every connection hung for a second, the collector admitted %d records, the slowest in %s", during, slow)
	}

	network.set(passing)
	stop()
	if err := <-collected; err != nil {
		t.Fatalf("the collection stopped with %v", err)
	}
	eventually(t, "delivering what the collector admitted", func() bool { return outstanding(held, spool.Events).Outstanding == 0 })
	mu.Lock()
	defer mu.Unlock()
	if stored := serving.storedIDs(protocol.Events); !slices.Equal(stored, ids) {
		t.Fatalf("the platform stores %d of the %d events the collector admitted", len(stored), len(ids))
	}
}

const (
	passing int32 = iota
	holding
	closing
)

// The network between the agent and the platform, which passes every
// connection through, holds every one without passing a byte until the agent
// gives up on it, or closes every one as it arrives; one that stops passing
// drops the connections it carried. It counts the connections it holds or
// passes at once.
type network struct {
	listener net.Listener
	target   string
	mode     atomic.Int32
	arrived  atomic.Int32
	open     atomic.Int32
	most     atomic.Int32
	carrying sync.WaitGroup

	mu    sync.Mutex
	conns map[net.Conn]bool
}

func between(t *testing.T, serving *platform) *network {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	carried := &network{listener: listener, target: serving.Listener.Addr().String(), conns: map[net.Conn]bool{}}
	carried.carrying.Go(carried.accept)
	t.Cleanup(carried.close)
	return carried
}

func (n *network) url() string { return "https://" + n.listener.Addr().String() }

func (n *network) set(mode int32) {
	n.mode.Store(mode)
	if mode == passing {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	for conn := range n.conns {
		conn.Close()
	}
}

func (n *network) accept() {
	for {
		conn, err := n.listener.Accept()
		if err != nil {
			return
		}
		n.arrived.Add(1)
		if n.mode.Load() == closing {
			conn.Close()
			continue
		}
		n.carrying.Go(func() { n.carry(conn) })
	}
}

func (n *network) carry(conn net.Conn) {
	n.track(conn, true)
	defer n.track(conn, false)
	defer conn.Close()
	if n.mode.Load() == holding {
		io.Copy(io.Discard, conn)
		return
	}
	upstream, err := net.Dial("tcp", n.target)
	if err != nil {
		return
	}
	defer upstream.Close()
	n.carrying.Go(func() {
		io.Copy(struct{ io.Writer }{upstream}, struct{ io.Reader }{conn})
		upstream.Close()
	})
	io.Copy(struct{ io.Writer }{conn}, struct{ io.Reader }{upstream})
}

func (n *network) track(conn net.Conn, opened bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !opened {
		delete(n.conns, conn)
		n.open.Add(-1)
		return
	}
	n.conns[conn] = true
	for now, most := n.open.Add(1), n.most.Load(); now > most && !n.most.CompareAndSwap(most, now); most = n.most.Load() {
	}
}

func (n *network) close() {
	n.listener.Close()
	n.mu.Lock()
	for conn := range n.conns {
		conn.Close()
	}
	n.mu.Unlock()
	n.carrying.Wait()
}

func opened(t *testing.T) int {
	t.Helper()
	held, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("count the descriptors held: %v", err)
	}
	return len(held)
}
