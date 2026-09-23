package governor_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/governor"
	"github.com/dynasmon/Seagull-agent-v2/internal/spool"
)

var errUnreachable = errors.New("the platform is unreachable")

// Three modules hash a tree of files over and over, one file a slot, while
// inventory keeps the upload budget busy with its snapshots; meanwhile an
// authentication event is admitted every half second and delivered as a
// critical upload. The clock is the test's, so what the budgets allow is
// checked exactly, and the files, hashes and spool are real.
func TestAuthDeliveryKeepsGoingWhileScansAndInventorySpendTheirBudgets(t *testing.T) {
	tree := files(t, 24, 256<<10)
	synctest.Test(t, func(t *testing.T) {
		kept := spooled(t, 64*mib)
		budget := governor.Budget{Scans: 2, ScanBytesPerSecond: mib, Uploads: 1, UploadBytesPerSecond: mib}
		governed, _ := compose(t, budget)
		ctx, stop := context.WithCancel(t.Context())
		var work sync.WaitGroup
		var ledger workload

		for _, module := range []string{"fim", "inventory", "sca"} {
			work.Go(func() {
				for ctx.Err() == nil {
					for _, path := range tree {
						err := governed.Scan(ctx, governor.Scan{Module: module}, func(ctx context.Context, meter *governor.Meter) error {
							return ledger.hash(ctx, meter, path)
						})
						if err != nil && ctx.Err() == nil {
							t.Errorf("%s hashed %s with %v", module, path, err)
						}
					}
					if module == "inventory" && ctx.Err() == nil {
						snapshot := spool.Record{ID: fmt.Sprintf("snapshot-%d", time.Now().Unix()), Payload: make([]byte, mib-4096)}
						if _, err := kept.Admit(spool.Inventory, snapshot); err != nil {
							t.Errorf("admit an inventory snapshot: %v", err)
						}
					}
				}
			})
		}
		work.Go(func() { ledger.deliver(ctx, t, governed, kept, spool.Inventory, governor.Bulk, mib) })
		work.Go(func() { ledger.deliver(ctx, t, governed, kept, spool.Events, governor.Critical, 0) })
		work.Go(func() {
			for n := 0; ctx.Err() == nil; n++ {
				id := fmt.Sprintf("event-%d", n)
				if _, err := kept.Admit(spool.Events, spool.Record{ID: id, Payload: []byte("sshd[812]: Failed password for root from 203.0.113.9 port 51022 ssh2")}); err != nil {
					t.Errorf("event %d was refused while scans ran: %v", n, err)
				}
				ledger.admitted(id)
				time.Sleep(500 * time.Millisecond)
			}
		})

		time.Sleep(3 * time.Minute)
		stop()
		work.Wait()

		if ledger.mostScans.Load() != 2 {
			t.Errorf("%d scans ran at once, and the budget allows 2", ledger.mostScans.Load())
		}
		if hashed := ledger.bytes(ledger.read); hashed < 180*mib {
			t.Errorf("three minutes of scans at 1MiB a second hashed %d bytes, so they did not spend their budget", hashed)
		}
		within(t, ledger.read, mib, 128<<10)
		within(t, ledger.sent, mib, 128<<10)
		if slices.Max(ledger.waits[governor.Critical]) > 1100*time.Millisecond {
			t.Errorf("an upload of events waited %s, longer than an inventory snapshot takes to send", slices.Max(ledger.waits[governor.Critical]))
		}
		if len(ledger.waits[governor.Bulk]) < 120 {
			t.Errorf("inventory was sent %d times in three minutes of uploads a second long", len(ledger.waits[governor.Bulk]))
		}
		late, undelivered := ledger.latency(time.Now().Add(-2500 * time.Millisecond))
		if undelivered > 0 || late > 2500*time.Millisecond {
			t.Errorf("%d events were never delivered, and the slowest took %s, more than the batch before it and an inventory upload for each", undelivered, late)
		}
	})
}

// After an outage, senders for both streams retry at once with a backlog to
// send. Every attempt holds an upload while it connects and fails after the
// connect timeout, so the attempts are what bounds a reconnect storm.
func TestAnAgentReconnectingAfterAnOutageStaysWithinItsUploadBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		budget := governor.Budget{Scans: 1, ScanBytesPerSecond: mib, Uploads: 2, UploadBytesPerSecond: mib}
		governed, _ := compose(t, budget)
		recovered := time.Now().Add(5 * time.Minute)
		var ledger workload
		var attempts, bulk, most, mostBulk atomic.Int32
		var backlog atomic.Int64
		backlog.Store(64 * mib)
		var senders sync.WaitGroup
		for i := range 8 {
			class := []governor.Class{governor.Critical, governor.Bulk}[i%2]
			senders.Go(func() {
				for backlog.Load() > 0 {
					governed.Upload(t.Context(), class, func(ctx context.Context, meter *governor.Meter) error {
						highest(&most, attempts.Add(1))
						defer attempts.Add(-1)
						if class == governor.Bulk {
							highest(&mostBulk, bulk.Add(1))
							defer bulk.Add(-1)
						}
						if time.Now().Before(recovered) {
							time.Sleep(10 * time.Second)
							return errUnreachable
						}
						if backlog.Add(-512<<10) < 0 {
							return nil
						}
						return ledger.send(ctx, meter, 512<<10)
					})
				}
			})
		}
		senders.Wait()

		if most.Load() != 2 || mostBulk.Load() != 1 {
			t.Fatalf("%d attempts ran at once, %d of them bulk, and the budget allows 2 with one kept for events", most.Load(), mostBulk.Load())
		}
		within(t, ledger.sent, mib, 128<<10)
		if sent := ledger.bytes(ledger.sent); sent != 64*mib {
			t.Fatalf("a backlog of 64MiB was sent as %d bytes", sent)
		}
		drained := time.Since(recovered)
		if want := time.Duration(float64(64*mib-128<<10) / mib * float64(time.Second)); drained < want || drained > want+10*time.Second {
			t.Fatalf("the 64MiB backlog drained in %s at 1MiB a second, want about %s", drained, want)
		}
	})
}

func TestPacedWorkHoldsNoMoreMemoryThanItsBuffers(t *testing.T) {
	tree := files(t, 64, 256<<10)
	synctest.Test(t, func(t *testing.T) {
		governed, _ := compose(t, governor.Budget{Scans: 2, ScanBytesPerSecond: 64 * mib, Uploads: 1, UploadBytesPerSecond: mib})
		buffer := make([]byte, 32<<10)
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		for _, path := range tree {
			if err := governed.Scan(t.Context(), governor.Scan{Module: "fim"}, func(ctx context.Context, meter *governor.Meter) error {
				file, err := os.Open(path)
				if err != nil {
					return err
				}
				defer file.Close()
				_, err = io.CopyBuffer(sha256.New(), meter.Reader(ctx, file), buffer)
				return err
			}); err != nil {
				t.Fatalf("hash %s: %v", path, err)
			}
		}
		runtime.ReadMemStats(&after)
		if allocated := after.TotalAlloc - before.TotalAlloc; allocated > mib {
			t.Fatalf("hashing 16MiB under the budget allocated %d bytes", allocated)
		}
	})
}

type workload struct {
	mu        sync.Mutex
	read      []charge
	sent      []charge
	waits     map[governor.Class][]time.Duration
	events    map[string]time.Time
	delivered map[string]time.Time
	scans     atomic.Int32
	mostScans atomic.Int32
}

func (w *workload) hash(ctx context.Context, meter *governor.Meter, path string) error {
	highest(&w.mostScans, w.scans.Add(1))
	defer w.scans.Add(-1)
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = io.Copy(sha256.New(), &recorded{reader: meter.Reader(ctx, file), charged: func(read int) {
		w.mu.Lock()
		defer w.mu.Unlock()
		w.read = append(w.read, charge{at: time.Now(), bytes: int64(read)})
	}})
	return err
}

func (w *workload) send(ctx context.Context, meter *governor.Meter, bytes int64) error {
	for bytes > 0 {
		part := min(bytes, 128<<10)
		if err := meter.Charge(ctx, part); err != nil {
			return err
		}
		w.mu.Lock()
		w.sent = append(w.sent, charge{at: time.Now(), bytes: part})
		w.mu.Unlock()
		bytes -= part
	}
	return nil
}

// A sender reads what its stream holds, uploads it under its class, and
// acknowledges it once the upload returned, as delivery will. A sender with
// a backlog sends that much whenever its stream holds nothing new.
func (w *workload) deliver(ctx context.Context, t *testing.T, governed *governor.Governor, kept *spool.Spool, stream spool.Stream, class governor.Class, backlog int64) {
	for ctx.Err() == nil {
		entries, err := kept.Read(stream, 1, 64, 4*mib)
		if err != nil {
			t.Errorf("read %s: %v", stream, err)
			return
		}
		if len(entries) == 0 && backlog == 0 {
			time.Sleep(250 * time.Millisecond)
			continue
		}
		queued := time.Now()
		var batch int64 = 1024
		if len(entries) == 0 {
			batch = backlog
		}
		var sequences []uint64
		for _, entry := range entries {
			batch += int64(len(entry.ID) + len(entry.Payload))
			sequences = append(sequences, entry.Sequence)
		}
		err = governed.Upload(ctx, class, func(ctx context.Context, meter *governor.Meter) error {
			w.mu.Lock()
			if w.waits == nil {
				w.waits = map[governor.Class][]time.Duration{}
			}
			w.waits[class] = append(w.waits[class], time.Since(queued))
			w.mu.Unlock()
			if err := w.send(ctx, meter, batch); err != nil {
				return err
			}
			time.Sleep(50 * time.Millisecond)
			return nil
		})
		if err != nil {
			return
		}
		if err := kept.Acknowledge(stream, sequences...); err != nil {
			t.Errorf("acknowledge %s: %v", stream, err)
			return
		}
		if stream == spool.Events {
			w.mu.Lock()
			if w.delivered == nil {
				w.delivered = map[string]time.Time{}
			}
			for _, entry := range entries {
				w.delivered[entry.ID] = time.Now()
			}
			w.mu.Unlock()
		}
	}
}

func (w *workload) admitted(id string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.events == nil {
		w.events = map[string]time.Time{}
	}
	w.events[id] = time.Now()
}

func (w *workload) latency(before time.Time) (time.Duration, int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	var slowest time.Duration
	undelivered := 0
	for id, admitted := range w.events {
		delivered, ok := w.delivered[id]
		switch {
		case !ok && admitted.Before(before):
			undelivered++
		case ok:
			slowest = max(slowest, delivered.Sub(admitted))
		}
	}
	return slowest, undelivered
}

func (w *workload) bytes(charged []charge) int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	var total int64
	for _, held := range charged {
		total += held.bytes
	}
	return total
}

type recorded struct {
	reader  io.Reader
	charged func(int)
}

func (r *recorded) Read(buffer []byte) (int, error) {
	read, err := r.reader.Read(buffer)
	if read > 0 && (err == nil || errors.Is(err, io.EOF)) {
		r.charged(read)
	}
	return read, err
}
