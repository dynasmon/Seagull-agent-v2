package governor_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/governor"
)

const mib = 1 << 20

var ample = governor.Budget{Scans: 2, ScanBytesPerSecond: 8 * mib, Uploads: 1, UploadBytesPerSecond: mib}

func TestComposingTheGovernorRefusesWhatItCannotKeep(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	with := func(change func(*governor.Budget)) governor.Budget {
		budget := ample
		change(&budget)
		return budget
	}
	cases := map[string]struct {
		logger       *slog.Logger
		installation string
		budget       governor.Budget
		says         string
	}{
		"no logger":            {installation: "a", budget: ample, says: "no logger"},
		"no installation":      {logger: logger, budget: ample, says: "no installation to spread periodic work by"},
		"no scan at all":       {logger: logger, installation: "a", budget: with(func(b *governor.Budget) { b.Scans = 0 }), says: "0 scans at once"},
		"nothing to read":      {logger: logger, installation: "a", budget: with(func(b *governor.Budget) { b.ScanBytesPerSecond = 0 }), says: "leaves scans nothing to read"},
		"no upload at all":     {logger: logger, installation: "a", budget: with(func(b *governor.Budget) { b.Uploads = -1 }), says: "-1 uploads at once"},
		"nothing to send with": {logger: logger, installation: "a", budget: with(func(b *governor.Budget) { b.UploadBytesPerSecond = 0 }), says: "leaves uploads nothing to send"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			governed, err := governor.New(c.logger, c.installation, c.budget)
			if governed != nil || err == nil || !strings.Contains(err.Error(), c.says) {
				t.Fatalf("composing the governor with %s returned %v, %v", name, governed, err)
			}
		})
	}

	governed, _ := compose(t, ample)
	if err := governed.Limit(governor.Budget{Scans: 1}); err == nil {
		t.Fatal("the governor took a budget that leaves nothing to read or send")
	}
	if held := governed.Stats().Budget; held != ample {
		t.Fatalf("a refused budget left the governor keeping to %+v", held)
	}
	for _, refused := range []error{
		governed.Scan(t.Context(), governor.Scan{}, func(context.Context, *governor.Meter) error { return nil }),
		governed.Scan(t.Context(), governor.Scan{Module: "fim"}, nil),
		governed.Upload(t.Context(), governor.Class(7), func(context.Context, *governor.Meter) error { return nil }),
		governed.Room(t.Context(), nil, 1),
	} {
		if refused == nil {
			t.Error("the governor took work it cannot account for")
		}
	}
}

func TestNoMoreScansRunAtOnceThanTheBudgetAllows(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		governed, _ := compose(t, ample)
		var running, most atomic.Int32
		release := make(chan struct{})
		var scans sync.WaitGroup
		for i := range 6 {
			scans.Go(func() {
				err := governed.Scan(t.Context(), governor.Scan{Module: fmt.Sprintf("module-%d", i)}, func(context.Context, *governor.Meter) error {
					highest(&most, running.Add(1))
					<-release
					running.Add(-1)
					return nil
				})
				if err != nil {
					t.Errorf("scan %d: %v", i, err)
				}
			})
		}
		synctest.Wait()
		if held := governed.Stats().Scans; held != (governor.Use{Bulk: 2, Waiting: 4}) {
			t.Fatalf("six scans asked for two slots and the governor holds %+v", held)
		}
		for range 6 {
			release <- struct{}{}
			synctest.Wait()
		}
		scans.Wait()
		if most.Load() != 2 {
			t.Fatalf("%d scans ran at once, and the budget allows 2", most.Load())
		}
		if held := governed.Stats().Scans; held != (governor.Use{}) {
			t.Fatalf("the governor holds %+v once every scan ended", held)
		}
	})
}

func TestAModuleHoldingNoSlotIsServedBeforeOneHoldingSome(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		governed, _ := compose(t, ample)
		started := make(chan string, 4)
		releases := map[string]chan struct{}{}
		scan := func(module, name string) {
			release := make(chan struct{})
			releases[name] = release
			go governed.Scan(t.Context(), governor.Scan{Module: module}, func(context.Context, *governor.Meter) error {
				started <- name
				<-release
				return nil
			})
			synctest.Wait()
		}
		scan("fim", "fim-1")
		scan("fim", "fim-2")
		scan("fim", "fim-3")
		scan("inventory", "inventory-1")
		if got := drain(started); !slices.Equal(got, []string{"fim-1", "fim-2"}) {
			t.Fatalf("the first two slots went to %v", got)
		}

		close(releases["fim-1"])
		synctest.Wait()
		if got := drain(started); !slices.Equal(got, []string{"inventory-1"}) {
			t.Fatalf("a slot fim gave back went to %v, while inventory held none and fim still held one", got)
		}
		close(releases["fim-2"])
		synctest.Wait()
		if got := drain(started); !slices.Equal(got, []string{"fim-3"}) {
			t.Fatalf("the next slot went to %v", got)
		}
		close(releases["fim-3"])
		close(releases["inventory-1"])
	})
}

func TestCriticalUploadsGoFirstAndOneUploadIsKeptForThem(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		budget := ample
		budget.Uploads = 3
		governed, _ := compose(t, budget)
		started := make(chan string, 8)
		releases := map[string]chan struct{}{}
		upload := func(class governor.Class, name string) {
			release := make(chan struct{})
			releases[name] = release
			go governed.Upload(t.Context(), class, func(context.Context, *governor.Meter) error {
				started <- name
				<-release
				return nil
			})
			synctest.Wait()
		}
		for _, name := range []string{"inventory-1", "inventory-2", "inventory-3"} {
			upload(governor.Bulk, name)
		}
		if held := governed.Stats().Uploads; held != (governor.Use{Bulk: 2, Waiting: 1}) {
			t.Fatalf("three bulk uploads of three at once hold %+v, and one upload is kept for critical ones", held)
		}
		upload(governor.Critical, "events-1")
		if got := drain(started); !slices.Equal(got, []string{"inventory-1", "inventory-2", "events-1"}) {
			t.Fatalf("uploads started in the order %v", got)
		}
		upload(governor.Critical, "events-2")
		close(releases["inventory-1"])
		synctest.Wait()
		if got := drain(started); !slices.Equal(got, []string{"events-2"}) {
			t.Fatalf("the upload inventory gave back went to %v, while events waited behind the inventory that was queued first", got)
		}
		for _, name := range []string{"inventory-2", "events-1", "events-2"} {
			close(releases[name])
		}
		synctest.Wait()
		if got := drain(started); !slices.Equal(got, []string{"inventory-3"}) {
			t.Fatalf("once every critical upload ended, %v started", got)
		}
		close(releases["inventory-3"])
	})
}

func TestBulkUploadsWaitBehindCriticalOnesAndAreNeverStarved(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		governed, _ := compose(t, ample)
		ctx, stop := context.WithCancel(t.Context())
		var critical, bulk atomic.Int32
		var waits []time.Duration
		sender := func(class governor.Class, sent *atomic.Int32) {
			for ctx.Err() == nil {
				queued := time.Now()
				governed.Upload(ctx, class, func(context.Context, *governor.Meter) error {
					if class == governor.Bulk {
						waits = append(waits, time.Since(queued))
					}
					sent.Add(1)
					time.Sleep(time.Second)
					return nil
				})
			}
		}
		var senders sync.WaitGroup
		senders.Go(func() { sender(governor.Critical, &critical) })
		senders.Go(func() { sender(governor.Critical, &critical) })
		synctest.Wait()
		senders.Go(func() { sender(governor.Bulk, &bulk) })
		time.Sleep(time.Minute)
		stop()
		senders.Wait()

		if len(waits) < 9 {
			t.Fatalf("bulk uploads were sent %d times in a minute of uploads a second long", len(waits))
		}
		for i, waited := range waits {
			if waited < time.Second || waited > 5*time.Second {
				t.Fatalf("bulk upload %d waited %s, behind the upload on its way and at most four critical ones", i, waited)
			}
		}
		if critical.Load() < 4*bulk.Load() {
			t.Fatalf("%d critical uploads and %d bulk ones were sent, and critical ones go first", critical.Load(), bulk.Load())
		}
	})
}

func TestCancellingWorkReleasesWhatItHeldAndWhatItWaitedFor(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		budget := ample
		budget.Scans, budget.ScanBytesPerSecond = 1, mib
		governed, _ := compose(t, budget)

		holding, stopHolding := context.WithCancel(t.Context())
		held := make(chan error, 1)
		go func() {
			held <- governed.Scan(holding, governor.Scan{Module: "fim"}, func(ctx context.Context, meter *governor.Meter) error {
				return meter.Charge(ctx, 1<<40)
			})
		}()
		synctest.Wait()
		waiting, stopWaiting := context.WithCancel(t.Context())
		waited := make(chan error, 1)
		go func() {
			waited <- governed.Scan(waiting, governor.Scan{Module: "sca"}, func(context.Context, *governor.Meter) error {
				t.Error("a scan that stopped waiting ran")
				return nil
			})
		}()
		time.Sleep(10 * time.Second)
		synctest.Wait()
		if stats := governed.Stats(); stats.Scans != (governor.Use{Bulk: 1, Waiting: 1}) || stats.Reading != 1 {
			t.Fatalf("a scan reading and another waiting for its slot left the governor with %+v", stats)
		}

		stopWaiting()
		if err := <-waited; !errors.Is(err, context.Canceled) {
			t.Fatalf("a scan that stopped waiting returned %v", err)
		}
		stopHolding()
		if err := <-held; !errors.Is(err, context.Canceled) {
			t.Fatalf("a scan stopped while it read returned %v", err)
		}
		synctest.Wait()
		if stats := governed.Stats(); stats.Scans != (governor.Use{}) || stats.Reading != 0 {
			t.Fatalf("cancelled scans left the governor with %+v", stats)
		}

		failed := errors.New("the package database is unreadable")
		if err := governed.Scan(t.Context(), governor.Scan{Module: "inventory"}, func(context.Context, *governor.Meter) error { return failed }); !errors.Is(err, failed) {
			t.Fatalf("a failing scan returned %v", err)
		}
		began := time.Now()
		if err := governed.Scan(t.Context(), governor.Scan{Module: "inventory"}, func(ctx context.Context, meter *governor.Meter) error {
			return meter.Charge(ctx, mib)
		}); err != nil {
			t.Fatalf("a scan after the failure: %v", err)
		}
		if took := time.Since(began); took < time.Second-time.Millisecond || took > time.Second+time.Millisecond {
			t.Fatalf("a mebibyte at a mebibyte a second took %s once the scan before it was cancelled mid-read", took)
		}
	})
}

func TestScansReadNoFasterThanTheirBudgetTogether(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		budget := ample
		budget.Scans, budget.ScanBytesPerSecond = 4, mib
		governed, _ := compose(t, budget)
		began := time.Now()
		var mu sync.Mutex
		var charged []charge
		var scans sync.WaitGroup
		for i := range 4 {
			scans.Go(func() {
				governed.Scan(t.Context(), governor.Scan{Module: fmt.Sprintf("module-%d", i)}, func(ctx context.Context, meter *governor.Meter) error {
					for range 16 {
						if err := meter.Charge(ctx, 128<<10); err != nil {
							return err
						}
						mu.Lock()
						charged = append(charged, charge{at: time.Now(), bytes: 128 << 10})
						mu.Unlock()
					}
					return nil
				})
			})
		}
		scans.Wait()
		want := time.Duration(float64(8*mib-128<<10) / mib * float64(time.Second))
		if took := time.Since(began); took < want || took > want+time.Millisecond {
			t.Fatalf("four scans read 8MiB at 1MiB a second in %s, want %s", took, want)
		}
		within(t, charged, mib, 128<<10)
	})
}

func TestAMeteredReaderPassesWhatItReadsAtThePaceOfItsBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		budget := ample
		budget.ScanBytesPerSecond = mib
		governed, _ := compose(t, budget)
		content := bytes.Repeat([]byte("seagull"), 4*mib/7)
		digest := sha256.New()
		began := time.Now()
		if err := governed.Scan(t.Context(), governor.Scan{Module: "fim"}, func(ctx context.Context, meter *governor.Meter) error {
			_, err := io.Copy(digest, meter.Reader(ctx, bytes.NewReader(content)))
			return err
		}); err != nil {
			t.Fatalf("hash through the meter: %v", err)
		}
		if got, want := digest.Sum(nil), sha256.Sum256(content); !bytes.Equal(got, want[:]) {
			t.Fatal("what the meter read is not what the reader held")
		}
		want := time.Duration(float64(len(content)-128<<10) / mib * float64(time.Second))
		if took := time.Since(began); took < want || took > want+time.Millisecond {
			t.Fatalf("hashing %d bytes at 1MiB a second took %s, want %s", len(content), took, want)
		}
	})
}

func TestCriticalBytesAreSentBeforeBulkBytesThatWait(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		budget := ample
		budget.Uploads = 2
		governed, _ := compose(t, budget)
		var uploads sync.WaitGroup
		uploads.Go(func() {
			governed.Upload(t.Context(), governor.Bulk, func(ctx context.Context, meter *governor.Meter) error {
				return meter.Charge(ctx, 4*mib)
			})
		})
		time.Sleep(time.Second)
		began := time.Now()
		if err := governed.Upload(t.Context(), governor.Critical, func(ctx context.Context, meter *governor.Meter) error {
			return meter.Charge(ctx, 512<<10)
		}); err != nil {
			t.Fatalf("send events: %v", err)
		}
		if took := time.Since(began); took > 500*time.Millisecond+time.Millisecond {
			t.Fatalf("512KiB of events took %s while inventory was sending, and sharing 1MiB a second evenly takes a second", took)
		}
		uploads.Wait()
	})
}

func TestALowerBudgetTakesEffectAsWorkInProgressEnds(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		governed, _ := compose(t, ample)
		started := make(chan string, 8)
		releases := map[string]chan struct{}{}
		scan := func(name string) {
			release := make(chan struct{})
			releases[name] = release
			go governed.Scan(t.Context(), governor.Scan{Module: name}, func(context.Context, *governor.Meter) error {
				started <- name
				<-release
				return nil
			})
			synctest.Wait()
		}
		scan("inventory")
		scan("fim")
		scan("sca")
		lower := ample
		lower.Scans = 1
		if err := governed.Limit(lower); err != nil {
			t.Fatalf("lower the budget: %v", err)
		}
		if held := governed.Stats().Scans; held != (governor.Use{Bulk: 2, Waiting: 1}) {
			t.Fatalf("lowering the budget left %+v, and work already running keeps its slot", held)
		}
		close(releases["inventory"])
		synctest.Wait()
		if held := governed.Stats().Scans; held != (governor.Use{Bulk: 1, Waiting: 1}) {
			t.Fatalf("under a budget of one scan the governor holds %+v", held)
		}
		close(releases["fim"])
		synctest.Wait()
		if got := drain(started); !slices.Equal(got, []string{"inventory", "fim", "sca"}) {
			t.Fatalf("scans started in the order %v", got)
		}

		higher := ample
		higher.Scans = 3
		scan("inventory-2")
		scan("fim-2")
		if err := governed.Limit(higher); err != nil {
			t.Fatalf("raise the budget: %v", err)
		}
		synctest.Wait()
		if got := drain(started); len(got) != 2 {
			t.Fatalf("raising the budget started %v", got)
		}
		for _, name := range []string{"sca", "inventory-2", "fim-2"} {
			close(releases[name])
		}
	})
}

func TestARaisedRateSpeedsUpWhatIsAlreadyWaiting(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		budget := ample
		budget.ScanBytesPerSecond = mib
		governed, _ := compose(t, budget)
		began := time.Now()
		done := make(chan error, 1)
		go func() {
			done <- governed.Scan(t.Context(), governor.Scan{Module: "fim"}, func(ctx context.Context, meter *governor.Meter) error {
				return meter.Charge(ctx, 10*mib)
			})
		}()
		time.Sleep(2 * time.Second)
		faster := budget
		faster.ScanBytesPerSecond = 8 * mib
		if err := governed.Limit(faster); err != nil {
			t.Fatalf("raise the rate: %v", err)
		}
		if err := <-done; err != nil {
			t.Fatalf("read 10MiB: %v", err)
		}
		if took := time.Since(began); took > 4*time.Second {
			t.Fatalf("10MiB took %s, 2s at 1MiB a second and the rest at 8MiB a second", took)
		}
	})
}

func TestAMeterRefusesChargesOnceItsWorkHasEnded(t *testing.T) {
	governed, _ := compose(t, ample)
	var kept *governor.Meter
	governed.Scan(t.Context(), governor.Scan{Module: "fim"}, func(_ context.Context, meter *governor.Meter) error {
		kept = meter
		return nil
	})
	if err := kept.Charge(t.Context(), 1); !errors.Is(err, governor.ErrEnded) {
		t.Fatalf("a meter charged after its scan ended with %v", err)
	}
}

func TestAScanWaitsForRoomWithoutHoldingASlot(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		budget := ample
		budget.Scans = 1
		governed, logs := compose(t, budget)
		var room atomic.Int64
		ran := make(chan string, 2)
		go governed.Scan(t.Context(), governor.Scan{Module: "inventory", Room: room.Load, Needs: 4 * mib}, func(context.Context, *governor.Meter) error {
			ran <- "inventory"
			return nil
		})
		synctest.Wait()
		if stats := governed.Stats(); stats.Deferred != 1 || stats.Scans != (governor.Use{}) {
			t.Fatalf("a scan waiting for room left the governor with %+v", stats)
		}
		if err := governed.Scan(t.Context(), governor.Scan{Module: "fim"}, func(context.Context, *governor.Meter) error {
			ran <- "fim"
			return nil
		}); err != nil {
			t.Fatalf("scan while another waits for room: %v", err)
		}
		time.Sleep(time.Hour)
		synctest.Wait()
		if got := drain(ran); !slices.Equal(got, []string{"fim"}) {
			t.Fatalf("with no room in the spool, %v ran", got)
		}

		room.Store(4 * mib)
		time.Sleep(10 * time.Second)
		synctest.Wait()
		if got := drain(ran); !slices.Equal(got, []string{"inventory"}) {
			t.Fatalf("once the spool had room, %v ran", got)
		}
		deferred := logs.entries(t, "scan_deferred")
		resumed := logs.entries(t, "scan_resumed")
		if len(deferred) != 1 || deferred[0]["module"] != "inventory" || deferred[0]["room"] != float64(0) || deferred[0]["needs"] != float64(4*mib) {
			t.Fatalf("the governor reported the deferred scan as %v", deferred)
		}
		if len(resumed) != 1 || resumed[0]["deferred"].(float64) < float64(time.Hour) {
			t.Fatalf("the governor reported the resumed scan as %v", resumed)
		}
		if stats := governed.Stats(); stats.Deferred != 0 {
			t.Fatalf("the governor counts %d scans waiting for room once none does", stats.Deferred)
		}
	})
}

func TestWhoeverWaitsForRoomLooksAgainLessOftenUpToALimit(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		governed, _ := compose(t, ample)
		began := time.Now()
		var looks []time.Duration
		room := func() int64 {
			looks = append(looks, time.Since(began))
			if len(looks) > 10 {
				return mib
			}
			return 0
		}
		if err := governed.Room(t.Context(), room, mib); err != nil {
			t.Fatalf("wait for room: %v", err)
		}
		want := []time.Duration{250 * time.Millisecond, 500 * time.Millisecond, time.Second, 2 * time.Second, 4 * time.Second,
			5 * time.Second, 5 * time.Second, 5 * time.Second, 5 * time.Second, 5 * time.Second}
		for i, interval := range want {
			if waited := looks[i+1] - looks[i]; waited < interval*4/5 || waited > interval*6/5 {
				t.Errorf("look %d came %s after the one before, around %s was due", i+1, waited, interval)
			}
		}

		stopped, stop := context.WithCancel(t.Context())
		stop()
		if err := governed.Room(stopped, func() int64 { return 0 }, mib); !errors.Is(err, context.Canceled) {
			t.Fatalf("waiting for room after the stop returned %v", err)
		}
	})
}

type charge struct {
	at    time.Time
	bytes int64
}

// Paced work spends at most its burst at once and its rate after that, over
// every stretch of time between two of its charges.
func within(t *testing.T, charged []charge, rate, burst int64) {
	t.Helper()
	slices.SortFunc(charged, func(a, b charge) int { return a.at.Compare(b.at) })
	for i := range charged {
		var spent int64
		for j := i; j < len(charged); j++ {
			spent += charged[j].bytes
			allowed := burst + int64(charged[j].at.Sub(charged[i].at).Seconds()*float64(rate)) + 1
			if spent > allowed {
				t.Fatalf("%d bytes were charged between %s and %s, and the budget allows %d", spent,
					charged[i].at.Format(time.StampMilli), charged[j].at.Format(time.StampMilli), allowed)
			}
		}
	}
}

func highest(most *atomic.Int32, now int32) {
	for {
		held := most.Load()
		if now <= held || most.CompareAndSwap(held, now) {
			return
		}
	}
}

func drain(started chan string) []string {
	var got []string
	for {
		select {
		case name := <-started:
			got = append(got, name)
		default:
			return got
		}
	}
}

func compose(t *testing.T, budget governor.Budget) (*governor.Governor, *journal) {
	t.Helper()
	logs := &journal{}
	governed, err := governor.New(slog.New(slog.NewJSONHandler(logs, nil)), "8a4a6c52-3a3b-4f0e-9c38-1f2d7f0c9b11", budget)
	if err != nil {
		t.Fatalf("compose the governor: %v", err)
	}
	return governed, logs
}

type journal struct {
	mu   sync.Mutex
	held bytes.Buffer
}

func (j *journal) Write(line []byte) (int, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.held.Write(line)
}

func (j *journal) entries(t *testing.T, message string) []map[string]any {
	t.Helper()
	j.mu.Lock()
	defer j.mu.Unlock()
	var found []map[string]any
	for line := range strings.Lines(j.held.String()) {
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("decode the log line %q: %v", line, err)
		}
		if entry["msg"] == message {
			found = append(found, entry)
		}
	}
	return found
}
