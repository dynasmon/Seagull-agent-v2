package governor_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"testing/synctest"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/governor"
	"github.com/dynasmon/Seagull-agent-v2/internal/spool"
)

func TestAScanFeedingAFullStreamWaitsUntilDeliveryFreesRoomInIt(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		kept := spooled(t, 16*mib)
		var backlog []uint64
		for n := 0; ; n++ {
			receipt, err := kept.Admit(spool.Inventory, spool.Record{ID: fmt.Sprintf("inventory-%d", n), Payload: make([]byte, 512<<10)})
			if errors.Is(err, spool.ErrFull) {
				break
			}
			if err != nil {
				t.Fatalf("admit inventory %d: %v", n, err)
			}
			backlog = append(backlog, receipt.First)
		}
		budget := ample
		budget.Scans = 1
		governed, logs := compose(t, budget)
		snapshot := spool.Record{ID: "snapshot", Payload: make([]byte, mib)}
		scanned := make(chan error, 1)
		go func() {
			scanned <- governed.Scan(t.Context(), governor.Scan{
				Module: "inventory",
				Room:   func() int64 { return kept.Room(spool.Inventory) },
				Needs:  int64(len(snapshot.Payload)) + 1024,
			}, func(context.Context, *governor.Meter) error {
				_, err := kept.Admit(spool.Inventory, snapshot)
				return err
			})
		}()
		time.Sleep(time.Hour)
		synctest.Wait()
		if stats := governed.Stats(); stats.Deferred != 1 || stats.Scans != (governor.Use{}) {
			t.Fatalf("a scan feeding a full stream left the governor with %+v", stats)
		}
		if _, err := kept.Admit(spool.Events, spool.Record{ID: "event", Payload: []byte("sshd: accepted publickey")}); err != nil {
			t.Fatalf("events were refused while inventory waited for room: %v", err)
		}

		if err := kept.Acknowledge(spool.Inventory, backlog...); err != nil {
			t.Fatalf("deliver the inventory backlog: %v", err)
		}
		time.Sleep(10 * time.Second)
		synctest.Wait()
		select {
		case err := <-scanned:
			if err != nil {
				t.Fatalf("the scan admitted its snapshot with %v", err)
			}
		default:
			t.Fatal("the scan was still waiting once delivery freed room for it")
		}
		if resumed := logs.entries(t, "scan_resumed"); len(resumed) != 1 || resumed[0]["module"] != "inventory" {
			t.Fatalf("the governor reported %v", resumed)
		}
	})
}

func spooled(t *testing.T, budget int64) *spool.Spool {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "spool")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatalf("create %s: %v", directory, err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatalf("open %s: %v", directory, err)
	}
	t.Cleanup(func() { root.Close() })
	kept, err := spool.Open(root, spool.Limits{MaxBytes: budget, MaxRecordBytes: 4 * mib, MaxAge: map[spool.Stream]time.Duration{
		spool.Events: 168 * time.Hour, spool.Inventory: 720 * time.Hour,
	}}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("open the spool: %v", err)
	}
	t.Cleanup(func() { kept.Close() })
	return kept
}
