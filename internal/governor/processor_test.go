//go:build linux || darwin

package governor_test

import (
	"context"
	"crypto/sha256"
	"io"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/governor"
)

// Paced work does the same work as unpaced work, spread over the time its
// budget buys, so the processor time it takes stays what the work costs and
// the processor is left idle for the rest. The clock and the processor time
// here are the host's own.
func TestPacedHashingTakesTheProcessorTimeItsWorkCostsAndNoMore(t *testing.T) {
	tree := files(t, 32, 256<<10)
	hashed := func(rate int64) (time.Duration, time.Duration) {
		governed, _ := compose(t, governor.Budget{Scans: 1, ScanBytesPerSecond: rate, Uploads: 1, UploadBytesPerSecond: mib})
		buffer := make([]byte, 32<<10)
		spent, began := processor(t), time.Now()
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
		return processor(t) - spent, time.Since(began)
	}
	unpacedProcessor, unpacedWall := hashed(1 << 30)
	pacedProcessor, pacedWall := hashed(16 * mib)
	t.Logf("hashing 8MiB took %s of processor time in %s unpaced, and %s in %s at 16MiB a second",
		unpacedProcessor, unpacedWall, pacedProcessor, pacedWall)
	if want := time.Duration(float64(8*mib-2*mib) / (16 * mib) * float64(time.Second)); pacedWall < want {
		t.Fatalf("8MiB at 16MiB a second were hashed in %s, sooner than the %s the budget allows", pacedWall, want)
	}
	if pacedProcessor > pacedWall/4 {
		t.Fatalf("paced hashing kept the processor busy for %s of %s", pacedProcessor, pacedWall)
	}
	if pacedProcessor > 2*unpacedProcessor+25*time.Millisecond {
		t.Fatalf("pacing took %s of processor time for work that costs %s", pacedProcessor, unpacedProcessor)
	}
}

func processor(t *testing.T) time.Duration {
	t.Helper()
	var used syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &used); err != nil {
		t.Fatalf("read the processor time the test used: %v", err)
	}
	return time.Duration(used.Utime.Nano() + used.Stime.Nano())
}
