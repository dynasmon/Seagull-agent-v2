package governor

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"math/rand/v2"
	"sync/atomic"
	"time"
)

const (
	firstLook = 250 * time.Millisecond
	lastLook  = 5 * time.Second
	jitter    = 0.2
)

var (
	ErrEnded      = errors.New("the work the meter paced has ended")
	errUnnamed    = errors.New("a scan names the module it belongs to and the work it does")
	errUnclassed  = errors.New("an upload is critical or bulk, and sends something")
	errUnreserved = errors.New("room is asked for with a way to measure it")
)

// A scan is the expensive work a module does in one go, such as enumerating
// what is installed or hashing files. Room, when a scan has one, measures what
// the stream it admits to may still take, and the scan waits for Needs bytes
// of it before it takes a slot, so a scan never holds one it cannot use.
type Scan struct {
	Module string
	Room   func() int64
	Needs  int64
}

func (g *Governor) Scan(ctx context.Context, scan Scan, work func(context.Context, *Meter) error) error {
	if scan.Module == "" || work == nil {
		return errUnnamed
	}
	if scan.Room != nil {
		if err := g.hold(ctx, scan); err != nil {
			return err
		}
	}
	release, err := g.scans.acquire(ctx, scan.Module, Bulk)
	if err != nil {
		return err
	}
	defer release()
	meter := &Meter{pace: g.reading, class: Bulk}
	defer meter.ended.Store(true)
	return work(ctx, meter)
}

func (g *Governor) Upload(ctx context.Context, class Class, send func(context.Context, *Meter) error) error {
	if (class != Critical && class != Bulk) || send == nil {
		return errUnclassed
	}
	release, err := g.uploads.acquire(ctx, class.String(), class)
	if err != nil {
		return err
	}
	defer release()
	meter := &Meter{pace: g.sending, class: class}
	defer meter.ended.Store(true)
	return send(ctx, meter)
}

// Room returns once room measures at least need bytes: at once when it does
// already, and otherwise after looking again at growing intervals, since what
// frees room, a delivery or an expiry, says nothing to whoever waits for it.
func (g *Governor) Room(ctx context.Context, room func() int64, need int64) error {
	if room == nil {
		return errUnreserved
	}
	if room() >= need {
		return nil
	}
	return g.await(ctx, room, need)
}

func (g *Governor) hold(ctx context.Context, scan Scan) error {
	left := scan.Room()
	if left >= scan.Needs {
		return nil
	}
	began := time.Now()
	g.logger.Warn("scan_deferred", slog.String("module", scan.Module), slog.Int64("room", left), slog.Int64("needs", scan.Needs),
		slog.String("recovery", "none: the scan starts once delivery frees room in the spool or what it holds expires"))
	if err := g.await(ctx, scan.Room, scan.Needs); err != nil {
		return err
	}
	g.logger.Info("scan_resumed", slog.String("module", scan.Module), slog.Duration("deferred", time.Since(began)))
	return nil
}

func (g *Governor) await(ctx context.Context, room func() int64, need int64) error {
	g.count(1)
	defer g.count(-1)
	wait := firstLook
	for {
		timer := time.NewTimer(spread(wait))
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
		if room() >= need {
			return nil
		}
		wait = min(2*wait, lastLook)
	}
}

func (g *Governor) count(by int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.deferred += by
}

func spread(wait time.Duration) time.Duration {
	return time.Duration(float64(wait) * (1 - jitter + rand.Float64()*2*jitter))
}

type Meter struct {
	pace  *pace
	class Class
	ended atomic.Bool
}

// Charge waits until the budget allows bytes more. A large charge is taken a
// part at a time, so what it pays for is spread over the time it buys rather
// than let through at once.
func (m *Meter) Charge(ctx context.Context, bytes int64) error {
	for bytes > 0 {
		if m.ended.Load() {
			return ErrEnded
		}
		taken, err := m.pace.take(ctx, m.class, bytes)
		if err != nil {
			return err
		}
		bytes -= taken
	}
	return nil
}

func (m *Meter) Reader(ctx context.Context, reader io.Reader) io.Reader {
	return &metered{ctx: ctx, meter: m, reader: reader}
}

type metered struct {
	ctx    context.Context
	meter  *Meter
	reader io.Reader
}

func (r *metered) Read(buffer []byte) (int, error) {
	if most := r.meter.pace.largest(); int64(len(buffer)) > most {
		buffer = buffer[:most]
	}
	read, err := r.reader.Read(buffer)
	if read > 0 {
		if charged := r.meter.Charge(r.ctx, int64(read)); charged != nil {
			return read, charged
		}
	}
	return read, err
}
