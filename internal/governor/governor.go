// Package governor bounds the expensive work the agent does, whoever does it:
// how many scans run at once and how fast they read, how many uploads run at
// once and how fast they send, and when periodic work runs. It starts no work
// of its own, and whoever waits on it owns the wait.
package governor

import (
	"errors"
	"fmt"
	"log/slog"
	"sync"
)

type Class int

const (
	Critical Class = iota + 1
	Bulk
)

func (c Class) String() string {
	switch c {
	case Critical:
		return "critical"
	case Bulk:
		return "bulk"
	default:
		return fmt.Sprintf("class(%d)", int(c))
	}
}

// What the agent lets its expensive work spend: scans at once and the bytes
// they read and hash each second, uploads at once and the bytes they send each
// second. When two or more uploads may run at once, bulk ones take one fewer,
// so critical work never waits on bulk work to send.
type Budget struct {
	Scans                int
	ScanBytesPerSecond   int64
	Uploads              int
	UploadBytesPerSecond int64
}

func (b Budget) validate() error {
	var problems []error
	if b.Scans < 1 {
		problems = append(problems, fmt.Errorf("%d scans at once leaves no scan running", b.Scans))
	}
	if b.ScanBytesPerSecond < 1 {
		problems = append(problems, fmt.Errorf("%d bytes a second leaves scans nothing to read", b.ScanBytesPerSecond))
	}
	if b.Uploads < 1 {
		problems = append(problems, fmt.Errorf("%d uploads at once leaves nothing to deliver", b.Uploads))
	}
	if b.UploadBytesPerSecond < 1 {
		problems = append(problems, fmt.Errorf("%d bytes a second leaves uploads nothing to send", b.UploadBytesPerSecond))
	}
	return errors.Join(problems...)
}

type Governor struct {
	logger       *slog.Logger
	installation string
	scans        *pool
	uploads      *pool
	reading      *pace
	sending      *pace

	mu       sync.Mutex
	budget   Budget
	deferred int
}

type Stats struct {
	Budget   Budget
	Scans    Use
	Uploads  Use
	Reading  int
	Sending  int
	Deferred int
}

type Use struct {
	Critical int
	Bulk     int
	Waiting  int
}

func New(logger *slog.Logger, installation string, budget Budget) (*Governor, error) {
	var problems []error
	if logger == nil {
		problems = append(problems, errors.New("no logger"))
	}
	if installation == "" {
		problems = append(problems, errors.New("no installation to spread periodic work by"))
	}
	if err := budget.validate(); err != nil {
		problems = append(problems, err)
	}
	if len(problems) > 0 {
		return nil, fmt.Errorf("compose the governor: %w", errors.Join(problems...))
	}
	governor := &Governor{
		logger:       logger,
		installation: installation,
		scans:        newPool(),
		uploads:      newPool(),
		reading:      &pace{},
		sending:      &pace{},
	}
	governor.apply(budget)
	return governor, nil
}

// Limit replaces the budget whole. Work already running keeps what it holds,
// so a lower budget takes effect as that work ends, and a higher one serves
// whatever waits at once.
func (g *Governor) Limit(budget Budget) error {
	if err := budget.validate(); err != nil {
		return fmt.Errorf("limit the governor: %w", err)
	}
	g.apply(budget)
	return nil
}

func (g *Governor) apply(budget Budget) {
	g.mu.Lock()
	g.budget = budget
	g.mu.Unlock()
	reserved := 0
	if budget.Uploads > 1 {
		reserved = 1
	}
	g.scans.limit(budget.Scans, 0)
	g.uploads.limit(budget.Uploads, reserved)
	g.reading.limit(budget.ScanBytesPerSecond)
	g.sending.limit(budget.UploadBytesPerSecond)
}

func (g *Governor) Stats() Stats {
	g.mu.Lock()
	held := Stats{Budget: g.budget, Deferred: g.deferred}
	g.mu.Unlock()
	held.Scans, held.Uploads = g.scans.use(), g.uploads.use()
	held.Reading, held.Sending = g.reading.waiting(), g.sending.waiting()
	return held
}
