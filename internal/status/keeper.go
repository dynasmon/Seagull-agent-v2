package status

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const temporary = "." + name + ".tmp"

// A Keeper writes what the agent says of itself into a directory only the
// account it runs as reaches: as it starts, every interval after, and once
// more as it stops. What it writes replaces the snapshot before it whole, so a
// reader finds one snapshot or the other and never half of one.
type Keeper struct {
	directory *os.Root
	every     time.Duration
	observe   func() Snapshot
	logger    *slog.Logger

	mu       sync.Mutex
	failures int
}

func NewKeeper(directory *os.Root, every time.Duration, observe func() Snapshot, logger *slog.Logger) (*Keeper, error) {
	var problems []error
	if directory == nil || observe == nil || logger == nil {
		problems = append(problems, errors.New("a directory, what to observe and a logger are all needed to keep the status"))
	}
	if every < time.Second {
		problems = append(problems, fmt.Errorf("a status written every %s is written more than once a second", every))
	}
	if len(problems) > 0 {
		return nil, fmt.Errorf("compose the status: %w", errors.Join(problems...))
	}
	if err := directory.Remove(temporary); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("discard the interrupted write %s: %w", filepath.Join(directory.Name(), temporary), err)
	}
	return &Keeper{directory: directory, every: every, observe: observe, logger: logger}, nil
}

func (k *Keeper) Run(ctx context.Context) error {
	k.write(k.observe())
	ticker := time.NewTicker(k.every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			k.write(k.observe())
		}
	}
}

// Stopped writes the last snapshot of a run, which says the agent stopped and
// why, so a reader never takes an agent that stopped for one that runs.
func (k *Keeper) Stopped(reason string) {
	snapshot := k.observe()
	snapshot.State, snapshot.Reason = Stopped, Text(reason)
	k.write(snapshot)
}

func (k *Keeper) write(snapshot Snapshot) {
	k.mu.Lock()
	defer k.mu.Unlock()
	snapshot.Format, snapshot.WrittenAt, snapshot.EverySeconds = Format, time.Now().UTC(), int(k.every/time.Second)
	if snapshot.State == "" {
		snapshot.State = Worst(snapshot.Components)
	}
	err := k.store(snapshot)
	if err == nil {
		k.failures = 0
		return
	}
	k.failures++
	if k.failures&(k.failures-1) == 0 {
		k.logger.Warn("status_not_written", slog.Any("error", err), slog.Int("attempt", k.failures), slog.Duration("every", k.every),
			slog.String("recovery", "let the account the agent runs as write "+k.directory.Name()+": the agent writes its status there again every interval, and runs on meanwhile"))
	}
}

func (k *Keeper) store(snapshot Snapshot) error {
	content, err := json.MarshalIndent(snapshot, "", "  ")
	if err == nil && len(content) > maxBytes {
		err = fmt.Errorf("a snapshot of %d bytes is larger than the %d a reader takes", len(content), maxBytes)
	}
	if err != nil {
		return fmt.Errorf("encode the status: %w", err)
	}
	path := filepath.Join(k.directory.Name(), name)
	if err := k.directory.Remove(temporary); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("write %s: %w", path, err)
	}
	file, err := k.directory.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	_, err = file.Write(append(content, '\n'))
	err = errors.Join(err, file.Close())
	if err == nil {
		err = k.directory.Rename(temporary, name)
	}
	if err != nil {
		return errors.Join(fmt.Errorf("write %s: %w", path, err), ignoreMissing(k.directory.Remove(temporary)))
	}
	return nil
}

func ignoreMissing(err error) error {
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}
