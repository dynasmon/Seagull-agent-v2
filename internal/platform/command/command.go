// Package command runs a program of the host that the agent names by its full
// path, with the arguments the agent fixes, through no shell and with an empty
// environment, and reads what the program writes within a bound, so nothing
// the host holds decides what runs or how much of what it says the agent keeps.
package command

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/secrets"
)

const (
	maxComplaint = 1 << 10
	stopping     = time.Second
)

var (
	ErrAbsent  = errors.New("the program is not on this host")
	ErrTooLong = errors.New("the program wrote more than the agent reads of it")
)

// A Failure is a program that ran and did not succeed: how it stopped, and
// the last line it wrote to its standard error, bounded.
type Failure struct {
	Program string
	Said    string
	Err     error
}

func (f *Failure) Error() string {
	if f.Said == "" {
		return fmt.Sprintf("%s stopped: %v", f.Program, f.Err)
	}
	return fmt.Sprintf("%s stopped, %v: %s", f.Program, f.Err, f.Said)
}

func (f *Failure) Unwrap() error { return f.Err }

// Output runs program to its end and returns what it wrote to its standard
// output. A program the host does not have is ErrAbsent, and one that writes
// more than most bytes is stopped and reported as ErrTooLong.
func Output(ctx context.Context, program string, arguments []string, most int64) ([]byte, error) {
	name := filepath.Base(program)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	command := exec.CommandContext(ctx, program, arguments...)
	command.Env = []string{}
	command.WaitDelay = stopping
	written := &bounded{most: most, exceeded: cancel}
	said := &complaint{}
	command.Stdout, command.Stderr = written, said
	if err := supervise(command); err != nil {
		return nil, err
	}
	err := command.Start()
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, fmt.Errorf("%w: %s", ErrAbsent, program)
	case err != nil:
		return nil, fmt.Errorf("run %s: %w", name, err)
	}
	stopped := command.Wait()
	switch {
	case written.long():
		return nil, fmt.Errorf("%w: %s wrote more than %d bytes", ErrTooLong, name, most)
	case ctx.Err() != nil:
		return nil, fmt.Errorf("run %s: %w", name, context.Cause(ctx))
	case errors.Is(stopped, exec.ErrWaitDelay):
		return nil, fmt.Errorf("run %s: it left a process behind that holds what it writes", name)
	case stopped != nil:
		return nil, &Failure{Program: name, Said: said.last(), Err: stopped}
	}
	return written.bytes(), nil
}

type bounded struct {
	mu       sync.Mutex
	most     int64
	held     []byte
	over     bool
	exceeded context.CancelFunc
}

func (b *bounded) Write(written []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.over || int64(len(b.held)+len(written)) > b.most {
		b.over, b.held = true, nil
		b.exceeded()
		return 0, ErrTooLong
	}
	b.held = append(b.held, written...)
	return len(written), nil
}

func (b *bounded) long() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.over
}

func (b *bounded) bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.held == nil {
		return []byte{}
	}
	return b.held
}

type complaint struct {
	mu   sync.Mutex
	held []byte
}

func (c *complaint) Write(written []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	kept := append(c.held, written[max(len(written)-maxComplaint, 0):]...)
	c.held = append([]byte(nil), kept[max(len(kept)-maxComplaint, 0):]...)
	return len(written), nil
}

func (c *complaint) last() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	last := ""
	for line := range strings.SplitSeq(string(bytes.TrimSpace(c.held)), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			last = line
		}
	}
	if last == "" {
		return ""
	}
	return secrets.Bounded(last)
}
