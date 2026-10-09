// Package processes reads the processes procfs shows the agent: every one of
// the PID namespace procfs was mounted for, each through the directory /proc
// keeps of it, so what is read of a process is never read of another that took
// its PID meanwhile. It opens neither a command line nor an environment.
package processes

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/secrets"
)

const (
	maxStat   = 4 << 10
	maxStatus = 4 << 10
	maxSystem = 4 << 20
	maxMounts = 1 << 20
	listing   = 256
	hertz     = 100
)

var proc = "/proc"

var (
	ErrUnreadable = errors.New("the processes of the host cannot be read")
	ErrHidden     = errors.New("procfs hides the processes of other accounts from the agent")
	ErrTooMany    = errors.New("the host runs more processes than the agent takes")
	errGone       = errors.New("the process ended as it was read")
	errLonger     = errors.New("the file holds more than the agent reads of it")
)

// A Process is what procfs says of one: its parent, the name the kernel keeps
// for it, which the process may have chosen itself, the account it acts as,
// when it started, to the tick of USER_HZ, which is 100 on every architecture
// Go builds linux for, and the executable it runs, which procfs shows an
// account only of the processes it runs itself.
type Process struct {
	PID        uint32
	Parent     uint32
	Name       string
	User       uint32
	StartedAt  time.Time
	Executable string
}

// list reads every process procfs shows under root, and refuses when it hides
// some of them or there are more than most: a part is never taken for all.
func list(ctx context.Context, root string, most int) ([]Process, error) {
	held, err := os.OpenRoot(root)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnreadable, err)
	}
	defer held.Close()
	if err := shown(held); err != nil {
		return nil, err
	}
	booted, err := boot(held)
	if err != nil {
		return nil, err
	}
	pids, err := listed(held, most)
	if err != nil {
		return nil, err
	}
	if !slices.Contains(pids, 1) {
		return nil, fmt.Errorf("%w: procfs shows the agent no process 1", ErrHidden)
	}
	running := make([]Process, 0, len(pids))
	for _, pid := range pids {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		found, err := read(held, pid, booted)
		if errors.Is(err, errGone) {
			continue
		}
		if err != nil {
			return nil, err
		}
		running = append(running, found)
	}
	return running, nil
}

func shown(held *os.Root) error {
	mounts, err := content(held, "self/mountinfo", maxMounts)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrUnreadable, err)
	}
	var options string
	found := false
	for line := range strings.SplitSeq(string(mounts), "\n") {
		fields := strings.Fields(line)
		separator := slices.Index(fields, "-")
		if separator < 5 || len(fields) < separator+4 || fields[4] != "/proc" {
			continue
		}
		if fields[separator+1] != "proc" {
			return fmt.Errorf("%w: /proc is a %s file system, not procfs", ErrUnreadable, secrets.Shown(fields[separator+1]))
		}
		options, found = fields[separator+3], true
	}
	if !found {
		return nil
	}
	for option := range strings.SplitSeq(options, ",") {
		if hidden, set := strings.CutPrefix(option, "hidepid="); set && hidden != "0" && hidden != "off" {
			return fmt.Errorf("%w: procfs is mounted for the agent with hidepid=%s", ErrHidden, secrets.Bounded(hidden))
		}
	}
	return nil
}

func boot(held *os.Root) (time.Time, error) {
	system, err := content(held, "stat", maxSystem)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: %w", ErrUnreadable, err)
	}
	for line := range strings.SplitSeq(string(system), "\n") {
		if written, found := strings.CutPrefix(line, "btime "); found {
			seconds, err := strconv.ParseInt(strings.TrimSpace(written), 10, 64)
			if err != nil || seconds <= 0 {
				return time.Time{}, fmt.Errorf("%w: procfs says the host booted at %s", ErrUnreadable, secrets.Shown(written))
			}
			return time.Unix(seconds, 0).UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("%w: procfs does not say when the host booted", ErrUnreadable)
}

func listed(held *os.Root, most int) ([]uint32, error) {
	directory, err := held.Open(".")
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnreadable, err)
	}
	defer directory.Close()
	var pids []uint32
	for {
		names, err := directory.Readdirnames(listing)
		for _, name := range names {
			pid, err := strconv.ParseUint(name, 10, 32)
			if err != nil || pid == 0 || strconv.FormatUint(pid, 10) != name {
				continue
			}
			if len(pids) == most {
				return nil, fmt.Errorf("%w: more than %d", ErrTooMany, most)
			}
			pids = append(pids, uint32(pid))
		}
		if errors.Is(err, io.EOF) {
			return pids, nil
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrUnreadable, err)
		}
	}
}

// Visit hands each the processes procfs shows under root, in the order of
// their PIDs, each read from its stat alone, its parent, its name and when it
// started, and handed with the directory /proc keeps of it still open, so what
// each reads there is of that process and of none that took its PID since.
// Unlike List, it reads what procfs shows when it hides the rest, and counts
// the processes procfs lists and refuses to read.
func Visit(ctx context.Context, root string, most int, each func(Process, *os.Root) error) (int, error) {
	held, err := os.OpenRoot(root)
	if err != nil {
		return 0, fmt.Errorf("%w: %w", ErrUnreadable, err)
	}
	defer held.Close()
	booted, err := boot(held)
	if err != nil {
		return 0, err
	}
	pids, err := listed(held, most)
	if err != nil {
		return 0, err
	}
	slices.Sort(pids)
	refused := 0
	for _, pid := range pids {
		if err := ctx.Err(); err != nil {
			return refused, err
		}
		err := within(held, pid, booted, each)
		switch {
		case errors.Is(err, errGone):
		case errors.Is(err, ErrHidden):
			refused++
		case err != nil:
			return refused, err
		}
	}
	return refused, nil
}

func within(held *os.Root, pid uint32, booted time.Time, each func(Process, *os.Root) error) error {
	own, err := held.OpenRoot(strconv.FormatUint(uint64(pid), 10))
	if err != nil {
		return judged(pid, err)
	}
	defer own.Close()
	stat, err := content(own, "stat", maxStat)
	if err != nil {
		return judged(pid, err)
	}
	parent, name, started, err := stated(stat, pid)
	if err != nil {
		return fmt.Errorf("%w: process %d: %w", ErrUnreadable, pid, err)
	}
	return each(Process{PID: pid, Parent: parent, Name: name, StartedAt: began(booted, started)}, own)
}

func read(held *os.Root, pid uint32, booted time.Time) (Process, error) {
	own, err := held.OpenRoot(strconv.FormatUint(uint64(pid), 10))
	if err != nil {
		return Process{}, judged(pid, err)
	}
	defer own.Close()
	stat, err := content(own, "stat", maxStat)
	if err != nil {
		return Process{}, judged(pid, err)
	}
	parent, name, started, err := stated(stat, pid)
	if err != nil {
		return Process{}, fmt.Errorf("%w: process %d: %w", ErrUnreadable, pid, err)
	}
	status, err := content(own, "status", maxStatus)
	if err != nil && !errors.Is(err, errLonger) {
		return Process{}, judged(pid, err)
	}
	user, err := acting(status)
	if err != nil {
		return Process{}, fmt.Errorf("%w: process %d: %w", ErrUnreadable, pid, err)
	}
	executable, _ := own.Readlink("exe")
	return Process{PID: pid, Parent: parent, Name: name, User: user, StartedAt: began(booted, started), Executable: executable}, nil
}

func began(booted time.Time, ticks uint64) time.Time {
	return booted.Add(time.Duration(ticks/hertz)*time.Second + time.Duration(ticks%hertz)*time.Second/time.Duration(hertz))
}

func judged(pid uint32, err error) error {
	switch {
	case errors.Is(err, fs.ErrNotExist), errors.Is(err, syscall.ESRCH):
		return errGone
	case errors.Is(err, fs.ErrPermission):
		return fmt.Errorf("%w: process %d: %w", ErrHidden, pid, err)
	}
	return fmt.Errorf("%w: process %d: %w", ErrUnreadable, pid, err)
}

func content(held *os.Root, name string, most int64) ([]byte, error) {
	file, err := held.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	read, err := io.ReadAll(io.LimitReader(file, most+1))
	switch {
	case err != nil:
		return nil, err
	case int64(len(read)) > most:
		return read[:most], fmt.Errorf("%w: %s holds more than %d bytes", errLonger, name, most)
	}
	return read, nil
}

func stated(stat []byte, pid uint32) (uint32, string, uint64, error) {
	opened, closed := bytes.IndexByte(stat, '('), bytes.LastIndexByte(stat, ')')
	if opened < 0 || closed < opened || string(stat[:opened]) != strconv.FormatUint(uint64(pid), 10)+" " {
		return 0, "", 0, fmt.Errorf("its stat reads %s", secrets.Bounded(string(stat)))
	}
	fields := strings.Fields(string(stat[closed+1:]))
	if len(fields) < 20 {
		return 0, "", 0, fmt.Errorf("its stat holds %d fields after its name", len(fields))
	}
	parent, err := strconv.ParseUint(fields[1], 10, 32)
	if err != nil {
		return 0, "", 0, fmt.Errorf("its stat names the parent %s", secrets.Shown(fields[1]))
	}
	started, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return 0, "", 0, fmt.Errorf("its stat says it started at %s", secrets.Shown(fields[19]))
	}
	return uint32(parent), string(stat[opened+1 : closed]), started, nil
}

func acting(status []byte) (uint32, error) {
	for line := range strings.SplitSeq(string(status), "\n") {
		written, found := strings.CutPrefix(line, "Uid:")
		if !found {
			continue
		}
		ids := strings.Fields(written)
		if len(ids) != 4 {
			break
		}
		user, err := strconv.ParseUint(ids[1], 10, 32)
		if err != nil {
			break
		}
		return uint32(user), nil
	}
	return 0, errors.New("its status names no account it acts as")
}
