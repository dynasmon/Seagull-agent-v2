package processes

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

const booted = 1759752000

type described struct {
	pid, parent, user uint32
	name              string
	started           uint64
	executable        string
}

// A procfs tree the test writes: when the host booted, how /proc is mounted,
// and each process as stat, status and exe say.
type tree struct {
	t    *testing.T
	root string
}

func plant(t *testing.T, mounted string, running ...described) tree {
	t.Helper()
	held := tree{t: t, root: t.TempDir()}
	held.write("stat", fmt.Sprintf("cpu  1 2 3 4\nintr 12345 0 0\nctxt 999\nbtime %d\nprocesses 4242\n", booted))
	held.write("self/mountinfo", "22 1 0:21 / /sys rw,nosuid - sysfs sysfs rw\n24 1 0:22 / /proc rw,nosuid,nodev,noexec - proc proc "+mounted+"\n")
	for _, process := range running {
		held.add(process)
	}
	return held
}

func (h tree) write(name, content string) {
	h.t.Helper()
	path := filepath.Join(h.root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		h.t.Fatal(err)
	}
}

func (h tree) add(process described) {
	h.t.Helper()
	pid := strconv.FormatUint(uint64(process.pid), 10)
	h.write(pid+"/stat", fmt.Sprintf("%s (%s) S %d %s 1 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 %d 24301568 3685 18446744073709551615 1 1 0 0 0 0 671173123 4096 1260 0 0 0 17 3 0 0 0 0 0\n",
		pid, process.name, process.parent, pid, process.started))
	h.write(pid+"/status", fmt.Sprintf("Name:\t%s\nUmask:\t0022\nState:\tS (sleeping)\nTgid:\t%s\nPid:\t%s\nPPid:\t%d\nUid:\t1000\t%d\t%d\t%d\nGid:\t0\t0\t0\t0\nGroups:\t%s\n",
		strings.ReplaceAll(process.name, "\n", "\\n"), pid, pid, process.parent, process.user, process.user, process.user, strings.Repeat("27 ", 2000)))
	if process.executable != "" {
		if err := os.Symlink(process.executable, filepath.Join(h.root, pid, "exe")); err != nil {
			h.t.Fatal(err)
		}
	}
}

func at(ticks uint64) time.Time {
	return time.Unix(booted, 0).UTC().Add(time.Duration(ticks) * 10 * time.Millisecond)
}

func TestEveryProcessIsWhatProcfsSaysOfIt(t *testing.T) {
	running := []described{
		{pid: 1, name: "systemd", started: 201, executable: "/usr/lib/systemd/systemd"},
		{pid: 2, name: "kthreadd", started: 202},
		{pid: 77, parent: 1, user: 997, name: "seagull-agent", started: 123456789, executable: "/usr/bin/seagull-agent"},
		{pid: 4242, parent: 77, user: 1000, name: "a) S 1 (b\n\xff", started: 98765, executable: "/tmp/x (deleted)"},
	}
	planted := plant(t, "rw", running...)
	planted.write("self/stat", "not a process")
	planted.write("version", "Linux version 6.8.0")
	listed, err := list(t.Context(), planted.root, 10)
	if err != nil {
		t.Fatal(err)
	}
	want := make([]Process, len(running))
	for i, process := range running {
		want[i] = Process{PID: process.pid, Parent: process.parent, Name: process.name, User: process.user, StartedAt: at(process.started), Executable: process.executable}
	}
	slices.SortFunc(listed, func(a, b Process) int { return int(a.PID) - int(b.PID) })
	if !slices.Equal(listed, want) {
		t.Errorf("procfs lists\n%+v\nwant\n%+v", listed, want)
	}
}

func TestAProcessThatEndsAsItIsReadIsLeftOut(t *testing.T) {
	planted := plant(t, "rw", described{pid: 1, name: "init", started: 1}, described{pid: 300, parent: 1, name: "ending", started: 7})
	if err := os.Remove(filepath.Join(planted.root, "300", "status")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(planted.root, "301"), 0o755); err != nil {
		t.Fatal(err)
	}
	listed, err := list(t.Context(), planted.root, 10)
	if err != nil || len(listed) != 1 || listed[0].PID != 1 {
		t.Errorf("with processes ending as they are read, procfs lists %+v, %v", listed, err)
	}
}

func TestAProcfsThatHidesProcessesListsNone(t *testing.T) {
	for _, mounted := range []string{"rw,hidepid=invisible", "rw,hidepid=2", "rw,hidepid=ptraceable", "rw,hidepid=noaccess,gid=4"} {
		planted := plant(t, mounted, described{pid: 1, name: "init", started: 1})
		if listed, err := list(t.Context(), planted.root, 10); !errors.Is(err, ErrHidden) || !strings.Contains(err.Error(), "hidepid=") {
			t.Errorf("procfs mounted %s lists %+v, %v", mounted, listed, err)
		}
	}
	for _, mounted := range []string{"rw", "rw,hidepid=0", "rw,hidepid=off,subset=pid"} {
		planted := plant(t, mounted, described{pid: 1, name: "init", started: 1})
		if _, err := list(t.Context(), planted.root, 10); err != nil {
			t.Errorf("procfs mounted %s lists nothing: %v", mounted, err)
		}
	}
	planted := plant(t, "rw", described{pid: 7, name: "alone", started: 1})
	if _, err := list(t.Context(), planted.root, 10); !errors.Is(err, ErrHidden) {
		t.Errorf("procfs without process 1 lists its processes: %v", err)
	}
	if os.Geteuid() == 0 {
		t.Skip("the superuser reads a directory whatever its mode")
	}
	planted = plant(t, "rw", described{pid: 1, name: "init", started: 1}, described{pid: 8, parent: 1, name: "other", started: 2})
	locked := filepath.Join(planted.root, "8")
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(locked, 0o755) })
	if _, err := list(t.Context(), planted.root, 10); !errors.Is(err, ErrHidden) {
		t.Errorf("procfs refusing a process to the agent lists the others: %v", err)
	}
}

func TestMoreProcessesThanTakenAreRefused(t *testing.T) {
	planted := plant(t, "rw", described{pid: 1, name: "init", started: 1}, described{pid: 2, name: "two", started: 2}, described{pid: 3, name: "three", started: 3})
	if listed, err := list(t.Context(), planted.root, 2); !errors.Is(err, ErrTooMany) {
		t.Errorf("three processes taken two at most are %+v, %v", listed, err)
	}
	if listed, err := list(t.Context(), planted.root, 3); err != nil || len(listed) != 3 {
		t.Errorf("three processes taken three at most are %+v, %v", listed, err)
	}
}

func TestWhatProcfsDoesNotSayWholeIsUnreadable(t *testing.T) {
	for name, damage := range map[string]func(tree){
		"a stat without its name":      func(h tree) { h.write("9/stat", "9 S 1 9 1 0\n") },
		"a stat of another process":    func(h tree) { h.write("9/stat", strings.Replace(h.read("9/stat"), "9 (", "10 (", 1)) },
		"a stat cut short":             func(h tree) { h.write("9/stat", "9 (cut) S 1 9 1\n") },
		"a stat naming no parent":      func(h tree) { h.write("9/stat", strings.Replace(h.read("9/stat"), ") S 1 ", ") S x ", 1)) },
		"a stat larger than it can be": func(h tree) { h.write("9/stat", strings.Repeat("9 (big) ", 1000)) },
		"a status naming no account":   func(h tree) { h.write("9/status", "Name:\tnine\nGid:\t0\t0\t0\t0\n") },
		"no boot time":                 func(h tree) { h.write("stat", "cpu 1 2 3\n") },
		"a boot time that is no time":  func(h tree) { h.write("stat", "btime soon\n") },
		"a /proc that is not procfs":   func(h tree) { h.write("self/mountinfo", "24 1 0:22 / /proc rw - tmpfs tmpfs rw\n") },
	} {
		planted := plant(t, "rw", described{pid: 1, name: "init", started: 1}, described{pid: 9, parent: 1, name: "nine", started: 9})
		damage(planted)
		if listed, err := list(t.Context(), planted.root, 10); !errors.Is(err, ErrUnreadable) {
			t.Errorf("with %s, procfs lists %+v, %v", name, listed, err)
		}
	}
	if _, err := list(t.Context(), filepath.Join(t.TempDir(), "absent"), 10); !errors.Is(err, ErrUnreadable) {
		t.Errorf("an absent procfs lists processes: %v", err)
	}
}

func TestVisitingHandsEachProcessItsOwnDirectoryInTheOrderOfItsPID(t *testing.T) {
	planted := plant(t, "rw,hidepid=invisible",
		described{pid: 300, parent: 1, user: 33, name: "worker", started: 30, executable: "/usr/sbin/worker"},
		described{pid: 1, name: "init", started: 1},
		described{pid: 42, parent: 1, user: 1000, name: "a) S 1 (b", started: 4},
	)
	planted.write("300/marker", "three hundred")
	if err := os.MkdirAll(filepath.Join(planted.root, "301"), 0o755); err != nil {
		t.Fatal(err)
	}
	var visited []Process
	var marked []string
	refused, err := Visit(t.Context(), planted.root, 10, func(found Process, own *os.Root) error {
		visited = append(visited, found)
		content, _ := own.ReadFile("marker")
		marked = append(marked, string(content))
		return nil
	})
	want := []Process{
		{PID: 1, Name: "init", StartedAt: at(1)},
		{PID: 42, Parent: 1, Name: "a) S 1 (b", StartedAt: at(4)},
		{PID: 300, Parent: 1, Name: "worker", StartedAt: at(30)},
	}
	if err != nil || refused != 0 || !slices.Equal(visited, want) || !slices.Equal(marked, []string{"", "", "three hundred"}) {
		t.Errorf("procfs mounted to hide processes visits\n%+v\nreading %q, refusing %d, %v; want\n%+v", visited, marked, refused, err, want)
	}

	stopped := errors.New("stop here")
	visited = nil
	if _, err := Visit(t.Context(), planted.root, 10, func(found Process, _ *os.Root) error {
		visited = append(visited, found)
		return stopped
	}); !errors.Is(err, stopped) || len(visited) != 1 {
		t.Errorf("a visit asked to stop visits %d processes and returns %v", len(visited), err)
	}
	if _, err := Visit(t.Context(), planted.root, 2, func(Process, *os.Root) error { return nil }); !errors.Is(err, ErrTooMany) {
		t.Errorf("four processes visited two at most return %v", err)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := Visit(cancelled, planted.root, 10, func(Process, *os.Root) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Errorf("a cancelled visit returns %v", err)
	}
	planted.write("42/stat", "42 (cut) S 1\n")
	if _, err := Visit(t.Context(), planted.root, 10, func(Process, *os.Root) error { return nil }); !errors.Is(err, ErrUnreadable) {
		t.Errorf("a stat cut short visits as %v", err)
	}

	if os.Geteuid() == 0 {
		t.Skip("the superuser reads a directory whatever its mode")
	}
	planted.write("42/stat", fmt.Sprintf("42 (shown) S 1 42 1 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 %d 1 1\n", 4))
	locked := filepath.Join(planted.root, "42")
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(locked, 0o755) })
	visited = nil
	refused, err = Visit(t.Context(), planted.root, 10, func(found Process, _ *os.Root) error {
		visited = append(visited, found)
		return nil
	})
	if err != nil || refused != 1 || len(visited) != 2 {
		t.Errorf("procfs refusing a process to the agent visits %+v, refusing %d, %v", visited, refused, err)
	}
}

func (h tree) read(name string) string {
	h.t.Helper()
	content, err := os.ReadFile(filepath.Join(h.root, name))
	if err != nil {
		h.t.Fatal(err)
	}
	return string(content)
}

func TestThisHostShowsTheProcessReadingIt(t *testing.T) {
	if runtime.GOOS != "linux" {
		if _, err := List(t.Context(), 1<<16); !errors.Is(err, errors.ErrUnsupported) {
			t.Errorf("%s lists processes: %v", runtime.GOOS, err)
		}
		t.Skip("procfs is linux's")
	}
	began := time.Now()
	listed, err := List(t.Context(), 1<<16)
	if errors.Is(err, ErrHidden) {
		t.Skipf("this host hides processes from the test: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("read %d processes in %s", len(listed), time.Since(began))
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	index := slices.IndexFunc(listed, func(process Process) bool { return process.PID == uint32(os.Getpid()) })
	if index < 0 || !slices.ContainsFunc(listed, func(process Process) bool { return process.PID == 1 }) {
		t.Fatalf("this host shows %d processes, without this one or without process 1", len(listed))
	}
	own := listed[index]
	if own.Parent != uint32(os.Getppid()) || own.User != uint32(os.Geteuid()) || own.Executable != executable ||
		!bytes.HasPrefix([]byte(filepath.Base(executable)), []byte(own.Name)) {
		t.Errorf("this process is %+v, run from %s by %d as %d", own, executable, os.Getppid(), os.Geteuid())
	}
	if own.StartedAt.After(began.Add(time.Second)) || own.StartedAt.Before(began.Add(-10*time.Minute)) {
		t.Errorf("this process started at %s, and the test began at %s", own.StartedAt, began)
	}
}

func FuzzAStatReadsOnlyAsWhatItSays(f *testing.F) {
	f.Add([]byte("4242 (a) S 1 (b\n\xff) R 77 4242 1 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 98765 24301568 3685\n"))
	f.Add([]byte("1 (systemd) S 0 1 1 0 -1 4194560 33144 435409 32 9654 62 338 599 2042 20 0 1 0 201 24301568 3685 18446744073709551615 1\n"))
	f.Add([]byte("1 () S 0"))
	f.Fuzz(func(t *testing.T, stat []byte) {
		parent, name, started, err := stated(stat, 1)
		if err != nil {
			return
		}
		closed := bytes.LastIndexByte(stat, ')')
		if !bytes.HasPrefix(stat, []byte("1 (")) || string(stat[3:closed]) != name {
			t.Errorf("%q reads as the process %q", stat, name)
		}
		fields := strings.Fields(string(stat[closed+1:]))
		said, _ := strconv.ParseUint(fields[1], 10, 32)
		began, _ := strconv.ParseUint(fields[19], 10, 64)
		if uint64(parent) != said || started != began {
			t.Errorf("%q reads as the parent %d, started at %d", stat, parent, started)
		}
	})
}
