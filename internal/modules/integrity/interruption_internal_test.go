//go:build linux

package integrity

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/governor"
)

const (
	childWatcher = "SEAGULL_FILES_TEST_CHILD"
	installation = "7f3c1a2e-5b6d-4e8f-9a0b-1c2d3e4f5a6b"
)

func TestMain(m *testing.M) {
	if arguments, ok := os.LookupEnv(childWatcher); ok {
		os.Exit(child(arguments))
	}
	os.Exit(m.Run())
}

type instructions struct {
	Base  string `json:"base"`
	State string `json:"state"`
	Rate  int64  `json:"rate"`
}

// A child watches as the agent does, writing down what it saw after every
// directory, and logs to its standard output until it is killed.
func child(arguments string) int {
	var told instructions
	if err := json.Unmarshal([]byte(arguments), &told); err != nil {
		fmt.Println("failed", err)
		return 1
	}
	saveEvery = 0
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	directory, err := os.OpenRoot(told.State)
	if err != nil {
		fmt.Println("failed", err)
		return 1
	}
	governed, err := governor.New(logger, installation, governor.Budget{Scans: 1, ScanBytesPerSecond: told.Rate, Uploads: 1, UploadBytesPerSecond: 1 << 20})
	if err != nil {
		fmt.Println("failed", err)
		return 1
	}
	collector, err := New(Options{Governor: governed, Directory: directory, Logger: logger, Scope: func() Scope { return Scope{Paths: []string{told.Base}} }})
	if err != nil {
		fmt.Println("failed", err)
		return 1
	}
	if err := collector.Collect(context.Background()); err != nil {
		fmt.Println("failed", err)
		return 1
	}
	return 0
}

type output struct {
	mu    sync.Mutex
	lines []map[string]any
}

func (o *output) read(scanner *bufio.Scanner) {
	for scanner.Scan() {
		line := map[string]any{}
		if json.Unmarshal(scanner.Bytes(), &line) == nil {
			o.mu.Lock()
			o.lines = append(o.lines, line)
			o.mu.Unlock()
		}
	}
}

func (o *output) changed() []map[string]any {
	o.mu.Lock()
	defer o.mu.Unlock()
	var found []map[string]any
	for _, line := range o.lines {
		if line["msg"] == "file_changed" {
			found = append(found, line)
		}
	}
	return found
}

func watchedChild(t *testing.T, base, state string, rate int64) (*exec.Cmd, *output) {
	t.Helper()
	arguments, err := json.Marshal(instructions{Base: base, State: state, Rate: rate})
	if err != nil {
		t.Fatal(err)
	}
	started := exec.Command(os.Args[0], "-test.run=^$")
	started.Env = append(os.Environ(), childWatcher+"="+string(arguments))
	piped, err := started.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := started.Start(); err != nil {
		t.Fatal(err)
	}
	held := &output{}
	go held.read(bufio.NewScanner(piped))
	return started, held
}

func listedIn(t *testing.T, state string) (int, int) {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(state, baselineFile))
	if err != nil {
		return 0, 0
	}
	var written stored
	if json.Unmarshal(content, &written) != nil {
		return 0, 0
	}
	listed := 0
	for _, held := range written.Entries {
		if held.Listed {
			listed++
		}
	}
	return listed, len(written.Entries)
}

func killWhen(t *testing.T, started *exec.Cmd, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for !ready() {
		if time.Now().After(deadline) {
			started.Process.Kill()
			t.Fatal("the child never reached the point it was to be killed at")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := started.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	started.Wait()
}

func grow(t *testing.T, base string, directories, files int) {
	t.Helper()
	for d := range directories {
		for f := range files {
			path := filepath.Join(base, fmt.Sprintf("d%02d", d), fmt.Sprintf("f%02d", f))
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(path), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
}

type locked struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (l *locked) Write(content []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buffer.Write(content)
}

func (l *locked) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buffer.String()
}

func finish(t *testing.T, base, state string) *locked {
	t.Helper()
	log := &locked{}
	logger := slog.New(slog.NewJSONHandler(log, nil))
	directory, err := os.OpenRoot(state)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	governed, err := governor.New(logger, installation, governor.Budget{Scans: 1, ScanBytesPerSecond: 1 << 30, Uploads: 1, UploadBytesPerSecond: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	collector, err := New(Options{Governor: governed, Directory: directory, Logger: logger, Scope: func() Scope { return Scope{Paths: []string{base}} }})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- collector.Collect(ctx) }()
	deadline := time.Now().Add(20 * time.Second)
	for !strings.Contains(log.String(), `"msg":"files_walked"`) && !strings.Contains(log.String(), `"msg":"files_watched"`) {
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("the module did not finish its walk:\n%s", log)
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	return log
}

// Killed part of the way through the baseline it takes, the module started
// again goes on from what it wrote down: it reports nothing, since nothing
// changed, reads again none of what it hashed, and holds the whole tree.
func TestABaselineInterruptedByAKillGoesOnWhereItWasWrittenDown(t *testing.T) {
	top := t.TempDir()
	base, state := filepath.Join(top, "watched"), filepath.Join(top, "collection")
	for _, path := range []string{base, state} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	grow(t, base, 20, 20)
	started, said := watchedChild(t, base, state, 64<<10)
	killWhen(t, started, func() bool { listed, _ := listedIn(t, state); return listed >= 3 })
	listed, held := listedIn(t, state)
	if listed >= 21 {
		t.Fatalf("the child finished its baseline before it was killed: %d directories listed", listed)
	}
	if found := said.changed(); len(found) > 0 {
		t.Fatalf("the child reported its baseline as changes: %v", found)
	}
	log := finish(t, base, state)
	if strings.Contains(log.String(), `"msg":"file_changed"`) {
		t.Errorf("the module started again on a baseline it was taking reported changes:\n%s", log)
	}
	if strings.Contains(log.String(), `"msg":"files_baseline_lost"`) {
		t.Errorf("the module could not read what the child wrote down:\n%s", log)
	}
	listed, entries := listedIn(t, state)
	if listed != 21 || entries != 421 {
		t.Errorf("after the kill at %d entries, the baseline holds %d entries and %d listed directories", held, entries, listed)
	}
}

// Killed as it reports what changed while it was stopped, the module started
// again reports every change again that it had not written down as seen, so
// a change is reported twice at worst and never lost.
func TestAWalkInterruptedByAKillLosesNoChange(t *testing.T) {
	top := t.TempDir()
	base, state := filepath.Join(top, "watched"), filepath.Join(top, "collection")
	for _, path := range []string{base, state} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	grow(t, base, 20, 20)
	finish(t, base, state)
	changed := map[string]bool{}
	for d := range 20 {
		path := filepath.Join(base, fmt.Sprintf("d%02d", d), "f07")
		if err := os.WriteFile(path, []byte("changed"), 0o644); err != nil {
			t.Fatal(err)
		}
		changed[path] = true
		gone := filepath.Join(base, fmt.Sprintf("d%02d", d), "f11")
		if err := os.Remove(gone); err != nil {
			t.Fatal(err)
		}
		changed[gone] = true
	}
	started, said := watchedChild(t, base, state, 64<<10)
	killWhen(t, started, func() bool { return len(said.changed()) >= 5 })
	before := said.changed()
	log := finish(t, base, state)
	reported := map[string]int{}
	for _, line := range before {
		reported[line["path"].(string)]++
	}
	for line := range strings.SplitSeq(log.String(), "\n") {
		found := map[string]any{}
		if json.Unmarshal([]byte(line), &found) == nil && found["msg"] == "file_changed" {
			reported[found["path"].(string)]++
		}
	}
	for path := range changed {
		if reported[path] == 0 {
			t.Errorf("%s changed and was never reported", path)
		}
	}
	for path, times := range reported {
		if !changed[path] || times > 2 {
			t.Errorf("%s was reported %d times", path, times)
		}
	}
	if len(before) == 0 || len(before) >= len(changed) {
		t.Errorf("the child reported %d of %d changes before it was killed", len(before), len(changed))
	}
}

func TestATreeLargerThanTheModuleKeepsIsReportedAndKeptInPart(t *testing.T) {
	kept := maxEntries
	maxEntries = 50
	t.Cleanup(func() { maxEntries = kept })
	top := t.TempDir()
	base, state := filepath.Join(top, "watched"), filepath.Join(top, "collection")
	for _, path := range []string{base, state} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	grow(t, base, 4, 20)
	log := finish(t, base, state)
	if strings.Contains(log.String(), `"msg":"file_changed"`) {
		t.Errorf("a tree past the bound was reported as changes:\n%s", log)
	}
	if !strings.Contains(log.String(), `"msg":"files_not_covered"`) || !strings.Contains(log.String(), "holds more than the 50 entries the module keeps") {
		t.Errorf("a tree past the bound was not reported:\n%s", log)
	}
	if _, entries := listedIn(t, state); entries > 50 || entries < 40 {
		t.Errorf("the baseline holds %d entries of a tree past a bound of 50", entries)
	}
}
