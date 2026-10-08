//go:build linux

package integrity_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/governor"
	"github.com/dynasmon/Seagull-agent-v2/internal/modules/integrity"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/inotify"
)

const installation = "7f3c1a2e-5b6d-4e8f-9a0b-1c2d3e4f5a6b"

type logged struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (l *logged) Write(content []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buffer.Write(content)
}

func (l *logged) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buffer.String()
}

func (l *logged) lines(message string) []map[string]any {
	l.mu.Lock()
	defer l.mu.Unlock()
	var found []map[string]any
	for line := range strings.SplitSeq(l.buffer.String(), "\n") {
		entry := map[string]any{}
		if json.Unmarshal([]byte(line), &entry) == nil && (message == "" || entry["msg"] == message) {
			found = append(found, entry)
		}
	}
	return found
}

type harness struct {
	t        *testing.T
	base     string
	state    string
	log      *logged
	governor *governor.Governor

	mu    sync.Mutex
	scope integrity.Scope
}

func prepare(t *testing.T) *harness {
	t.Helper()
	top := t.TempDir()
	h := &harness{t: t, base: filepath.Join(top, "watched"), state: filepath.Join(top, "collection"), log: &logged{}}
	for _, path := range []string{h.base, h.state} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(h.base, 0o755); err != nil {
		t.Fatal(err)
	}
	governed, err := governor.New(slog.New(slog.NewJSONHandler(h.log, nil)), installation, governor.Budget{Scans: 1, ScanBytesPerSecond: 256 << 20, Uploads: 1, UploadBytesPerSecond: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	h.governor = governed
	h.scope = integrity.Scope{Paths: []string{h.base}}
	return h
}

func (h *harness) path(elements ...string) string {
	return filepath.Join(append([]string{h.base}, elements...)...)
}

func (h *harness) write(content string, elements ...string) {
	h.t.Helper()
	path := h.path(elements...)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) given(scope integrity.Scope) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.scope = scope
}

type running struct {
	collector *integrity.Collector
	cancel    context.CancelFunc
	done      chan struct{}
	err       error
}

func (r *running) stop(t *testing.T) {
	t.Helper()
	r.cancel()
	select {
	case <-r.done:
		if r.err != nil {
			t.Fatalf("the module returned %v as it stopped", r.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the module did not stop")
	}
}

func (h *harness) start(adjust func(*integrity.Options)) *running {
	h.t.Helper()
	directory, err := os.OpenRoot(h.state)
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { directory.Close() })
	options := integrity.Options{
		Governor:  h.governor,
		Directory: directory,
		Logger:    slog.New(slog.NewJSONHandler(h.log, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Scope: func() integrity.Scope {
			h.mu.Lock()
			defer h.mu.Unlock()
			return integrity.Scope{Paths: slices.Clone(h.scope.Paths), Exclude: slices.Clone(h.scope.Exclude)}
		},
	}
	if adjust != nil {
		adjust(&options)
	}
	collector, err := integrity.New(options)
	if err != nil {
		h.t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	held := &running{collector: collector, cancel: cancel, done: make(chan struct{})}
	go func() {
		held.err = collector.Collect(ctx)
		close(held.done)
	}()
	h.t.Cleanup(func() {
		cancel()
		select {
		case <-held.done:
		case <-time.After(10 * time.Second):
		}
	})
	return held
}

func (h *harness) await(message string, count int) []map[string]any {
	h.t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		if found := h.log.lines(message); len(found) >= count {
			return found
		}
		if time.Now().After(deadline) {
			h.t.Fatalf("the module did not log %s %d times:\n%s", message, count, h.log.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

type reported struct {
	path, operation, origin, previous string
	changes                           []string
	before, after                     map[string]any
	seen                              []string
	coalesced                         float64
}

func (h *harness) changes() []reported {
	var held []reported
	for _, line := range h.log.lines("file_changed") {
		found := reported{}
		found.path, _ = line["path"].(string)
		found.operation, _ = line["operation"].(string)
		found.origin, _ = line["origin"].(string)
		found.previous, _ = line["previous"].(string)
		for _, change := range asList(line["changes"]) {
			found.changes = append(found.changes, change.(string))
		}
		for _, seen := range asList(line["seen"]) {
			found.seen = append(found.seen, seen.(string))
		}
		found.coalesced, _ = line["coalesced"].(float64)
		found.before, _ = line["before"].(map[string]any)
		found.after, _ = line["after"].(map[string]any)
		held = append(held, found)
	}
	return held
}

func asList(value any) []any {
	held, _ := value.([]any)
	return held
}

// expect waits until the module reported a change of path as operation, and
// returns it.
func (h *harness) expect(operation, path string, from int) reported {
	h.t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		found := h.changes()
		for _, change := range found[min(from, len(found)):] {
			if change.operation == operation && change.path == path {
				return change
			}
		}
		if time.Now().After(deadline) {
			h.t.Fatalf("the module did not report %s %s; it reported %+v", path, operation, found[min(from, len(found)):])
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func digest(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

func TestTheFirstWalkTakesWhatItSeesAsTheBaselineAndReportsNothing(t *testing.T) {
	h := prepare(t)
	h.write("root:x:0:0", "passwd")
	h.write("deep", "a", "b", "c", "d")
	if err := os.Symlink("/etc/hostname", h.path("link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(h.path("passwd"), h.path("again")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(h.path("pipe"), 0o600); err != nil {
		t.Fatal(err)
	}
	watching := h.start(nil)
	watched := h.await("files_watched", 1)[0]
	if watched["entries"] != float64(9) || watched["directories"] != float64(4) || watched["watched"] != float64(4) {
		t.Errorf("the module took the baseline as %v", watched)
	}
	time.Sleep(1500 * time.Millisecond)
	if found := h.changes(); len(found) > 0 {
		t.Errorf("the baseline was reported as changes: %+v", found)
	}
	stats := watching.collector.Stats()
	if stats.Entries != 9 || stats.Directories != 4 || stats.Watched != 4 || stats.Failure != nil || stats.Walked.IsZero() {
		t.Errorf("the module says %+v", stats)
	}
	watching.stop(t)
	described, err := os.Stat(filepath.Join(h.state, "files.json"))
	if err != nil || described.Mode().Perm() != 0o600 {
		t.Fatalf("the baseline is written as %v, %v", described, err)
	}
	content, err := os.ReadFile(filepath.Join(h.state, "files.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, said := range []string{digest("root:x:0:0"), `"target":"/etc/hostname"`, `"kind":"pipe"`, `"listed":true`} {
		if !strings.Contains(string(content), said) {
			t.Errorf("the baseline does not hold %s:\n%s", said, content)
		}
	}
	if strings.Contains(string(content), "hostname\n") {
		t.Error("the module read what the link leads to")
	}
}

func TestWhatChangesIsReportedAsItChanges(t *testing.T) {
	h := prepare(t)
	h.write("first", "config")
	h.write("kept", "sub", "kept")
	h.write("doomed", "doomed")
	h.start(nil)
	h.await("files_watched", 1)

	h.write("created", "fresh")
	created := h.expect("created", h.path("fresh"), 0)
	if created.origin != "realtime" || created.after["sha256"] != digest("created") || created.after["mode"] != "0644" || !slices.Contains(created.seen, "created") {
		t.Errorf("a new file was reported as %+v", created)
	}

	from := len(h.changes())
	h.write("second", "config")
	modified := h.expect("modified", h.path("config"), from)
	if !slices.Equal(modified.changes, []string{"content"}) || modified.before["sha256"] != digest("first") || modified.after["sha256"] != digest("second") {
		t.Errorf("a file written again was reported as %+v", modified)
	}

	from = len(h.changes())
	if err := os.Chmod(h.path("sub", "kept"), 0o4755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Chmod(h.path("sub", "kept"), 0o4755); err != nil {
		t.Fatal(err)
	}
	moded := h.expect("modified", h.path("sub", "kept"), from)
	if !slices.Equal(moded.changes, []string{"mode"}) || moded.after["mode"] != "4755" || moded.before["mode"] != "0644" {
		t.Errorf("a chmod was reported as %+v", moded)
	}

	from = len(h.changes())
	if err := os.Rename(h.path("sub", "kept"), h.path("moved")); err != nil {
		t.Fatal(err)
	}
	renamed := h.expect("renamed", h.path("moved"), from)
	if renamed.previous != h.path("sub", "kept") || len(renamed.changes) != 0 {
		t.Errorf("a rename was reported as %+v", renamed)
	}

	from = len(h.changes())
	if err := os.Remove(h.path("doomed")); err != nil {
		t.Fatal(err)
	}
	deleted := h.expect("deleted", h.path("doomed"), from)
	if deleted.before["sha256"] != digest("doomed") || deleted.after != nil {
		t.Errorf("a deletion was reported as %+v", deleted)
	}

	from = len(h.changes())
	h.write("replacement", ".config.tmp")
	if err := os.Rename(h.path(".config.tmp"), h.path("config")); err != nil {
		t.Fatal(err)
	}
	replaced := h.expect("modified", h.path("config"), from)
	if !slices.Equal(replaced.changes, []string{"identity", "content"}) || replaced.after["sha256"] != digest("replacement") {
		t.Errorf("a file replaced by a rename over it was reported as %+v", replaced)
	}

	from = len(h.changes())
	h.write("one", "tree", "one")
	h.write("two", "tree", "deeper", "two")
	h.expect("created", h.path("tree", "deeper", "two"), from)
	h.expect("created", h.path("tree"), from)

	from = len(h.changes())
	if err := os.RemoveAll(h.path("tree")); err != nil {
		t.Fatal(err)
	}
	h.expect("deleted", h.path("tree", "deeper", "two"), from)
	h.expect("deleted", h.path("tree"), from)

	from = len(h.changes())
	h.write("brief", "transient")
	if err := os.Remove(h.path("transient")); err != nil {
		t.Fatal(err)
	}
	brief := h.expect("transient", h.path("transient"), from)
	if !slices.Contains(brief.seen, "created") || brief.coalesced < 2 {
		t.Errorf("a file created and deleted before the module looked was reported as %+v", brief)
	}
	time.Sleep(1500 * time.Millisecond)
	for _, change := range h.changes() {
		if strings.HasSuffix(change.path, ".config.tmp") {
			t.Errorf("a file renamed over another was reported on its own as %+v", change)
		}
	}
}

func TestWhatChangedWhileNobodyWatchedIsFoundAsTheModuleStarts(t *testing.T) {
	h := prepare(t)
	h.write("before", "config")
	h.write("moving", "a", "file")
	h.write("going", "gone")
	h.write("inside", "directory", "inside")
	watching := h.start(nil)
	h.await("files_watched", 1)
	watching.stop(t)

	h.write("after", "config")
	if err := os.Rename(h.path("a", "file"), h.path("file")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(h.path("directory"), h.path("renamed")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(h.path("gone")); err != nil {
		t.Fatal(err)
	}
	h.write("new", "new")
	h.start(nil)
	walked := h.await("files_walked", 1)[0]
	if walked["because"] != "start" {
		t.Errorf("the module walked %v", walked)
	}
	want := map[string]string{
		h.path("config"):  "modified",
		h.path("file"):    "renamed",
		h.path("renamed"): "renamed",
		h.path("gone"):    "deleted",
		h.path("new"):     "created",
	}
	found := map[string]string{}
	for _, change := range h.changes() {
		if change.origin != "reconciliation" {
			t.Errorf("a change found as the module started was reported as %+v", change)
		}
		found[change.path] = change.operation
		if change.operation == "renamed" && change.path == h.path("renamed") && change.previous != h.path("directory") {
			t.Errorf("a directory that moved was reported as %+v", change)
		}
	}
	if !mapsEqual(found, want) {
		t.Errorf("the module reported %v, want %v", found, want)
	}
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for key, value := range a {
		if b[key] != value {
			return false
		}
	}
	return true
}

func TestALinkIsWatchedAsALinkAndNeverFollowed(t *testing.T) {
	h := prepare(t)
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("not to be read"), 0o644); err != nil {
		t.Fatal(err)
	}
	h.write("watched", "file")
	if err := os.Symlink(outside, h.path("door")); err != nil {
		t.Fatal(err)
	}
	h.start(nil)
	h.await("files_watched", 1)

	from := len(h.changes())
	if err := os.Remove(h.path("file")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "secret"), h.path("file")); err != nil {
		t.Fatal(err)
	}
	swapped := h.expect("modified", h.path("file"), from)
	if !slices.Equal(swapped.changes, []string{"kind"}) || swapped.after["kind"] != "link" || swapped.after["target"] != filepath.Join(outside, "secret") || swapped.after["sha256"] != nil {
		t.Errorf("a file replaced by a link was reported as %+v", swapped)
	}
	from = len(h.changes())
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("changed"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "elsewhere"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Second)
	if found := h.changes()[from:]; len(found) > 0 {
		t.Errorf("what a link leads to was watched: %+v", found)
	}
	if strings.Contains(h.log.String(), digest("not to be read")) || strings.Contains(h.log.String(), "elsewhere") {
		t.Error("the module read what a link leads to")
	}
}

func TestAPathThatIsALinkOrPassesThroughOneIsNotWatched(t *testing.T) {
	h := prepare(t)
	h.write("held", "real", "file")
	if err := os.Symlink("real", h.path("alias")); err != nil {
		t.Fatal(err)
	}
	h.given(integrity.Scope{Paths: []string{h.path("alias"), h.path("alias", "file")}})
	watching := h.start(nil)
	h.await("files_watched", 1)
	stats := watching.collector.Stats()
	if !errors.Is(stats.Failure, integrity.ErrUnobserved) || !strings.Contains(stats.Failure.Error(), "symbolic link") {
		t.Fatalf("a path that is a link was watched: %+v", stats)
	}
	if recovery := integrity.Recovery(stats.Failure); !strings.Contains(recovery, "the path the link leads to") {
		t.Errorf("the recovery says %q", recovery)
	}
	if stats.Entries != 1 {
		t.Errorf("the module holds %d entries of a link and what passes through it", stats.Entries)
	}
	not := h.await("files_not_covered", 1)[0]
	if !strings.Contains(fmt.Sprint(not["error"]), "symbolic link") {
		t.Errorf("the module said %v", not)
	}
}

func TestWhatTheModuleCannotReadIsReportedAndKept(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the superuser reads everything")
	}
	h := prepare(t)
	h.write("listed", "closed", "inside")
	h.write("private", "private")
	watching := h.start(nil)
	h.await("files_watched", 1)
	if err := os.Chmod(h.path("private"), 0o200); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(h.path("closed"), 0o755) })
	if err := os.Chmod(h.path("closed"), 0o000); err != nil {
		t.Fatal(err)
	}
	h.expect("modified", h.path("private"), 0)
	h.expect("modified", h.path("closed"), 0)
	watching.stop(t)
	h.start(nil)
	h.await("files_walked", 1)
	not := h.await("files_not_covered", 1)
	said := fmt.Sprint(not[len(not)-1]["reason"])
	if !strings.Contains(said, "directories it cannot list: 1, such as "+h.path("closed")) || !strings.Contains(said, "files whose content it cannot read: 1, such as "+h.path("private")) ||
		!strings.Contains(fmt.Sprint(not[len(not)-1]["recovery"]), "CAP_DAC_READ_SEARCH") {
		t.Errorf("the module said %v", not[len(not)-1])
	}
	for _, change := range h.changes() {
		if change.operation == "deleted" {
			t.Errorf("what the module could not read was reported as %+v", change)
		}
	}
	if err := os.Chmod(h.path("closed"), 0o755); err != nil {
		t.Fatal(err)
	}
	h.write("changed while closed", "closed", "inside")
	h.expect("modified", h.path("closed", "inside"), 0)
}

type silent struct {
	inner  integrity.Watcher
	events chan []inotify.Event
}

func (s *silent) Add(directory *os.File) (int, error) { return s.inner.Add(directory) }
func (s *silent) Remove(watch int) error              { return s.inner.Remove(watch) }
func (s *silent) Close() error                        { close(s.events); return s.inner.Close() }

func (s *silent) Read() ([]inotify.Event, error) {
	events, open := <-s.events
	if !open {
		return nil, inotify.ErrClosed
	}
	return events, nil
}

func TestWhatTheKernelDroppedIsFoundByWalkingEverythingAgain(t *testing.T) {
	h := prepare(t)
	h.write("watched", "file")
	held := &silent{events: make(chan []inotify.Event, 1)}
	h.start(func(options *integrity.Options) {
		options.Watch = func() (integrity.Watcher, error) {
			watcher, err := inotify.Open()
			held.inner = watcher
			return held, err
		}
	})
	h.await("files_watched", 1)
	h.write("unseen", "missed")
	h.write("changed", "file")
	time.Sleep(1500 * time.Millisecond)
	if found := h.changes(); len(found) > 0 {
		t.Fatalf("the module reported what nobody told it: %+v", found)
	}
	held.events <- []inotify.Event{{Watch: -1, What: inotify.Overflowed}}
	lost := h.await("files_hints_lost", 1)[0]
	if lost["level"] != "WARN" {
		t.Errorf("the module said %v", lost)
	}
	if walked := h.await("files_walked", 1)[0]; walked["because"] != "overflow" {
		t.Errorf("the module walked %v", walked)
	}
	if created := h.expect("created", h.path("missed"), 0); created.origin != "reconciliation" {
		t.Errorf("a file the kernel did not tell of was reported as %+v", created)
	}
	h.expect("modified", h.path("file"), 0)
}

func TestAFileThatKeepsChangingIsReportedLessOftenTheLongerItDoes(t *testing.T) {
	h := prepare(t)
	h.write("0", "hot")
	h.start(nil)
	h.await("files_watched", 1)
	began := time.Now()
	for i := 1; time.Since(began) < 8*time.Second; i++ {
		h.write(fmt.Sprint(i), "hot")
		time.Sleep(50 * time.Millisecond)
	}
	time.Sleep(1500 * time.Millisecond)
	var reports []reported
	folded := 0.0
	for _, change := range h.changes() {
		if change.path == h.path("hot") {
			reports = append(reports, change)
			folded += change.coalesced
		}
	}
	if len(reports) < 2 || len(reports) > 5 || folded < 100 {
		t.Errorf("a file written every 50ms for 8s was reported %d times, folding %v hints: %+v", len(reports), folded, reports)
	}
}

func TestStoppingTheModuleReleasesWhatItWatches(t *testing.T) {
	h := prepare(t)
	for i := range 20 {
		h.write("x", fmt.Sprint(i), "file")
	}
	before := watchers(t)
	watching := h.start(nil)
	h.await("files_watched", 1)
	if during := watchers(t); during != before+1 {
		t.Errorf("the module holds %d watchers, and %d were held before it started", during, before)
	}
	watching.stop(t)
	if after := watchers(t); after != before {
		t.Errorf("the module left %d watchers behind, and %d were held before it started", after, before)
	}
}

func watchers(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	counted := 0
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join("/proc/self/fd", entry.Name()))
		if err == nil && target == "anon_inode:inotify" {
			counted++
		}
	}
	return counted
}

func TestAScopeThatChangesTakesWhatItNowWatchesAsTheBaseline(t *testing.T) {
	h := prepare(t)
	other := filepath.Join(filepath.Dir(h.base), "other")
	if err := os.Mkdir(other, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, "existing"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	h.write("x", "cache", "entry")
	h.write("x", "notes.swp")
	h.write("x", "kept")
	h.given(integrity.Scope{Paths: []string{h.base}, Exclude: []string{h.path("cache"), "*.swp"}})
	watching := h.start(nil)
	h.await("files_watched", 1)
	if stats := watching.collector.Stats(); stats.Entries != 2 {
		t.Errorf("with the cache and the swap files left out, the module holds %d entries", stats.Entries)
	}
	h.write("y", "cache", "entry")
	h.write("y", "other.swp")
	time.Sleep(1500 * time.Millisecond)
	if found := h.changes(); len(found) > 0 {
		t.Fatalf("the module reported what it leaves out: %+v", found)
	}

	h.given(integrity.Scope{Paths: []string{h.base, other}})
	watching.collector.Rescope()
	walked := h.await("files_walked", 1)[0]
	if walked["because"] != "scope" || walked["entries"] != float64(8) {
		t.Errorf("the module walked %v", walked)
	}
	if found := h.changes(); len(found) > 0 {
		t.Errorf("what the module now watches was reported as changes: %+v", found)
	}
	h.write("z", "cache", "entry")
	h.expect("modified", h.path("cache", "entry"), 0)
	if err := os.WriteFile(filepath.Join(other, "existing"), []byte("y"), 0o644); err != nil {
		t.Fatal(err)
	}
	h.expect("modified", filepath.Join(other, "existing"), 0)
	watching.stop(t)

	h.given(integrity.Scope{Paths: []string{other}})
	h.start(nil)
	h.await("files_walked", 2)
	h.write("w", "kept")
	time.Sleep(1500 * time.Millisecond)
	for _, change := range h.changes() {
		if strings.HasPrefix(change.path, h.base) && change.operation != "modified" {
			t.Errorf("a path the module no longer watches was reported as %+v", change)
		}
	}
}

func TestAHardLinkIsANewNameOfAFileWithTheNamesItHas(t *testing.T) {
	h := prepare(t)
	h.write("shared", "original")
	h.start(func(options *integrity.Options) { options.Interval = func() time.Duration { return time.Second } })
	h.await("files_watched", 1)
	if err := os.Link(h.path("original"), h.path("another")); err != nil {
		t.Fatal(err)
	}
	created := h.expect("created", h.path("another"), 0)
	if created.after["links"] != float64(2) || created.after["sha256"] != digest("shared") {
		t.Errorf("a second name of a file was reported as %+v", created)
	}
	linked := h.expect("modified", h.path("original"), 0)
	if !slices.Equal(linked.changes, []string{"links"}) || linked.origin != "reconciliation" {
		t.Errorf("a file that gained a name was reported as %+v", linked)
	}
	from := len(h.changes())
	if err := os.Remove(h.path("original")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.path("unrelated"), []byte("shared"), 0o644); err != nil {
		t.Fatal(err)
	}
	h.expect("deleted", h.path("original"), from)
	h.expect("created", h.path("unrelated"), from)
	for _, change := range h.changes()[from:] {
		if change.operation == "renamed" {
			t.Errorf("a name removed from a file with two was reported as %+v", change)
		}
	}
}

func TestADirectoryDeeperThanTheModuleWalksIsReported(t *testing.T) {
	h := prepare(t)
	elements := make([]string, 70)
	for i := range elements {
		elements[i] = "d"
	}
	h.write("bottom", append(elements, "file")...)
	watching := h.start(nil)
	h.await("files_watched", 1)
	stats := watching.collector.Stats()
	if stats.Deep.Count != 1 || stats.Entries != 65 || stats.Failure != nil {
		t.Errorf("a tree 70 directories deep is held as %+v", stats)
	}
	if not := h.await("files_not_covered", 1)[0]; !strings.Contains(fmt.Sprint(not["reason"]), "directories deeper than it walks: 1") {
		t.Errorf("the module said %v", not)
	}
}

func TestAWalkReadsNoFasterThanTheGovernorLets(t *testing.T) {
	h := prepare(t)
	for d := range 15 {
		for f := range 100 {
			h.write("x", fmt.Sprintf("d%02d", d), fmt.Sprintf("f%03d", f))
		}
	}
	governed, err := governor.New(slog.New(slog.DiscardHandler), installation, governor.Budget{Scans: 1, ScanBytesPerSecond: 1 << 20, Uploads: 1, UploadBytesPerSecond: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	var before, after syscall.Rusage
	syscall.Getrusage(syscall.RUSAGE_SELF, &before)
	began := time.Now()
	h.start(func(options *integrity.Options) { options.Governor = governed })
	h.await("files_watched", 1)
	took := time.Since(began)
	syscall.Getrusage(syscall.RUSAGE_SELF, &after)
	spent := time.Duration(after.Utime.Nano()+after.Stime.Nano()-before.Utime.Nano()-before.Stime.Nano()) * time.Nanosecond
	if took < 1200*time.Millisecond {
		t.Errorf("1516 entries charged at 1KiB each were walked in %s at 1MiB a second", took)
	}
	if spent > took/2 {
		t.Errorf("walking 1516 entries spent %s of processor time in %s", spent, took)
	}
	t.Logf("walked 1516 entries, hashing each, in %s, spending %s of processor time", took, spent)
}
