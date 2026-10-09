package network_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/governor"
	"github.com/dynasmon/Seagull-agent-v2/internal/modules/network"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/accounts"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/sockets"
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
	state    string
	log      *logged
	governor *governor.Governor

	mu      sync.Mutex
	current sockets.Reading
	failure error
}

func prepare(t *testing.T) *harness {
	t.Helper()
	h := &harness{t: t, state: t.TempDir(), log: &logged{}}
	if err := os.Chmod(h.state, 0o700); err != nil {
		t.Fatal(err)
	}
	governed, err := governor.New(slog.New(slog.NewJSONHandler(h.log, nil)), installation, governor.Budget{Scans: 1, ScanBytesPerSecond: 256 << 20, Uploads: 1, UploadBytesPerSecond: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	h.governor = governed
	return h
}

func (h *harness) shows(reading sockets.Reading, failure error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.current, h.failure = reading, failure
}

func (h *harness) read(context.Context, sockets.Limits) (sockets.Reading, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.current, h.failure
}

type running struct {
	collector *network.Collector
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

func (h *harness) start(adjust func(*network.Options)) *running {
	h.t.Helper()
	directory, err := os.OpenRoot(h.state)
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { directory.Close() })
	options := network.Options{
		Governor:  h.governor,
		Directory: directory,
		Logger:    slog.New(slog.NewJSONHandler(h.log, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Interval:  func() time.Duration { return time.Hour },
		Read:      h.read,
		Accounts: func() (accounts.Database, error) {
			return accounts.Database{Accounts: []accounts.Account{{Name: "root", UID: 0}, {Name: "www-data", UID: 33}, {Name: "nathan", UID: 1000}, {Name: "toor", UID: 0}}}, nil
		},
	}
	if adjust != nil {
		adjust(&options)
	}
	collector, err := network.New(options)
	if err != nil {
		h.t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(h.t.Context())
	started := &running{collector: collector, cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(started.done)
		started.err = collector.Collect(ctx)
	}()
	h.t.Cleanup(cancel)
	return started
}

func (h *harness) await(message string, count int) []map[string]any {
	h.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if found := h.log.lines(message); len(found) >= count {
			return found
		}
		if time.Now().After(deadline) {
			h.t.Fatalf("the module wrote down %d %s within 10s, want %d:\n%s", len(h.log.lines(message)), message, count, h.log.buffer.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func socket(protocol sockets.Protocol, local, remote string, state sockets.State, user uint32, inode uint64) sockets.Socket {
	owned := !(protocol == sockets.TCP && state == sockets.TimeWait)
	return sockets.Socket{Protocol: protocol, Local: netip.MustParseAddrPort(local), Remote: netip.MustParseAddrPort(remote), State: state, User: user, Owned: owned, Inode: inode}
}

func host(held ...sockets.Socket) sockets.Reading {
	return sockets.Reading{Boot: "6c1e4c49-0f6e-4a39-9d4e-3c1f2b7a9e10", Hidden: true, Namespaces: []sockets.Namespace{{Own: true, Key: 3, ID: "net:[4026531833]", Host: true, Sockets: held}}}
}

var (
	ssh     = socket(sockets.TCP, "0.0.0.0:22", "0.0.0.0:0", sockets.Listen, 0, 1)
	web     = socket(sockets.TCP, "[::]:80", "[::]:0", sockets.Listen, 33, 2)
	session = socket(sockets.TCP, "10.0.0.5:22", "203.0.113.7:51514", sockets.Established, 0, 3)
	fetch   = socket(sockets.TCP, "10.0.0.5:41000", "198.51.100.1:443", sockets.Established, 1000, 4)
)

func TestTheModuleTakesTheBaselineAndSaysWhatChangedWhileItWasStopped(t *testing.T) {
	h := prepare(t)
	h.shows(host(ssh, session), nil)
	first := h.start(nil)
	watched := h.await("network_watched", 1)[0]
	if watched["namespaces"] != float64(1) || watched["listeners"] != float64(1) || watched["flows"] != float64(1) || watched["connections"] != float64(1) || watched["module"] != "network" {
		t.Errorf("the module took the baseline as %v", watched)
	}
	first.stop(t)
	for _, message := range []string{"listener_opened", "flow_started"} {
		if said := h.log.lines(message); len(said) != 0 {
			t.Errorf("the baseline said %v", said)
		}
	}
	if described, err := os.Stat(filepath.Join(h.state, "network.json")); err != nil || described.Mode().Perm() != 0o600 {
		t.Errorf("the module wrote down what it saw as %v, %v", described, err)
	}

	h.shows(host(ssh, web, fetch), nil)
	second := h.start(nil)
	h.await("network_observed", 1)
	second.stop(t)
	opened := h.log.lines("listener_opened")
	if len(opened) != 1 {
		t.Fatalf("a listener opened while the module was stopped was said %d times", len(opened))
	}
	namespace, _ := opened[0]["namespace"].(map[string]any)
	if opened[0]["origin"] != "start" || opened[0]["protocol"] != "tcp" || opened[0]["address"] != "::" || opened[0]["port"] != float64(80) ||
		fmt.Sprint(opened[0]["accounts"]) != "[www-data]" || opened[0]["sockets"] != float64(1) || opened[0]["association"] != "accounts" ||
		namespace["own"] != true || namespace["host"] != true || namespace["id"] != "net:[4026531833]" || namespace["process"] != nil {
		t.Errorf("a listener opened while the module was stopped was said as %v", opened[0])
	}
	started := h.log.lines("flow_started")
	if len(started) != 1 || started[0]["direction"] != "outbound" || started[0]["remote"] != "198.51.100.1" || started[0]["port"] != float64(443) ||
		started[0]["account"] != "nathan" || started[0]["connections"] != float64(1) || fmt.Sprint(started[0]["states"]) != "[established]" || started[0]["origin"] != "start" {
		t.Errorf("a flow that started while the module was stopped was said as %v", started)
	}
	ended := h.log.lines("flow_ended")
	if len(ended) != 1 || ended[0]["direction"] != "inbound" || ended[0]["remote"] != "203.0.113.7" || ended[0]["port"] != float64(22) || ended[0]["account"] != "root" {
		t.Errorf("a flow that ended while the module was stopped was said as %v", ended)
	}
	if observed := h.log.lines("network_observed")[0]; observed["because"] != "start" || observed["changes"] != float64(3) || observed["level"] != "INFO" {
		t.Errorf("the module observed as it started %v", observed)
	}
}

func TestTheModuleSaysWhatItCannotSeeAndHowToShowIt(t *testing.T) {
	h := prepare(t)
	h.shows(host(ssh), nil)
	r := h.start(nil)
	hidden := h.await("network_not_covered", 1)[0]
	r.stop(t)
	if reason, recovery := fmt.Sprint(hidden["reason"]), fmt.Sprint(hidden["recovery"]); hidden["level"] != "WARN" || !strings.Contains(reason, "procfs hides the processes of other accounts") ||
		!strings.Contains(recovery, "ProtectProc=default") || !strings.Contains(recovery, "CAP_SYS_PTRACE CAP_DAC_READ_SEARCH") || !strings.Contains(recovery, "~process_vm_readv process_vm_writev") {
		t.Errorf("with procfs hiding the other processes, the module said %v", hidden)
	}
	if coverage := r.collector.Stats().Coverage(); !strings.Contains(coverage, "procfs hides") {
		t.Errorf("the module says it does not see %q", coverage)
	}

	shown := host(ssh)
	shown.Hidden, shown.Unread = false, 12
	h.shows(shown, nil)
	r = h.start(nil)
	unread := h.await("network_not_covered", 2)[1]
	r.stop(t)
	if reason := fmt.Sprint(unread["reason"]); !strings.Contains(reason, "the descriptors of 12 processes") || strings.Contains(fmt.Sprint(unread["recovery"]), "to watch the other namespaces") {
		t.Errorf("with the processes shown and their descriptors unread, the module said %v", unread)
	}

	shown.Unread = 0
	shown.Namespaces = append(shown.Namespaces, sockets.Namespace{Key: 9, Through: sockets.Process{PID: 500, Name: "big\x00", StartedAt: time.Now()}, Failure: fmt.Errorf("%w: more than 3", sockets.ErrTooMany)})
	h.shows(shown, nil)
	r = h.start(nil)
	tooMany := h.await("network_not_covered", 3)[2]
	if reason := fmt.Sprint(tooMany["reason"]); !strings.Contains(reason, `the sockets of the namespace of "big\x00" (pid 500)`) {
		t.Errorf("with a namespace holding more sockets than read, the module said %v", tooMany)
	}
	if stats := r.collector.Stats(); stats.Failure != nil || len(stats.Unreadable) != 1 || stats.Namespaces != 1 {
		t.Errorf("with a namespace it cannot read, the module holds %+v", stats)
	}
	r.stop(t)

	shown.Unread = 3
	h.shows(sockets.Reading{Boot: shown.Boot, Namespaces: shown.Namespaces[:1], Unread: 3}, nil)
	r = h.start(func(options *network.Options) { options.Interval = func() time.Duration { return time.Second } })
	h.await("network_not_covered", 4)
	h.shows(sockets.Reading{Boot: shown.Boot, Namespaces: shown.Namespaces[:1]}, nil)
	if covered := h.await("network_covered", 1)[0]; covered["namespaces"] != float64(1) {
		t.Errorf("seeing everything, the module said %v", covered)
	}
	r.stop(t)
}

func TestAReadingThatFailsIsSaidAndTheModuleGoesOn(t *testing.T) {
	h := prepare(t)
	h.shows(host(ssh), nil)
	r := h.start(func(options *network.Options) { options.Interval = func() time.Duration { return time.Second } })
	h.await("network_watched", 1)
	h.shows(sockets.Reading{}, fmt.Errorf("%w: the agent's own network namespace", sockets.ErrUnreadable))
	failed := h.await("network_not_observed", 1)[0]
	if failed["level"] != "WARN" || failed["failures"] != float64(1) || !strings.Contains(fmt.Sprint(failed["recovery"]), "next round") {
		t.Errorf("a reading that failed was said as %v", failed)
	}
	if stats := r.collector.Stats(); !errors.Is(stats.Failure, sockets.ErrUnreadable) || stats.Listeners != 1 {
		t.Errorf("after a reading that failed, the module holds %+v", stats)
	}
	h.shows(host(ssh, web), nil)
	again := h.await("network_observed_again", 1)[0]
	h.await("listener_opened", 1)
	r.stop(t)
	if again["failures"] == float64(0) || r.collector.Stats().Failure != nil {
		t.Errorf("the module observed again as %v, holding %+v", again, r.collector.Stats())
	}
}

func TestAHostWithoutSocketTablesFailsTheModule(t *testing.T) {
	h := prepare(t)
	h.shows(sockets.Reading{}, fmt.Errorf("read the sockets of plan9: %w", errors.ErrUnsupported))
	r := h.start(nil)
	select {
	case <-r.done:
	case <-time.After(10 * time.Second):
		t.Fatal("the module kept running on a host without socket tables")
	}
	if !errors.Is(r.err, errors.ErrUnsupported) {
		t.Errorf("on a host without socket tables the module returned %v", r.err)
	}
}

func TestWhatTheModuleWroteDownDecidesHowItStarts(t *testing.T) {
	h := prepare(t)
	path := filepath.Join(h.state, "network.json")
	if err := os.WriteFile(path, []byte("{\"format\": 1, \"namespaces\": ["), 0o600); err != nil {
		t.Fatal(err)
	}
	h.shows(host(ssh), nil)
	r := h.start(nil)
	lost := h.await("network_state_lost", 1)[0]
	h.await("network_watched", 1)
	r.stop(t)
	if lost["level"] != "WARN" || !strings.Contains(fmt.Sprint(lost["error"]), "cannot be read") {
		t.Errorf("a state the module cannot read was said as %v", lost)
	}

	if err := os.WriteFile(path, []byte(`{"format": 2}`), 0o600); err != nil {
		t.Fatal(err)
	}
	r = h.start(nil)
	<-r.done
	if !errors.Is(r.err, network.ErrNewer) {
		t.Errorf("a state a newer agent wrote started the module as %v", r.err)
	}
	if err := os.WriteFile(path, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	r = h.start(nil)
	<-r.done
	if !errors.Is(r.err, network.ErrInsecure) {
		t.Errorf("a state others may read started the module as %v", r.err)
	}
}

func TestTheModuleWritesDownAtMostAThousandChangesAMinute(t *testing.T) {
	h := prepare(t)
	h.shows(host(), nil)
	r := h.start(nil)
	h.await("network_watched", 1)
	r.stop(t)
	var many []sockets.Socket
	for port := range 1500 {
		many = append(many, socket(sockets.TCP, fmt.Sprintf("10.0.0.5:%d", 20000+port), "0.0.0.0:0", sockets.Listen, 1000, uint64(100+port)))
	}
	h.shows(host(many...), nil)
	r = h.start(nil)
	withheld := h.await("network_changes_not_logged", 1)[0]
	r.stop(t)
	counted, _ := withheld["withheld"].(map[string]any)
	if said := len(h.log.lines("listener_opened")); said != 1000 || counted["listener_opened"] != float64(500) || withheld["level"] != "WARN" {
		t.Errorf("1500 listeners opened were said %d times, and %v withheld", said, withheld)
	}
	if stats := r.collector.Stats(); stats.Changes != 1500 || stats.Unlogged != 500 || stats.Listeners != 1500 {
		t.Errorf("after 1500 changes the module holds %+v", stats)
	}
}

func TestTheModuleWatchesTheSocketsOfThisHost(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the module watches the network of linux hosts")
	}
	account, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	h := prepare(t)
	r := h.start(func(options *network.Options) {
		options.Read = nil
		options.Accounts = nil
		options.Interval = func() time.Duration { return time.Second }
	})
	h.await("network_watched", 1)
	listening, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		listening, err = net.Listen("tcp4", "127.0.0.1:0")
	}
	if err != nil {
		t.Fatal(err)
	}
	port := float64(listening.Addr().(*net.TCPAddr).Port)
	var opened map[string]any
	for opened == nil {
		for _, said := range h.await("listener_opened", 1) {
			if said["port"] == port {
				opened = said
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if processes := fmt.Sprint(opened["processes"]); fmt.Sprint(opened["accounts"]) != "["+account.Username+"]" ||
		!strings.Contains(processes, fmt.Sprintf("(pid %d)", os.Getpid())) || opened["origin"] != "interval" {
		t.Errorf("a listener this test opened was said as %v", opened)
	}
	listening.Close()
	deadline := time.Now().Add(10 * time.Second)
	for !slices.ContainsFunc(h.log.lines("listener_closed"), func(said map[string]any) bool { return said["port"] == port }) {
		if time.Now().After(deadline) {
			t.Fatalf("the listener this test closed was not said closed:\n%s", h.log.buffer.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
	r.stop(t)
}
