//go:build linux

package native_test

import (
	"bufio"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-agent-v2/internal/protocol"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
	controlv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/control/v1"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

type arrival struct {
	at      time.Time
	written time.Time
}

// The installed agent run as a service while the gate loads it and measures
// what it spends: sshd's stand-in decides outcomes at the pace a workload
// asks, and the platform takes every event, notes when it arrived, and may be
// out for a while or issue certificates that do not last.
type measuring struct {
	*gate
	writer   string
	sampler  *sampler
	refusing atomic.Bool
	lasting  atomic.Int64

	mu       sync.Mutex
	produced int
	pending  map[string]bool
	arrived  map[string]arrival
	repeated int
	strays   []string
	spent    []spent
}

func openMeasuring(t *testing.T) *measuring {
	g := open(t)
	m := &measuring{gate: g, writer: filepath.Join(g.scratch, "sshd"), pending: map[string]bool{}, arrived: map[string]arrival{}}
	t.Cleanup(func() {
		if m.sampler != nil {
			m.sampler.stop()
		}
	})
	copySelf(t, m.writer)
	handled, renewed := m.admit, m.renew
	g.platform.handling.Store(&handled)
	g.platform.renewing.Store(&renewed)
	g.platform.taking.Store(true)
	return m
}

func (m *measuring) admit(w http.ResponseWriter, r *http.Request, content []byte) bool {
	if m.refusing.Load() {
		w.Header().Set("Retry-After", "1")
		refuse(w, http.StatusServiceUnavailable, "backbone_unavailable", "", -1)
		return true
	}
	now := time.Now()
	records := protocol.Events.Records(content)
	events := make([]*eventv1.Event, len(records))
	for i, record := range records {
		events[i] = &eventv1.Event{}
		if err := proto.Unmarshal(record, events[i]); err != nil {
			refuse(w, http.StatusBadRequest, "malformed_payload", "", -1)
			return true
		}
	}
	if len(events) == 0 {
		refuse(w, http.StatusBadRequest, "malformed_payload", "", -1)
		return true
	}
	m.mu.Lock()
	for _, event := range events {
		user := event.GetAuthentication().GetUser().GetName()
		switch _, held := m.arrived[user]; {
		case !decided.MatchString(user):
		case held:
			m.repeated++
		default:
			m.arrived[user] = arrival{at: now, written: event.GetTime().GetEventTime().AsTime()}
			delete(m.pending, user)
		}
	}
	m.mu.Unlock()
	acknowledge(w, len(events))
	return true
}

func (m *measuring) renew(w http.ResponseWriter, agent string, asked *agentv1.RenewalRequest) bool {
	lasting := time.Duration(m.lasting.Load())
	if lasting == 0 {
		return false
	}
	answer := func(status int, body []byte) {
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(status)
		w.Write(body)
	}
	issued, err := issueBy(m.platform.authority, m.platform.key, m.platform.bundle(), m.platform.bundle(), asked.GetCsrPem(), agent,
		time.Now().Add(-time.Minute).Truncate(time.Second), time.Now().Add(lasting))
	if err != nil {
		encoded, _ := proto.Marshal(&controlv1.Refusal{Code: "malformed_certificate_request", Detail: err.Error()})
		answer(http.StatusUnprocessableEntity, encoded)
		return true
	}
	m.platform.renewals.Add(1)
	answer(http.StatusCreated, issued)
	return true
}

func (m *measuring) out(out bool) {
	m.refusing.Store(out)
	m.platform.taking.Store(!out)
}

type loading struct {
	process *exec.Cmd
	ended   chan struct{}
	once    sync.Once
	waited  error
}

func (m *measuring) load(t *testing.T, prefix string, count int, every time.Duration) *loading {
	t.Helper()
	process := exec.Command(m.writer, "-test.run=^$")
	process.Env = append(os.Environ(), fmt.Sprintf("%s=%s 1 %d %s", writerVariable, prefix, count, every))
	said, err := process.StdoutPipe()
	if err == nil {
		err = process.Start()
	}
	if err != nil {
		t.Fatalf("have sshd decide: %v", err)
	}
	l := &loading{process: process, ended: make(chan struct{})}
	t.Cleanup(func() {
		process.Process.Kill()
		l.wait()
	})
	go func() {
		defer close(l.ended)
		lines := bufio.NewScanner(said)
		for lines.Scan() {
			m.mu.Lock()
			if user, wrote := strings.CutPrefix(lines.Text(), "wrote "); wrote && decided.MatchString(user) {
				m.produced++
				if _, held := m.arrived[user]; !held {
					m.pending[user] = true
				}
			} else {
				m.strays = append(m.strays, lines.Text())
			}
			m.mu.Unlock()
		}
	}()
	return l
}

func (l *loading) wait() error {
	<-l.ended
	l.once.Do(func() { l.waited = l.process.Wait() })
	return l.waited
}

func (l *loading) done() bool {
	select {
	case <-l.ended:
		return true
	default:
		return false
	}
}

func (m *measuring) finished(t *testing.T, l *loading) {
	t.Helper()
	err := l.wait()
	m.mu.Lock()
	strays := slices.Clone(m.strays)
	m.mu.Unlock()
	if err != nil || len(strays) > 0 {
		t.Fatalf("sshd's stand-in ended with %v and said %q", err, strays)
	}
}

func (m *measuring) outcomes() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.produced
}

func (m *measuring) waiting() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.pending)
}

func (m *measuring) missing() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Sorted(maps.Keys(m.pending))
}

// caughtUp waits until the platform holds every outcome sshd decided so far,
// and says how long that took.
func (m *measuring) caughtUp(t *testing.T, within time.Duration) time.Duration {
	t.Helper()
	began := time.Now()
	for m.waiting() > 0 {
		if time.Since(began) > within {
			missing := m.missing()
			t.Fatalf("the platform does not hold within %s %d events sshd decided, %q first:\n%s", within, len(missing), missing[:min(len(missing), 5)],
				answer("journalctl", "--no-pager", "--output", "cat", "--lines", "40", "_SYSTEMD_INVOCATION_ID="+m.invocation))
		}
		time.Sleep(100 * time.Millisecond)
	}
	return time.Since(began)
}

// drained says when the platform took the first and the last event it took
// after since.
func (m *measuring) drained(since time.Time) (time.Time, time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var first, last time.Time
	for _, arrived := range m.arrived {
		if arrived.at.Before(since) {
			continue
		}
		if first.IsZero() || arrived.at.Before(first) {
			first = arrived.at
		}
		if arrived.at.After(last) {
			last = arrived.at
		}
	}
	return first, last
}

func (m *measuring) latencies(began, ended time.Time) (*spread, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var waited []float64
	for _, arrived := range m.arrived {
		if !arrived.at.Before(began) && !arrived.at.After(ended) {
			waited = append(waited, float64(arrived.at.Sub(arrived.written).Microseconds())/1e3)
		}
	}
	if len(waited) == 0 {
		return nil, 0
	}
	held := spreadOf(waited)
	return &held, len(waited)
}

func (m *measuring) measure(t *testing.T, workload, load string, began time.Time, before int, observed map[string]any) spent {
	t.Helper()
	ended := time.Now()
	s := summarize(workload, load, m.sampler.between(began, ended))
	s.Events = m.outcomes() - before
	s.Latency, s.Delivered = m.latencies(began, ended)
	s.Observed = observed
	m.mu.Lock()
	m.spent = append(m.spent, s)
	m.mu.Unlock()
	t.Logf("%s (%s) over %.0fs: processor %.2f%% (busiest %.1f%%), anonymous %s, agent resident %s, goroutines %v, descriptors %v, written %s, sent %s, events %d delivered %d, latency %v",
		workload, load, s.Seconds, 100*s.Processor, 100*s.ProcessorPeak, mebibytes(s.Anonymous.Most), mebibytes(s.Resident.Most),
		s.Goroutines.Most, s.Descriptors.Most, mebibytes(float64(s.Written)), mebibytes(float64(s.Received)), s.Events, s.Delivered, s.Latency)
	return s
}

func mebibytes(bytes float64) string {
	return fmt.Sprintf("%.1fMiB", bytes/(1<<20))
}

type host struct {
	Processor      string `json:"processor"`
	Processors     int    `json:"processors"`
	Memory         int64  `json:"memory"`
	Kernel         string `json:"kernel"`
	Virtualization string `json:"virtualization"`
	Container      string `json:"container"`
	System         string `json:"system"`
	Systemd        string `json:"systemd"`
	Filesystem     string `json:"filesystem"`
}

func described(t *testing.T) host {
	t.Helper()
	processor := ""
	if content, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		for line := range strings.Lines(string(content)) {
			if name, found := strings.CutPrefix(line, "model name"); found {
				processor = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(name), ":"))
				break
			}
		}
	}
	kernel, _ := os.ReadFile("/proc/sys/kernel/osrelease")
	return host{
		Processor:      processor,
		Processors:     runtime.NumCPU(),
		Memory:         fields("/proc/meminfo")["MemTotal"] << 10,
		Kernel:         strings.TrimSpace(string(kernel)),
		Virtualization: answer("systemd-detect-virt", "--vm"),
		Container:      answer("systemd-detect-virt", "--container"),
		System:         run(t, "sh", "-c", ". /etc/os-release && echo $PRETTY_NAME"),
		Systemd:        strings.SplitN(run(t, "systemctl", "--version"), "\n", 2)[0],
		Filesystem:     run(t, "stat", "--file-system", "--format", "%T", state),
	}
}

var method = []string{
	"every sample reads the control group of " + unit + ", which holds the agent and every program it runs, and procfs for each process in it",
	"processor: usage_usec of cpu.stat, as the share of one processor over the workload; processor_peak over its busiest " + busiest.String() + "; throttled: throttled_usec of cpu.stat over the same time; own_processor: utime and stime of the agent's /proc/PID/stat, without the programs it runs",
	"memory: memory.current of the control group, page cache included; anonymous: anon of memory.stat, the memory no file backs",
	"resident and resident_peak: VmRSS and VmHWM of the agent's process; others_resident: VmRSS of the programs it runs",
	"threads and descriptors: Threads of the agent's process and the entries of its /proc/PID/fd; tasks: pids.current of the control group",
	"read and written: rchar and wchar of /proc/PID/io summed over the processes, what they asked of files, pipes and sockets; storage_read and storage_written: read_bytes and write_bytes, what reached the storage layer; a process the agent reaped counts in the agent's",
	"goroutines and heap_held: what the agent's status says, rewritten every 30 seconds; spooled: the bytes of the files under spool/; outstanding: the records the status says wait for delivery",
	"received, sent and connections: the bytes and connections the emulated platform's ingest and renewal listeners took and gave, TLS records included",
	"latency_ms: from the time journald gave an outcome to when the platform took its event, for the events taken during the workload",
}

type measured struct {
	RecordedAt time.Time          `json:"recorded_at"`
	Build      string             `json:"build"`
	Host       host               `json:"host"`
	Service    map[string]string  `json:"service"`
	Method     []string           `json:"method"`
	Workloads  []spent            `json:"workloads"`
	Trends     map[string]float64 `json:"trends_per_hour,omitempty"`
	Every      string             `json:"sampled_every"`
	Samples    []usage            `json:"samples"`
}

func (m *measuring) keep(t *testing.T, name string, trends map[string]float64, thinned time.Duration) {
	t.Helper()
	if *evidence == "" {
		return
	}
	service := map[string]string{}
	for _, setting := range []string{"MemoryMax", "MemorySwapMax", "CPUQuotaPerSecUSec", "TasksMax", "LimitNOFILE"} {
		service[setting] = property(t, setting)
	}
	var kept []usage
	for _, u := range m.sampler.all() {
		if len(kept) == 0 || u.At.Sub(kept[len(kept)-1].At) >= thinned {
			kept = append(kept, u)
		}
	}
	m.mu.Lock()
	workloads := slices.Clone(m.spent)
	m.mu.Unlock()
	written, err := json.MarshalIndent(measured{RecordedAt: time.Now().UTC(), Build: run(t, agentPath, "-version"), Host: described(t), Service: service,
		Method: method, Workloads: workloads, Trends: trends, Every: max(thinned, m.sampler.every).String(), Samples: kept}, "", "  ")
	directory := filepath.Join(*evidence, "footprint")
	if err == nil {
		err = os.MkdirAll(directory, 0o755)
	}
	if err == nil {
		err = os.WriteFile(filepath.Join(directory, name+".json"), append(written, '\n'), 0o644)
	}
	if err != nil {
		t.Fatalf("write what the agent spent: %v", err)
	}
}
