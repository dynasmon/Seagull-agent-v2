//go:build linux

package native_test

import (
	"bufio"
	"bytes"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/status"
)

const agentName = "seagull-agent"

// What the service spent at one instant: the unit's control group counts the
// processor time, memory and tasks of the agent and of every program it runs,
// procfs the resident memory, threads, descriptors and input/output of each
// process, the agent's status its goroutines and heap, the installation the
// bytes its spool holds, and the platform what crossed its listeners.
type usage struct {
	At           time.Time `json:"at"`
	Process      int       `json:"process"`
	Processes    int       `json:"processes"`
	Processor    int64     `json:"processor_usec"`
	Own          int64     `json:"own_processor_usec"`
	Throttled    int64     `json:"throttled_usec"`
	Memory       int64     `json:"memory"`
	Anonymous    int64     `json:"anonymous"`
	Cached       int64     `json:"cached"`
	Tasks        int64     `json:"tasks"`
	Resident     int64     `json:"resident"`
	ResidentPeak int64     `json:"resident_peak"`
	Others       int64     `json:"others_resident"`
	Threads      int64     `json:"threads"`
	Descriptors  int64     `json:"descriptors"`
	Read         int64     `json:"read"`
	Written      int64     `json:"written"`
	Fetched      int64     `json:"storage_read"`
	Stored       int64     `json:"storage_written"`
	Goroutines   int64     `json:"goroutines"`
	Held         int64     `json:"heap_held"`
	Spooled      int64     `json:"spooled"`
	Outstanding  int64     `json:"outstanding"`
	Received     int64     `json:"received"`
	Sent         int64     `json:"sent"`
	Connections  int64     `json:"connections"`
}

type sampler struct {
	group    string
	account  int
	platform *platform
	every    time.Duration
	stopped  chan struct{}
	done     chan struct{}

	mu      sync.Mutex
	samples []usage
}

func sample(t *testing.T, g *gate, every time.Duration) *sampler {
	t.Helper()
	s := &sampler{group: filepath.Join("/sys/fs/cgroup", property(t, "ControlGroup")), account: g.uid, platform: g.platform, every: every,
		stopped: make(chan struct{}), done: make(chan struct{})}
	if _, err := os.Stat(filepath.Join(s.group, "cpu.stat")); err != nil {
		t.Fatalf("the service runs in no control group the gate can read: %v", err)
	}
	go s.run()
	return s
}

func (s *sampler) run() {
	defer close(s.done)
	tick := time.NewTicker(s.every)
	defer tick.Stop()
	for {
		taken := s.take()
		s.mu.Lock()
		s.samples = append(s.samples, taken)
		s.mu.Unlock()
		select {
		case <-s.stopped:
			return
		case <-tick.C:
		}
	}
}

func (s *sampler) stop() {
	select {
	case <-s.stopped:
	default:
		close(s.stopped)
	}
	<-s.done
}

func (s *sampler) between(began, ended time.Time) []usage {
	s.mu.Lock()
	defer s.mu.Unlock()
	first := slices.IndexFunc(s.samples, func(u usage) bool { return !u.At.Before(began) })
	if first < 0 {
		return nil
	}
	return slices.DeleteFunc(slices.Clone(s.samples[max(0, first-1):]), func(u usage) bool { return u.At.After(ended) })
}

func (s *sampler) all() []usage {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.samples)
}

func (s *sampler) latest() usage {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.samples) == 0 {
		return usage{}
	}
	return s.samples[len(s.samples)-1]
}

func (s *sampler) take() usage {
	u := usage{At: time.Now()}
	processor := fields(filepath.Join(s.group, "cpu.stat"))
	u.Processor, u.Throttled = processor["usage_usec"], processor["throttled_usec"]
	u.Memory = number(filepath.Join(s.group, "memory.current"))
	memory := fields(filepath.Join(s.group, "memory.stat"))
	u.Anonymous, u.Cached = memory["anon"], memory["file"]
	u.Tasks = number(filepath.Join(s.group, "pids.current"))
	listed, _ := os.ReadFile(filepath.Join(s.group, "cgroup.procs"))
	for _, line := range strings.Fields(string(listed)) {
		pid, err := strconv.Atoi(line)
		if err != nil {
			continue
		}
		proc := filepath.Join("/proc", line)
		described := fields(filepath.Join(proc, "status"))
		comm, _ := os.ReadFile(filepath.Join(proc, "comm"))
		moved := fields(filepath.Join(proc, "io"))
		u.Processes++
		u.Read, u.Written = u.Read+moved["rchar"], u.Written+moved["wchar"]
		u.Fetched, u.Stored = u.Fetched+moved["read_bytes"], u.Stored+moved["write_bytes"]
		if strings.TrimSpace(string(comm)) != agentName {
			u.Others += described["VmRSS"] << 10
			continue
		}
		u.Process = pid
		u.Resident, u.ResidentPeak, u.Threads = described["VmRSS"]<<10, described["VmHWM"]<<10, described["Threads"]
		if stat, err := os.ReadFile(filepath.Join(proc, "stat")); err == nil {
			if named := bytes.LastIndex(stat, []byte(") ")); named >= 0 {
				if ticks := strings.Fields(string(stat[named+2:])); len(ticks) > 12 {
					user, _ := strconv.ParseInt(ticks[11], 10, 64)
					system, _ := strconv.ParseInt(ticks[12], 10, 64)
					u.Own = (user + system) * 10_000
				}
			}
		}
		if open, err := os.ReadDir(filepath.Join(proc, "fd")); err == nil {
			u.Descriptors = int64(len(open))
		}
	}
	if held, err := status.ReadOwned(filepath.Join(state, "status"), s.account); err == nil {
		u.Goroutines, u.Held = int64(held.Resources.Goroutines), held.Resources.MemoryHeld
		for _, stream := range held.Streams {
			u.Outstanding += int64(stream.Outstanding)
		}
	}
	filepath.WalkDir(filepath.Join(state, "spool"), func(path string, entry fs.DirEntry, err error) error {
		if err == nil && entry.Type().IsRegular() {
			if described, err := entry.Info(); err == nil {
				u.Spooled += described.Size()
			}
		}
		return nil
	})
	for _, carried := range []*traffic{&s.platform.ingested, &s.platform.controlled} {
		u.Received += carried.received.Load()
		u.Sent += carried.sent.Load()
		u.Connections += carried.connections.Load()
	}
	return u
}

// fields reads the "name value" lines of a control group or procfs file, and
// the "Name: value kB" lines of /proc/PID/status, as numbers.
func fields(path string) map[string]int64 {
	held := map[string]int64{}
	content, err := os.ReadFile(path)
	if err != nil {
		return held
	}
	lines := bufio.NewScanner(bytes.NewReader(content))
	for lines.Scan() {
		parts := strings.Fields(strings.Replace(lines.Text(), ":", " ", 1))
		if len(parts) < 2 {
			continue
		}
		if value, err := strconv.ParseInt(parts[1], 10, 64); err == nil {
			held[parts[0]] = value
		}
	}
	return held
}

func number(path string) int64 {
	content, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	value, _ := strconv.ParseInt(strings.TrimSpace(string(content)), 10, 64)
	return value
}

type spread struct {
	Least  float64 `json:"least"`
	Median float64 `json:"median"`
	P95    float64 `json:"p95"`
	Most   float64 `json:"most"`
}

func spreadOf(values []float64) spread {
	if len(values) == 0 {
		return spread{}
	}
	sorted := slices.Sorted(slices.Values(values))
	at := func(share float64) float64 {
		return sorted[min(len(sorted)-1, int(math.Ceil(share*float64(len(sorted))))-1)]
	}
	return spread{Least: sorted[0], Median: at(0.5), P95: at(0.95), Most: sorted[len(sorted)-1]}
}

func spreadBy(samples []usage, of func(usage) int64) spread {
	values := make([]float64, 0, len(samples))
	for _, u := range samples {
		values = append(values, float64(of(u)))
	}
	return spreadOf(values)
}

// spent sums up what the samples of one workload say: counters as what they
// grew by, counting again from zero those of a process or control group that
// started anew, the processor as the share of one processor the service used,
// overall and over its busiest window, and gauges as their spread.
type spent struct {
	Workload      string         `json:"workload"`
	Load          string         `json:"load"`
	Began         time.Time      `json:"began"`
	Ended         time.Time      `json:"ended"`
	Seconds       float64        `json:"seconds"`
	Samples       int            `json:"samples"`
	Processor     float64        `json:"processor"`
	OwnProcessor  float64        `json:"own_processor"`
	ProcessorPeak float64        `json:"processor_peak"`
	Throttled     float64        `json:"throttled"`
	Memory        spread         `json:"memory"`
	Anonymous     spread         `json:"anonymous"`
	Resident      spread         `json:"resident"`
	ResidentPeak  int64          `json:"resident_peak"`
	Others        spread         `json:"others_resident"`
	Goroutines    spread         `json:"goroutines"`
	Threads       spread         `json:"threads"`
	Descriptors   spread         `json:"descriptors"`
	Tasks         spread         `json:"tasks"`
	Spooled       spread         `json:"spooled"`
	Outstanding   spread         `json:"outstanding"`
	Read          int64          `json:"read"`
	Written       int64          `json:"written"`
	Fetched       int64          `json:"storage_read"`
	Stored        int64          `json:"storage_written"`
	Received      int64          `json:"received"`
	Sent          int64          `json:"sent"`
	Connections   int64          `json:"connections"`
	Events        int            `json:"events"`
	Delivered     int            `json:"delivered"`
	Latency       *spread        `json:"latency_ms,omitempty"`
	Observed      map[string]any `json:"observed,omitempty"`
}

const busiest = 5 * time.Second

func summarize(workload, load string, samples []usage) spent {
	s := spent{Workload: workload, Load: load, Samples: len(samples)}
	if len(samples) < 2 {
		return s
	}
	first, last := samples[0], samples[len(samples)-1]
	s.Began, s.Ended = first.At, last.At
	s.Seconds = last.At.Sub(first.At).Seconds()
	steps := func(of func(usage) int64, perProcess bool) []int64 {
		grown := make([]int64, len(samples))
		held := 0
		for i := 1; i < len(samples); i++ {
			if perProcess && samples[i].Process == 0 {
				continue
			}
			previous, current := of(samples[held]), of(samples[i])
			restarted := samples[i].Process != samples[held].Process && samples[i].Process != 0 && samples[held].Process != 0
			switch {
			case perProcess && samples[held].Process == 0:
			case restarted || !perProcess && current < previous:
				grown[i] = current
			case current > previous:
				grown[i] = current - previous
			}
			held = i
		}
		return grown
	}
	total := func(grown []int64) (sum int64) {
		for _, step := range grown {
			sum += step
		}
		return sum
	}
	processor := steps(func(u usage) int64 { return u.Processor }, false)
	s.Processor = float64(total(processor)) / 1e6 / s.Seconds
	s.OwnProcessor = float64(total(steps(func(u usage) int64 { return u.Own }, true))) / 1e6 / s.Seconds
	s.Throttled = float64(total(steps(func(u usage) int64 { return u.Throttled }, false))) / 1e6 / s.Seconds
	s.ProcessorPeak = s.Processor
	stride := max(1, int(math.Round(busiest.Seconds()*float64(len(samples)-1)/s.Seconds)))
	for i := stride; i < len(samples); i++ {
		var spent int64
		for _, step := range processor[i-stride+1 : i+1] {
			spent += step
		}
		s.ProcessorPeak = max(s.ProcessorPeak, float64(spent)/1e6/samples[i].At.Sub(samples[i-stride].At).Seconds())
	}
	s.Memory = spreadBy(samples, func(u usage) int64 { return u.Memory })
	s.Anonymous = spreadBy(samples, func(u usage) int64 { return u.Anonymous })
	s.Resident = spreadBy(samples, func(u usage) int64 { return u.Resident })
	s.Others = spreadBy(samples, func(u usage) int64 { return u.Others })
	s.Goroutines = spreadBy(slices.DeleteFunc(slices.Clone(samples), func(u usage) bool { return u.Goroutines == 0 }), func(u usage) int64 { return u.Goroutines })
	s.Threads = spreadBy(samples, func(u usage) int64 { return u.Threads })
	s.Descriptors = spreadBy(samples, func(u usage) int64 { return u.Descriptors })
	s.Tasks = spreadBy(samples, func(u usage) int64 { return u.Tasks })
	s.Spooled = spreadBy(samples, func(u usage) int64 { return u.Spooled })
	s.Outstanding = spreadBy(samples, func(u usage) int64 { return u.Outstanding })
	for _, u := range samples {
		s.ResidentPeak = max(s.ResidentPeak, u.ResidentPeak)
	}
	s.Read, s.Written = total(steps(func(u usage) int64 { return u.Read }, true)), total(steps(func(u usage) int64 { return u.Written }, true))
	s.Fetched, s.Stored = total(steps(func(u usage) int64 { return u.Fetched }, true)), total(steps(func(u usage) int64 { return u.Stored }, true))
	s.Received, s.Sent = max(0, last.Received-first.Received), max(0, last.Sent-first.Sent)
	s.Connections = max(0, last.Connections-first.Connections)
	return s
}

// trend is how fast a gauge grew over the samples, per hour, as the slope of
// the least squares line through them.
func trend(samples []usage, of func(usage) int64) float64 {
	if len(samples) < 2 {
		return 0
	}
	var n, sumX, sumY, sumXX, sumXY float64
	for _, u := range samples {
		x, y := u.At.Sub(samples[0].At).Hours(), float64(of(u))
		n, sumX, sumY, sumXX, sumXY = n+1, sumX+x, sumY+y, sumXX+x*x, sumXY+x*y
	}
	if spreadX := n*sumXX - sumX*sumX; spreadX > 0 {
		return (n*sumXY - sumX*sumY) / spreadX
	}
	return 0
}

func TestASummaryCountsWhatARestartedServiceSpentFromZero(t *testing.T) {
	at := time.Unix(1_800_000_000, 0)
	samples := []usage{
		{At: at, Process: 10, Processor: 5_000_000, Written: 900, Received: 40},
		{At: at.Add(time.Second), Process: 10, Processor: 5_100_000, Written: 1000, Received: 50},
		{At: at.Add(2 * time.Second), Received: 50},
		{At: at.Add(3 * time.Second), Process: 11, Processor: 80_000, Written: 300, Received: 70},
		{At: at.Add(4 * time.Second), Process: 11, Processor: 280_000, Written: 400, Received: 90},
		{At: at.Add(5 * time.Second), Process: 12, Processor: 9_000_000, Written: 50, Received: 90},
	}
	s := summarize("restarted", "", samples)
	if s.Seconds != 5 || math.Abs(s.Processor-(0.1+0.08+0.2+9)/5) > 1e-9 || s.Written != 100+300+100+50 || s.Received != 50 {
		t.Errorf("the summary counts %.4g seconds, %.4g of a processor, %d bytes written and %d received", s.Seconds, s.Processor, s.Written, s.Received)
	}
	var busy []usage
	for second := range 11 {
		spent := int64(min(second, 5)*100_000 + max(second-5, 0)*500_000)
		busy = append(busy, usage{At: at.Add(time.Duration(second) * time.Second), Process: 10, Processor: spent})
	}
	if s := summarize("busy", "", busy); math.Abs(s.Processor-0.3) > 1e-9 || math.Abs(s.ProcessorPeak-0.5) > 1e-9 {
		t.Errorf("half a processor for the last 5 of 10 seconds summarize as %.4g overall and %.4g at the busiest", s.Processor, s.ProcessorPeak)
	}
	if growing := trend([]usage{{At: at, Goroutines: 10}, {At: at.Add(time.Hour), Goroutines: 11}, {At: at.Add(2 * time.Hour), Goroutines: 12}}, func(u usage) int64 { return u.Goroutines }); growing != 1 {
		t.Errorf("goroutines growing by one an hour trend by %v", growing)
	}
	if held := spreadOf([]float64{4, 1, 3, 2}); held != (spread{Least: 1, Median: 2, P95: 4, Most: 4}) {
		t.Errorf("the spread of 1 to 4 is %+v", held)
	}
}
