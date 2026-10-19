//go:build linux

package native_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"time"

	assessmentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/assessment/v1"
	policyv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/policy/v1"
)

const (
	window       = 2 * time.Minute
	steadyEvery  = 100 * time.Millisecond
	burstEvery   = time.Millisecond
	burstCount   = 60000
	boundedCount = 120000
	boundedSpool = 16 << 20
	shownDropIns = "footprint.conf"
	everything   = "[Service]\nProtectProc=default\nReadOnlyPaths=/proc\nProtectHome=read-only\nCapabilityBoundingSet=CAP_SYS_PTRACE CAP_DAC_READ_SEARCH\nAmbientCapabilities=CAP_SYS_PTRACE CAP_DAC_READ_SEARCH\nSystemCallFilter=~process_vm_readv process_vm_writev\n"
)

// What the installed agent spends under each workload it meets, measured from
// outside the service as it runs with the package's settings, and held to the
// budgets this platform was measured to need: idle, collecting at a steady
// pace and in a burst, holding events while the platform is out and
// delivering them once it is back, pausing at a spool that reached its budget,
// starting and taking stock of the host, taking the baseline of the files it
// watches, and running every module at once.
func TestTheInstalledAgentSpendsWithinItsBudgets(t *testing.T) {
	m := openMeasuring(t)
	for _, step := range []struct {
		name string
		run  func(*testing.T)
	}{
		{name: "the service runs the agent as the package sets it up, enrolled and delivering", run: m.settle},
		{name: "idle, the agent waits for something to collect", run: m.idle},
		{name: "sshd decides outcomes at a steady pace and the agent delivers each as it comes", run: m.steady},
		{name: "sshd decides a burst of outcomes and the agent catches up", run: m.burst},
		{name: "while the platform is out, the agent keeps what it collects on disk", run: m.outage},
		{name: "once the platform is back, the agent delivers what it kept", run: m.recovery},
		{name: "a spool that reaches its budget pauses collection, and the agent delivers everything once the platform is back", run: m.bounded},
		{name: "the agent starts and takes stock of the host", run: m.stocktaking},
		{name: "the agent takes the baseline of the files it watches unless told otherwise", run: m.baseline},
		{name: "every module runs at once, seeing what the documented drop-ins let it see", run: m.combined},
		{name: "every workload spent within its budget", run: m.budgeted},
	} {
		if !t.Run(step.name, step.run) {
			t.Fatalf("the measurement stops at %q: every later step depends on it", step.name)
		}
	}
}

func (m *measuring) settle(t *testing.T) {
	m.install(t)
	m.collects, m.inventories = true, true
	m.tuned = map[string]any{}
	m.configure(t)
	m.enroll(t)
	began := time.Now()
	m.start(t)
	m.sampler = sample(t, m.gate, time.Second)
	await(t, m.invocation, "collection_started", 10*time.Second)
	await(t, m.invocation, "credential_renewed", time.Minute)
	m.stock(t, began.Add(-time.Second), stocked...)
	m.finished(t, m.load(t, "settle", 20, steadyEvery))
	m.caughtUp(t, time.Minute)
	time.Sleep(30 * time.Second)
}

func (m *measuring) idle(t *testing.T) {
	began, before := time.Now(), m.outcomes()
	time.Sleep(window)
	m.measure(t, "idle", "nothing to collect, the status written and reported", began, before, nil)
}

func (m *measuring) steady(t *testing.T) {
	began, before := time.Now(), m.outcomes()
	m.finished(t, m.load(t, "steady", int(window/steadyEvery), steadyEvery))
	m.caughtUp(t, time.Minute)
	m.measure(t, "steady", "10 outcomes a second", began, before, nil)
}

func (m *measuring) burst(t *testing.T) {
	began, before := time.Now(), m.outcomes()
	m.finished(t, m.load(t, "burst", burstCount, burstEvery))
	wrote := time.Since(began)
	caught := m.caughtUp(t, 5*time.Minute)
	m.measure(t, "burst", fmt.Sprintf("%d outcomes as fast as one writer hands them to journald, up to 1000 a second", burstCount), began, before,
		map[string]any{"written_seconds": wrote.Seconds(), "caught_up_seconds_after": caught.Seconds()})
}

func (m *measuring) outage(t *testing.T) {
	m.out(true)
	began, before := time.Now(), m.outcomes()
	m.finished(t, m.load(t, "outage", int(window/steadyEvery), steadyEvery))
	if held := m.waiting(); held < int(window/steadyEvery) {
		t.Fatalf("while the platform was out it took all but %d events", held)
	}
	await(t, m.invocation, "delivery_failed", time.Second)
	m.measure(t, "outage", "10 outcomes a second while the platform answers 503 backbone_unavailable", began, before, map[string]any{"held": m.waiting()})
}

func (m *measuring) recovery(t *testing.T) {
	began, before, held := time.Now(), m.outcomes(), m.waiting()
	m.out(false)
	m.caughtUp(t, 10*time.Minute)
	time.Sleep(15 * time.Second)
	m.measure(t, "recovery", fmt.Sprintf("the %d events held while the platform was out, delivered once it is back", held), began, before, m.delivering(began, held))
}

func (m *measuring) delivering(back time.Time, held int) map[string]any {
	first, last := m.drained(back)
	observed := map[string]any{"held": held, "resumed_after_seconds": first.Sub(back).Seconds(), "drained_seconds": last.Sub(first).Seconds()}
	if drained := last.Sub(first).Seconds(); drained > 0 {
		observed["events_per_second"] = float64(held) / drained
	}
	return observed
}

func (m *measuring) bounded(t *testing.T) {
	m.tuned["spool"] = map[string]any{"max_bytes": "16MiB"}
	m.collecting(t, true)
	m.out(true)
	began, before := time.Now(), m.outcomes()
	loaded := m.load(t, "bounded", boundedCount, burstEvery)
	paused := await(t, m.invocation, "spool_admission_paused", 3*time.Minute)
	m.finished(t, loaded)
	time.Sleep(20 * time.Second)
	m.measure(t, "bounded", fmt.Sprintf("%d outcomes up to 1000 a second while the platform is out and spool.max_bytes is 16MiB", boundedCount), began, before,
		map[string]any{"paused": paused["stream"], "held": m.waiting()})

	began, before = time.Now(), m.outcomes()
	held := m.waiting()
	m.out(false)
	m.caughtUp(t, 15*time.Minute)
	resumed := await(t, m.invocation, "spool_admission_resumed", time.Minute)
	time.Sleep(15 * time.Second)
	observed := m.delivering(began, held)
	observed["paused_for"] = resumed["paused"]
	m.measure(t, "bounded recovery", fmt.Sprintf("the %d events the spool and the journal held, delivered once the platform is back", held), began, before, observed)
	delete(m.tuned, "spool")
	m.collecting(t, true)
}

func (m *measuring) stocktaking(t *testing.T) {
	m.debugging = true
	m.write(t)
	began, before := time.Now(), m.outcomes()
	m.restarted(t)
	taken := await(t, m.invocation, "inventory_taken", 2*time.Minute)
	time.Sleep(15 * time.Second)
	m.measure(t, "start and stocktaking", "the agent started on its installation and took stock of the host", began, before,
		map[string]any{"took": taken["took"], "admitted": taken["admitted"]})
	m.debugging = false
	m.collecting(t, true)
}

func (m *measuring) baseline(t *testing.T) {
	t.Cleanup(func() {
		delete(m.tuned, "modules")
		m.collecting(t, true)
	})
	m.tuned["modules"] = map[string]any{"authentication": map[string]any{"enabled": true}, "inventory": map[string]any{"enabled": true}, "files": map[string]any{"enabled": true}}
	began, before := time.Now(), m.outcomes()
	m.collecting(t, true)
	watched := await(t, m.invocation, "files_watched", 10*time.Minute)
	time.Sleep(15 * time.Second)
	m.measure(t, "files baseline", "the files module enabled on the paths it watches by default, taking their baseline", began, before,
		map[string]any{"took": watched["took"], "entries": watched["entries"], "directories": watched["directories"], "watched": watched["watched"]})
}

func (m *measuring) combined(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("draw the signing key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("encode the signer: %v", err)
	}
	t.Cleanup(func() {
		os.Remove(filepath.Join(overrides, shownDropIns))
		exec.Command("systemctl", "daemon-reload").Run()
		m.platform.handed.Store(nil)
		m.signers = ""
		delete(m.tuned, "modules")
	})
	place(t, signersPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	order, expected := checklist()
	sealed := sealPolicy(t, 1, &policyv1.Settings{
		Modules:    []*policyv1.ModuleSettings{{Module: policyv1.Module_MODULE_ASSESSMENT, Collection: policyv1.Collection_COLLECTION_ENABLED}},
		Assessment: &assessmentv1.Checklist{Checks: checks(order, expected)},
	}, key)
	m.platform.handed.Store(&sealed)
	m.signers = signersPath
	m.tuned["modules"] = map[string]any{"authentication": map[string]any{"enabled": true}, "inventory": map[string]any{"enabled": true},
		"processes": map[string]any{"enabled": true}, "files": map[string]any{"enabled": true}, "network": map[string]any{"enabled": true}}
	m.write(t)
	if err := os.MkdirAll(overrides, 0o755); err != nil {
		t.Fatalf("create %s: %v", overrides, err)
	}
	place(t, filepath.Join(overrides, shownDropIns), []byte(everything))
	run(t, "systemctl", "daemon-reload")

	began, before := time.Now(), m.outcomes()
	m.restarted(t)
	m.stock(t, began, "process")
	walked := await(t, m.invocation, "files_walked", 10*time.Minute)
	listened := await(t, m.invocation, "network_watched", time.Minute)
	assessed := await(t, m.invocation, "assessment_admitted", 2*time.Minute)
	time.Sleep(15 * time.Second)
	m.measure(t, "every module starting", "authentication, inventory, processes, files, network and assessment started at once with the documented drop-ins", began, before,
		map[string]any{"files_took": walked["took"], "files_entries": walked["entries"], "network_took": listened["took"], "assessment_took": assessed["took"], "checks": len(order)})

	began, before = time.Now(), m.outcomes()
	m.finished(t, m.load(t, "combined", int(window/steadyEvery), steadyEvery))
	m.caughtUp(t, time.Minute)
	m.measure(t, "every module steady", "10 outcomes a second with every module running", began, before, nil)
}

type budget struct {
	workload string
	what     string
	limit    float64
	least    bool
	of       func(spent) float64
}

func spends(workload, what string, most float64, of func(spent) float64) budget {
	return budget{workload: workload, what: what, limit: most, of: of}
}

func delivers(workload, what string, least float64, of func(spent) float64) budget {
	return budget{workload: workload, what: what, limit: least, least: true, of: of}
}

func noted(name string) func(spent) float64 {
	return func(s spent) float64 {
		if value, ok := s.Observed[name].(float64); ok {
			return value
		}
		return math.NaN()
	}
}

func slowest(s spent) float64 {
	if s.Latency == nil {
		return math.NaN()
	}
	return s.Latency.Most
}

func processor(s spent) float64   { return s.Processor }
func anonymous(s spent) float64   { return s.Anonymous.Most }
func goroutines(s spent) float64  { return s.Goroutines.Most }
func descriptors(s spent) float64 { return s.Descriptors.Most }
func writtenPerSecond(s spent) float64 {
	return float64(s.Written) / s.Seconds
}

var budgets = []budget{
	spends("idle", "share of one processor", 0.005, processor),
	spends("idle", "anonymous memory", 32<<20, anonymous),
	spends("idle", "goroutines", 40, goroutines),
	spends("idle", "descriptors", 48, descriptors),
	spends("idle", "bytes written a second", 4<<10, writtenPerSecond),
	spends("steady", "share of one processor", 0.03, processor),
	spends("steady", "anonymous memory", 32<<20, anonymous),
	spends("steady", "slowest delivery, in milliseconds", 2000, slowest),
	spends("burst", "anonymous memory", 48<<20, anonymous),
	spends("burst", "seconds to catch up once sshd stopped", 30, noted("caught_up_seconds_after")),
	spends("outage", "anonymous memory", 32<<20, anonymous),
	spends("recovery", "anonymous memory", 48<<20, anonymous),
	spends("bounded", "bytes the spool held", boundedSpool, func(s spent) float64 { return s.Spooled.Most }),
	spends("bounded", "anonymous memory", 32<<20, anonymous),
	delivers("bounded recovery", "events delivered a second", 1500, noted("events_per_second")),
	spends("bounded recovery", "anonymous memory", 48<<20, anonymous),
	spends("start and stocktaking", "anonymous memory", 64<<20, anonymous),
	spends("files baseline", "anonymous memory", 64<<20, anonymous),
	spends("every module steady", "share of one processor", 0.05, processor),
	spends("every module steady", "anonymous memory", 64<<20, anonymous),
	spends("every module steady", "goroutines", 64, goroutines),
	spends("every module steady", "descriptors", 64, descriptors),
}

func (m *measuring) budgeted(t *testing.T) {
	m.keep(t, "footprint", nil, 5*time.Second)
	m.mu.Lock()
	workloads, repeated := slices.Clone(m.spent), m.repeated
	m.mu.Unlock()
	for _, problem := range overspent(workloads) {
		t.Error(problem)
	}
	t.Logf("the platform took %d events again that it already held, from %d outcomes sshd decided", repeated, m.outcomes())
	if missing := m.missing(); len(missing) > 0 {
		t.Errorf("the platform does not hold %d events sshd decided, %q first", len(missing), missing[:min(len(missing), 5)])
	}
}

func overspent(workloads []spent) []string {
	var problems []string
	for _, held := range budgets {
		measured := slices.IndexFunc(workloads, func(s spent) bool { return s.Workload == held.workload && s.Samples > 1 })
		if measured < 0 {
			problems = append(problems, fmt.Sprintf("no workload %q was measured", held.workload))
			continue
		}
		switch spent := held.of(workloads[measured]); {
		case math.IsNaN(spent):
			problems = append(problems, fmt.Sprintf("%s: %s was not measured", held.workload, held.what))
		case held.least && spent < held.limit:
			problems = append(problems, fmt.Sprintf("%s: %s is %.4g, and the budget is at least %.4g", held.workload, held.what, spent, held.limit))
		case !held.least && spent > held.limit:
			problems = append(problems, fmt.Sprintf("%s: %s is %.4g, and the budget is at most %.4g", held.workload, held.what, spent, held.limit))
		}
	}
	return problems
}
