//go:build linux

package native_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	assessmentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/assessment/v1"
	policyv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/policy/v1"
)

var soakFor = flag.Duration("soak", 0, "how long the soak runs the installed agent with every module at its shortest interval while the platform comes and goes")

const (
	soakCycle   = 15 * time.Minute
	soakSettled = 20 * time.Minute
	shortLived  = 10 * time.Minute
)

// The installed agent run for hours with every module at its shortest
// interval, renewing certificates that last ten minutes and drawing a new key
// every hour, collecting at a steady pace while the platform goes out for two
// minutes, drops every connection and has the agent read its configuration
// again with a module off and on, every quarter of an hour. Once settled, its
// goroutines, descriptors and memory end where they were.
func TestTheInstalledAgentLastsWithoutGrowing(t *testing.T) {
	if *soakFor <= 0 {
		t.Skip("-soak names no duration: the soak runs the installed agent for hours, so it runs only where it is asked to")
	}
	if *soakFor < 2*soakSettled {
		t.Fatalf("-soak names %s, and a soak runs at least %s to tell a trend from settling", *soakFor, 2*soakSettled)
	}
	platformLife = *soakFor + 4*time.Hour
	m := openMeasuring(t)
	var began time.Time
	for _, step := range []struct {
		name string
		run  func(*testing.T)
	}{
		{name: "the service runs the agent with every module at its shortest interval, on certificates that last ten minutes", run: func(t *testing.T) { began = m.prepare(t) }},
		{name: fmt.Sprintf("for %s the agent collects and delivers while the platform comes and goes and its configuration is read again", *soakFor), run: m.soak},
		{name: "settled, the agent's goroutines, descriptors and memory do not grow", run: func(t *testing.T) { m.lasted(t, began.Add(soakSettled)) }},
	} {
		if !t.Run(step.name, step.run) {
			t.Fatalf("the soak stops at %q: every later step depends on it", step.name)
		}
	}
}

func (m *measuring) modules(network bool) map[string]any {
	return map[string]any{
		"authentication": map[string]any{"enabled": true},
		"inventory":      map[string]any{"enabled": true, "interval": "1m"},
		"processes":      map[string]any{"enabled": true, "interval": "1m"},
		"files":          map[string]any{"enabled": true, "interval": "1m"},
		"network":        map[string]any{"enabled": network, "interval": "10s"},
	}
}

func (m *measuring) prepare(t *testing.T) time.Time {
	m.install(t)
	m.collects, m.inventories, m.tuned = true, true, map[string]any{}
	m.lasting.Store(int64(shortLived))
	m.configure(t)
	m.enroll(t)
	m.start(t)
	await(t, m.invocation, "credential_renewed", time.Minute)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("draw the signing key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("encode the signer: %v", err)
	}
	place(t, signersPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	order, expected := checklist()
	sealed := sealPolicy(t, 1, &policyv1.Settings{
		Modules:    []*policyv1.ModuleSettings{{Module: policyv1.Module_MODULE_ASSESSMENT, Collection: policyv1.Collection_COLLECTION_ENABLED, Interval: durationpb.New(time.Minute)}},
		Assessment: &assessmentv1.Checklist{Checks: checks(order, expected)},
	}, key)
	m.platform.handed.Store(&sealed)
	releaser := newReleaser(t)
	root, err := proto.Marshal(releaser.root)
	if err != nil {
		t.Fatal(err)
	}
	place(t, updateRootPath, root)
	current, revision := stamped(t, agentPath)
	built := contents(t, m.built)
	m.platform.offering(releaser.offer(t, current, 1, releaser.release(current, revision, built)), built)
	if err := os.MkdirAll(overrides, 0o755); err != nil {
		t.Fatalf("create %s: %v", overrides, err)
	}
	place(t, filepath.Join(overrides, shownDropIns), []byte(everything))
	t.Cleanup(func() {
		os.Remove(filepath.Join(overrides, shownDropIns))
		exec.Command("systemctl", "daemon-reload").Run()
	})
	run(t, "systemctl", "daemon-reload")
	m.signers, m.updating = signersPath, true
	m.tuned = map[string]any{
		"modules":   m.modules(true),
		"reporting": map[string]any{"interval": "10s"},
		"identity":  map[string]any{"state_directory": state, "key_lifetime": "1h"},
	}
	m.write(t)

	began := time.Now()
	m.restarted(t)
	m.sampler = sample(t, m.gate, 10*time.Second)
	m.stock(t, began, "process")
	await(t, m.invocation, "files_watched", 10*time.Minute)
	await(t, m.invocation, "network_watched", time.Minute)
	await(t, m.invocation, "assessment_admitted", 2*time.Minute)
	return began
}

func lettered(n int) string {
	letters := ""
	for {
		letters = string(rune('a'+n%26)) + letters
		if n = n/26 - 1; n < 0 {
			return letters
		}
	}
}

func (m *measuring) soak(t *testing.T) {
	ends := time.Now().Add(*soakFor)
	for cycle := 0; time.Now().Before(ends); cycle++ {
		began, before := time.Now(), m.outcomes()
		loaded := m.load(t, "soak"+lettered(cycle), int(soakCycle/steadyEvery), steadyEvery)
		until := func(offset time.Duration) { time.Sleep(time.Until(began.Add(offset))) }
		until(4 * time.Minute)
		m.out(true)
		until(6 * time.Minute)
		m.out(false)
		until(8 * time.Minute)
		m.tuned["modules"] = m.modules(false)
		m.collecting(t, true)
		until(10 * time.Minute)
		m.tuned["modules"] = m.modules(true)
		m.collecting(t, true)
		until(12 * time.Minute)
		m.platform.dropping.Store(true)
		m.platform.ingest.CloseClientConnections()
		until(12*time.Minute + 30*time.Second)
		m.platform.dropping.Store(false)
		m.finished(t, loaded)
		m.caughtUp(t, 5*time.Minute)
		m.measure(t, fmt.Sprintf("cycle %d", cycle+1), "10 outcomes a second; the platform out for 2 minutes, the network module off for 2 and every connection dropped for 30 seconds", began, before,
			map[string]any{"renewals": m.platform.renewals.Load()})
	}
}

func (m *measuring) lasted(t *testing.T, settled time.Time) {
	trends, problems, said := unsettled(m.sampler.between(settled, time.Now()))
	for _, line := range said {
		t.Log(line)
	}
	for _, problem := range problems {
		t.Error(problem)
	}
	m.keep(t, "soak", trends, time.Minute)
	if missing := m.missing(); len(missing) > 0 {
		t.Errorf("the platform does not hold %d events sshd decided, %q first", len(missing), missing[:min(len(missing), 5)])
	}
	if read, err := as(t, "-config", configuration, "status"); err != nil || !strings.HasPrefix(read, "the agent is running: ") {
		t.Errorf("after the soak the service account reads the status as %v:\n%s", err, read)
	}
	m.mu.Lock()
	repeated := m.repeated
	m.mu.Unlock()
	t.Logf("sshd decided %d outcomes; the platform took %d of them again; %d renewals", m.outcomes(), repeated, m.platform.renewals.Load())
}

var gauges = []struct {
	name  string
	of    func(usage) int64
	grows float64
	slack float64
}{
	{name: "goroutines", of: func(u usage) int64 { return u.Goroutines }, grows: 2, slack: 5},
	{name: "descriptors", of: func(u usage) int64 { return u.Descriptors }, grows: 1, slack: 3},
	{name: "threads", of: func(u usage) int64 { return u.Threads }, grows: 1, slack: 3},
	{name: "anonymous", of: func(u usage) int64 { return u.Anonymous }, grows: 2 << 20, slack: 8 << 20},
	{name: "heap_held", of: func(u usage) int64 { return u.Held }, grows: 2 << 20, slack: 8 << 20},
	{name: "resident", of: func(u usage) int64 { return u.Resident }, grows: 2 << 20, slack: 8 << 20},
}

// unsettled judges the samples of a settled agent: no gauge may grow by more
// than its slack at a rate above what it is allowed an hour, nor end with a
// median above the one it settled at by more than a tenth and its slack.
func unsettled(samples []usage) (map[string]float64, []string, []string) {
	trends, problems, said := map[string]float64{}, []string(nil), []string(nil)
	for _, gauge := range gauges {
		measured := samples
		if gauge.name == "goroutines" || gauge.name == "heap_held" {
			measured = slices.DeleteFunc(slices.Clone(samples), func(u usage) bool { return u.Goroutines == 0 })
		}
		if len(measured) < 8 {
			problems = append(problems, fmt.Sprintf("the settled agent's %s was read %d times", gauge.name, len(measured)))
			continue
		}
		quarter := len(measured) / 4
		trends[gauge.name] = trend(measured, gauge.of)
		early, late := spreadBy(measured[:quarter], gauge.of), spreadBy(measured[len(measured)-quarter:], gauge.of)
		hours := measured[len(measured)-1].At.Sub(measured[0].At).Hours()
		if grew := trends[gauge.name] * hours; grew > gauge.slack && trends[gauge.name] > gauge.grows {
			problems = append(problems, fmt.Sprintf("%s grew by %.4g an hour once settled, %.4g over %.1f hours", gauge.name, trends[gauge.name], grew, hours))
		}
		if late.Median > early.Median*1.1+gauge.slack {
			problems = append(problems, fmt.Sprintf("%s settled at a median of %.4g in the first quarter and ends at %.4g", gauge.name, early.Median, late.Median))
		}
		said = append(said, fmt.Sprintf("%s: %.4g an hour; median %.4g in the first quarter and %.4g in the last, most %.4g", gauge.name, trends[gauge.name], early.Median, late.Median, late.Most))
	}
	return trends, problems, said
}
