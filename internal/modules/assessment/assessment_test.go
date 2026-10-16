package assessment

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-agent-v2/internal/governor"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/dpkg"
	"github.com/dynasmon/Seagull-agent-v2/internal/spool"
	assessmentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/assessment/v1"
)

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
		if json.Unmarshal([]byte(line), &entry) == nil && entry["msg"] == message {
			found = append(found, entry)
		}
	}
	return found
}

func (l *logged) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buffer.String()
}

type harness struct {
	t         *testing.T
	directory string
	spool     *spool.Spool
	governor  *governor.Governor
	host      *fakeHost
	log       *logged

	mu    sync.Mutex
	asked Asked
}

func prepare(t *testing.T) *harness {
	t.Helper()
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("the module keeps its baseline where it can tell who owns it")
	}
	base := t.TempDir()
	for _, name := range []string{"spool", "collection"} {
		if err := os.Mkdir(filepath.Join(base, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.OpenRoot(filepath.Join(base, "spool"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	log := &logged{}
	logger := slog.New(slog.NewJSONHandler(log, nil))
	kept, err := spool.Open(root, spool.Limits{MaxBytes: 64 << 20}, logger)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { kept.Close() })
	governed, err := governor.New(logger, installation, governor.Budget{Scans: 1, ScanBytesPerSecond: 64 << 20, Uploads: 1, UploadBytesPerSecond: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	return &harness{t: t, directory: filepath.Join(base, "collection"), spool: kept, governor: governed, host: newHost(), log: log, asked: baselinePolicy(7)}
}

func baselinePolicy(revision uint64) Asked {
	return Asked{PolicyID: "linux-baseline", Revision: revision, Checks: []*assessmentv1.Check{
		checked("forwarding", &assessmentv1.KernelParameterTest{Name: "net.ipv4.ip_forward", Allowed: []string{"0"}}),
		checked("ssh.root-login", server("PermitRootLogin", "no")),
		checked("telnetd", &assessmentv1.PackageTest{Name: "telnetd", Presence: forbidden}),
		checked("cron-allow", &assessmentv1.FileTest{Path: "/etc/cron.allow", Presence: required}),
		checked("root-home", &assessmentv1.FileTest{Path: "/root", Kind: assessmentv1.FileTest_KIND_DIRECTORY}),
	}}
}

func (h *harness) ask(asked Asked) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.asked = asked
}

func (h *harness) collector(adjust func(*Options)) *Collector {
	h.t.Helper()
	directory, err := os.OpenRoot(h.directory)
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { directory.Close() })
	options := Options{
		Installation: installation,
		Spool:        h.spool,
		Governor:     h.governor,
		Directory:    directory,
		Logger:       slog.New(slog.NewJSONHandler(h.log, nil)),
		Host:         h.host,
		Asked: func() Asked {
			h.mu.Lock()
			defer h.mu.Unlock()
			return h.asked
		},
	}
	if adjust != nil {
		adjust(&options)
	}
	collector, err := New(options)
	if err != nil {
		h.t.Fatal(err)
	}
	return collector
}

type started struct {
	cancel context.CancelFunc
	done   chan error
}

func run(t *testing.T, collector *Collector) *started {
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- collector.Collect(ctx) }()
	return &started{cancel: cancel, done: done}
}

func (r *started) stop(t *testing.T) {
	t.Helper()
	r.cancel()
	select {
	case err := <-r.done:
		if err != nil {
			t.Fatalf("the module stopped with %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the module did not return once asked to stop")
	}
}

func settled(t *testing.T, collector *Collector, log *logged, done func(Stats) bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !done(collector.Stats()) {
		if time.Now().After(deadline) {
			t.Fatalf("the module never got there, it says %+v:\n%s", collector.Stats(), log)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// round runs a module of its own for one round at the moment given, as the
// agent would after starting again, and stops it.
func (h *harness) round(at time.Time, adjust ...func(*Options)) *Collector {
	h.t.Helper()
	collector := h.collector(func(options *Options) {
		options.Now = func() time.Time { return at }
		for _, adjusted := range adjust {
			adjusted(options)
		}
	})
	collecting := run(h.t, collector)
	settled(h.t, collector, h.log, func(held Stats) bool { return !held.Assessed.IsZero() || held.Idle != "" })
	collecting.stop(h.t)
	return collector
}

func (h *harness) admitted() []*assessmentv1.Assessment {
	h.t.Helper()
	held, err := h.spool.Read(spool.Assessments, 1, 1<<16, 64<<20)
	if err != nil {
		h.t.Fatal(err)
	}
	found := make([]*assessmentv1.Assessment, 0, len(held))
	for _, entry := range held {
		assessed := &assessmentv1.Assessment{}
		if err := proto.Unmarshal(entry.Payload, assessed); err != nil || assessed.GetAssessmentId() != entry.ID {
			h.t.Fatalf("the spool holds %q, which is no assessment of that name: %v", entry.ID, err)
		}
		found = append(found, assessed)
	}
	return found
}

func (h *harness) baseline() baseline {
	h.t.Helper()
	root, err := os.OpenRoot(h.directory)
	if err != nil {
		h.t.Fatal(err)
	}
	defer root.Close()
	held, err := load(root)
	if err != nil {
		h.t.Fatalf("read the baseline: %v", err)
	}
	return held
}

func outcomes(assessed *assessmentv1.Assessment) map[string]assessmentv1.Outcome {
	held := map[string]assessmentv1.Outcome{}
	for _, result := range assessed.GetResults() {
		held[result.GetCheckId()] = result.GetOutcome()
	}
	return held
}

func TestTheFirstRoundAdmitsAnAssessmentAnsweringEveryCheckInItsOrder(t *testing.T) {
	h := prepare(t)
	collector := h.round(madeAt)
	admitted := h.admitted()
	if len(admitted) != 1 {
		t.Fatalf("the first round admitted %d assessments:\n%s", len(admitted), h.log)
	}
	first := admitted[0]
	var order []string
	for _, result := range first.GetResults() {
		order = append(order, result.GetCheckId())
	}
	if strings.Join(order, ",") != "forwarding,ssh.root-login,telnetd,cron-allow,root-home" || first.GetPolicyId() != "linux-baseline" ||
		first.GetPolicyRevision() != 7 || !first.GetAssessedAt().AsTime().Equal(madeAt) {
		t.Fatalf("the first round admitted %v", first)
	}
	want := map[string]assessmentv1.Outcome{"forwarding": pass, "ssh.root-login": pass, "telnetd": pass, "cron-allow": fail, "root-home": erred}
	for check, outcome := range want {
		if outcomes(first)[check] != outcome {
			t.Errorf("%s was answered %s, want %s", check, outcomes(first)[check], outcome)
		}
	}
	if held := h.baseline(); held.AssessmentID != first.GetAssessmentId() || held.Checks != 5 || held.Revision != 7 || !held.AssessedAt.Equal(madeAt) {
		t.Fatalf("the baseline holds %+v", held)
	}
	if stats := collector.Stats(); stats.Counts != (Counts{Passed: 3, Failed: 1, Errors: 1}) || !stats.Sent.Equal(madeAt) || stats.Failure != nil {
		t.Fatalf("the module says %+v", stats)
	}
	admittedLines := h.log.lines("assessment_admitted")
	if len(admittedLines) != 1 || admittedLines[0]["because"] != "first" || admittedLines[0]["failed"] != float64(1) {
		t.Fatalf("the admission was logged as %v", admittedLines)
	}
	checks := h.log.lines("assessment_check")
	if len(checks) != 2 || checks[0]["check_id"] != "cron-allow" || checks[0]["level"] != "WARN" || checks[1]["outcome"] != "error" {
		t.Fatalf("the first round logged the checks %v", checks)
	}
}

func TestAnAssessmentIsAdmittedAgainOnlyWhenWhatItFoundChangedOrADayPassed(t *testing.T) {
	h := prepare(t)
	h.round(madeAt)
	h.round(madeAt.Add(time.Hour))
	if admitted := h.admitted(); len(admitted) != 1 {
		t.Fatalf("a round that found what the last one did admitted again: %d assessments", len(admitted))
	}

	h.host.parameters["net.ipv4.ip_forward"] = "1"
	h.round(madeAt.Add(2 * time.Hour))
	admitted := h.admitted()
	if len(admitted) != 2 || outcomes(admitted[1])["forwarding"] != fail {
		t.Fatalf("a change on the host was admitted as %d assessments", len(admitted))
	}
	changed := false
	for _, line := range h.log.lines("assessment_check") {
		changed = changed || line["check_id"] == "forwarding" && line["outcome"] == "fail" && line["level"] == "WARN"
	}
	if !changed {
		t.Fatalf("the change was not logged:\n%s", h.log)
	}

	h.round(madeAt.Add(2*time.Hour + 23*time.Hour + 29*time.Minute))
	if admitted := h.admitted(); len(admitted) != 2 {
		t.Fatalf("an assessment younger than a day less half an interval was refreshed")
	}
	h.round(madeAt.Add(2*time.Hour + 23*time.Hour + 30*time.Minute))
	if admitted := h.admitted(); len(admitted) != 3 {
		t.Fatalf("an assessment a day old was not refreshed: %d assessments", len(admitted))
	}
	if because := h.log.lines("assessment_admitted"); because[len(because)-1]["because"] != "refreshed" {
		t.Fatalf("the refresh was logged as %v", because[len(because)-1])
	}

	h.ask(baselinePolicy(8))
	h.round(madeAt.Add(26 * time.Hour))
	admitted = h.admitted()
	if len(admitted) != 4 || admitted[3].GetPolicyRevision() != 8 {
		t.Fatalf("a newer revision of the policy was not admitted")
	}
}

func TestAPolicyThatStopsAskingForChecksRetiresWhatTheLastAssessmentSaid(t *testing.T) {
	h := prepare(t)
	h.ask(Asked{})
	if idle := h.round(madeAt).Stats().Idle; !strings.Contains(idle, "no policy is in force") || len(h.admitted()) != 0 {
		t.Fatalf("with no policy in force the module says %q and admitted %d assessments", idle, len(h.admitted()))
	}
	h.ask(Asked{PolicyID: "linux-baseline", Revision: 6})
	if idle := h.round(madeAt).Stats().Idle; !strings.Contains(idle, "revision 6 of linux-baseline asks for no checks") || len(h.admitted()) != 0 {
		t.Fatalf("with a policy asking for no checks the module says %q", idle)
	}
	h.ask(baselinePolicy(7))
	h.round(madeAt.Add(time.Minute))
	h.ask(Asked{PolicyID: "linux-baseline", Revision: 8})
	h.round(madeAt.Add(2 * time.Minute))
	admitted := h.admitted()
	if len(admitted) != 2 || len(admitted[1].GetResults()) != 0 || admitted[1].GetPolicyRevision() != 8 {
		t.Fatalf("a policy that stopped asking for checks left %d assessments", len(admitted))
	}
	if idle := h.round(madeAt.Add(3 * time.Minute)).Stats().Idle; idle == "" || len(h.admitted()) != 2 {
		t.Fatalf("once it said so, the module assessed again: %q", idle)
	}
}

func TestAnAssessmentTheBatchOrThePlatformCannotTakeIsNotAdmittedAndSaysWhy(t *testing.T) {
	h := prepare(t)
	collector := h.round(madeAt, func(options *Options) { options.Largest = func() int64 { return 64 } })
	if stats := collector.Stats(); !errors.Is(stats.Failure, ErrBeyondBatch) || len(h.admitted()) != 0 {
		t.Fatalf("an assessment beyond a batch was answered %v and %d were admitted", stats.Failure, len(h.admitted()))
	}
	if refused := h.log.lines("assessment_not_admitted"); len(refused) != 1 || !strings.Contains(refused[0]["recovery"].(string), "transport.max_batch_bytes") {
		t.Fatalf("the refusal was logged as %v", refused)
	}
	if _, err := os.Stat(filepath.Join(h.directory, baselineFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("an assessment never admitted was written down: %v", err)
	}

	h.round(madeAt)
	h.host.parameters["net.ipv4.ip_forward"] = "1"
	behind := h.round(madeAt.Add(-time.Minute))
	if stats := behind.Stats(); !errors.Is(stats.Failure, ErrClockBehind) || len(h.admitted()) != 1 {
		t.Fatalf("a clock behind the last assessment was answered %v, and %d were admitted", stats.Failure, len(h.admitted()))
	}
	if len(h.log.lines("assessment_deferred")) != 1 || len(h.log.lines("assessment_clock_regressed")) != 0 {
		t.Fatalf("a clock a minute behind was logged as:\n%s", h.log)
	}
	far := h.round(madeAt.Add(-10 * time.Minute))
	if far.Stats().Failure != nil || len(h.admitted()) != 2 || len(h.log.lines("assessment_clock_regressed")) != 1 {
		t.Fatalf("an assessment further behind the last than any platform admits was answered %v", far.Stats().Failure)
	}
}

type stalling struct{ *fakeHost }

func (stalling) Packages(ctx context.Context) ([]dpkg.Package, error) {
	<-ctx.Done()
	return nil, errors.New("dpkg-query stopped: signal: killed")
}

func TestARoundThatRunsOutOfItsTimeAnswersWhatItDidNotReachAsAnErrorAndStillAdmitsIt(t *testing.T) {
	h := prepare(t)
	collector := h.round(madeAt, func(options *Options) { options.Host, options.Within = stalling{h.host}, 50*time.Millisecond })
	admitted := h.admitted()
	if len(admitted) != 1 || len(admitted[0].GetResults()) != 5 {
		t.Fatalf("a round that ran out of time admitted %v:\n%s", admitted, h.log)
	}
	results := admitted[0].GetResults()
	if results[0].GetOutcome() != pass || results[1].GetOutcome() != pass {
		t.Errorf("the checks answered before the round ran out of time were answered %v", results[:2])
	}
	if results[2].GetOutcome() != erred || !strings.Contains(results[2].GetEvidence(), "killed") {
		t.Errorf("the check whose source took too long was answered %v", results[2])
	}
	for _, result := range results[3:] {
		if result.GetOutcome() != erred || !strings.Contains(result.GetEvidence(), "ran out of the time") {
			t.Errorf("a check the round did not reach was answered %v", result)
		}
	}
	if stats := collector.Stats(); stats.Counts != (Counts{Passed: 2, Errors: 3}) || stats.Failure != nil {
		t.Fatalf("the module says %+v", stats)
	}
}

func TestAnAssessmentAskedForOutOfTurnRunsAtOnce(t *testing.T) {
	h := prepare(t)
	collector := h.collector(func(options *Options) { options.Interval = func() time.Duration { return 24 * time.Hour } })
	collecting := run(t, collector)
	defer collecting.stop(t)
	settled(t, collector, h.log, func(held Stats) bool { return !held.Sent.IsZero() })
	h.ask(baselinePolicy(9))
	collector.Again()
	settled(t, collector, h.log, func(held Stats) bool { return held.Revision == 9 && len(h.admitted()) == 2 })
}

func TestAModuleStartedAgainKnowsWhatItAdmittedAndAssessesOnlyWhatChanged(t *testing.T) {
	h := prepare(t)
	h.round(madeAt)
	again := h.round(madeAt.Add(time.Minute))
	if len(h.admitted()) != 1 || !again.Stats().Sent.Equal(madeAt) {
		t.Fatalf("a module started again admitted %d assessments and says it sent at %s", len(h.admitted()), again.Stats().Sent)
	}
	if err := os.WriteFile(filepath.Join(h.directory, baselineFile), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	h.round(madeAt.Add(2 * time.Minute))
	if len(h.admitted()) != 2 || len(h.log.lines("assessment_baseline_lost")) != 1 {
		t.Fatalf("a baseline that does not read left %d assessments:\n%s", len(h.admitted()), h.log)
	}
}
