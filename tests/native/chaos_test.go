//go:build linux

package native_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

const (
	hostsPath   = "/etc/hosts"
	volumeBytes = 320 << 20
)

type fate int

const (
	delivered fate = iota
	quarantined
	lost
	dropped
)

func (f fate) String() string {
	switch f {
	case quarantined:
		return "quarantined"
	case lost:
		return "lost"
	case dropped:
		return "dropped by the journal"
	}
	return "delivered"
}

var decided = regexp.MustCompile(`^[a-z]+-[0-9]{6}$`)

// The installed agent collecting what sshd decides while everything it depends
// on fails: the gate kills it, the platform loses answers, publishes part of
// batches, goes away, stops admitting it or rotates its authority, the
// filesystem of the installation fills up or turns read-only and a record is
// damaged on it. The gate knows every outcome it had sshd write, and at every
// step the platform holds each as one event, byte for byte however often it was
// delivered, unless the agent counted it apart for a reason the gate gave it.
func TestTheInstalledAgentAccountsForEveryEventThroughFailures(t *testing.T) {
	c := openChaos(t)
	for _, step := range []struct {
		name string
		run  func(*testing.T)
	}{
		{name: "the service runs the agent on a filesystem of its own, collecting what sshd decides", run: c.prepare},
		{name: "killed over and over while the platform loses answers, publishes part of batches and miscounts them, the agent delivers every event and repeats only the same bytes", run: c.kills},
		{name: "an outage, a name that does not resolve, a listener that drops connections, answers that come too late and a listener the agent does not trust hold the events until they are delivered", run: c.network},
		{name: "a filesystem with no room pauses collection, which catches up from where it stopped once there is room", run: c.full},
		{name: "a filesystem the kernel makes read-only stops the agent, which its service starts again on what it kept once the filesystem is repaired", run: c.readOnly},
		{name: "a record damaged on disk is counted as lost and the others are delivered", run: c.damage},
		{name: "what the journal dropped before the agent read it is reported as a gap", run: c.gap},
		{name: "a certificate left to expire, a platform that rotates its authority and one that stops admitting the agent for a while hold the events and drop none", run: c.credentials},
		{name: "an update interrupted as it installs or checks the release ends, on the same installation, with every event delivered", run: c.interrupted},
		{name: "the agent counts every event it did not deliver under the reason the gate gave it, and holds nothing more", run: c.counted},
	} {
		if !t.Run(step.name, step.run) {
			t.Fatalf("the chaos stops at %q: every later step depends on it", step.name)
		}
	}
}

type chaos struct {
	*gate
	volume   *volume
	writer   string
	seed     uint64
	mode     atomic.Int32
	renewing atomic.Pointer[renewing]
	current  *authority

	mu         sync.Mutex
	drawn      *rand.Rand
	produced   []string
	complaints []string
	fates      map[string]fate
	refused    map[string]bool
	copies     map[string][][]byte
	named      map[string]map[string]bool
}

func openChaos(t *testing.T) *chaos {
	g := open(t)
	seed := uint64(time.Now().UnixNano())
	t.Logf("drawing with seed %d", seed)
	c := &chaos{gate: g, writer: filepath.Join(g.scratch, "sshd"), seed: seed, drawn: rand.New(rand.NewPCG(seed, 37)),
		fates: map[string]fate{}, refused: map[string]bool{}, copies: map[string][][]byte{}, named: map[string]map[string]bool{},
		current: &authority{certificate: g.platform.authority, key: g.platform.key}}
	t.Cleanup(func() {
		if c.volume != nil {
			c.volume.release()
		}
	})
	copySelf(t, c.writer)
	hosts, err := os.ReadFile(hostsPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.WriteFile(hostsPath, hosts, 0o644) })
	return c
}

func (c *chaos) draw(n int) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.drawn.IntN(n)
}

func (c *chaos) prepare(t *testing.T) {
	c.install(t)
	c.volume = mountVolume(t, c.scratch, state, volumeBytes, c.uid, c.gid)
	c.resolve(t, true)
	c.platform.named, c.collects = true, true
	c.tuned = map[string]any{"transport": map[string]any{"connect_timeout": "2s", "request_timeout": "5s", "max_batch_bytes": "1MiB",
		"max_events_per_batch": 100, "max_upload_bytes_per_second": "8MiB"}}
	handled, renewed := c.admit, c.renew
	c.platform.handling.Store(&handled)
	c.platform.renewing.Store(&renewed)
	c.configure(t)
	c.enroll(t)
	c.start(t)
	await(t, c.invocation, "collection_started", 10*time.Second)
	var mounted, kept syscall.Stat_t
	if err := errors.Join(syscall.Stat(state, &mounted), syscall.Stat(filepath.Join(state, "installation.json"), &kept)); err != nil || mounted.Dev != kept.Dev {
		t.Fatalf("the installation is not on the filesystem the gate made for it: %v", err)
	}
	c.write(t, "first", 20, 20*time.Millisecond).wait(t)
	c.settled(t, time.Minute)
}

// The platform's name resolves through the hosts file, which the gate takes
// it out of while the name must not resolve.
func (c *chaos) resolve(t *testing.T, resolving bool) {
	t.Helper()
	content, err := os.ReadFile(hostsPath)
	if err != nil {
		t.Fatal(err)
	}
	entry := "127.0.0.1 " + platformName + "\n"
	kept := strings.ReplaceAll(string(content), entry, "")
	if resolving {
		kept += entry
	}
	place(t, hostsPath, []byte(kept))
}

type writing struct {
	process *exec.Cmd
	ended   chan struct{}
	chaos   *chaos
	waiting sync.Once
	waited  error
}

func (c *chaos) write(t *testing.T, prefix string, count int, every time.Duration) *writing {
	t.Helper()
	process := exec.Command(c.writer, "-test.run=^$")
	process.Env = append(os.Environ(), fmt.Sprintf("%s=%s 1 %d %s", writerVariable, prefix, count, every))
	said, err := process.StdoutPipe()
	if err == nil {
		err = process.Start()
	}
	if err != nil {
		t.Fatalf("have sshd decide: %v", err)
	}
	w := &writing{process: process, ended: make(chan struct{}), chaos: c}
	t.Cleanup(func() { process.Process.Kill() })
	go func() {
		defer close(w.ended)
		lines := bufio.NewScanner(said)
		for lines.Scan() {
			c.mu.Lock()
			if user, wrote := strings.CutPrefix(lines.Text(), "wrote "); wrote && decided.MatchString(user) {
				c.produced = append(c.produced, user)
			} else {
				c.complaints = append(c.complaints, lines.Text())
			}
			c.mu.Unlock()
		}
	}()
	return w
}

func (w *writing) done() bool {
	select {
	case <-w.ended:
		return true
	default:
		return false
	}
}

func (w *writing) wait(t *testing.T) {
	t.Helper()
	<-w.ended
	w.waiting.Do(func() { w.waited = w.process.Wait() })
	err := w.waited
	w.chaos.mu.Lock()
	complaints := slices.Clone(w.chaos.complaints)
	w.chaos.mu.Unlock()
	if err != nil || len(complaints) > 0 {
		t.Fatalf("sshd's stand-in ended with %v and said %q", err, complaints)
	}
}

func (w *writing) stop(t *testing.T) {
	t.Helper()
	w.process.Process.Signal(syscall.SIGTERM)
	w.wait(t)
}

func (c *chaos) kill(t *testing.T) {
	t.Helper()
	pid, err := strconv.Atoi(property(t, "MainPID"))
	if err != nil || pid <= 0 {
		t.Fatalf("the service runs no agent: %q", property(t, "MainPID"))
	}
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		t.Fatalf("kill the agent: %v", err)
	}
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); errors.Is(err, fs.ErrNotExist) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the agent outlived its kill by 10s")
		}
	}
	run(t, "systemctl", "restart", unit)
	c.invocation = started(t, c.invocation)
}

func (c *chaos) kills(t *testing.T) {
	for _, number := range []int{150, 750, 1350} {
		c.refuse(fmt.Sprintf("kill-%06d", number))
	}
	c.mode.Store(unsteady)
	writing := c.write(t, "kill", 1500, 40*time.Millisecond)
	killed := 0
	for !writing.done() {
		time.Sleep(time.Duration(2000+c.draw(4000)) * time.Millisecond)
		if writing.done() {
			break
		}
		c.kill(t)
		killed++
	}
	writing.wait(t)
	c.mode.Store(answering)
	c.settled(t, 3*time.Minute)
	if killed < 6 {
		t.Errorf("the agent was killed %d times while sshd decided", killed)
	}
}

func (c *chaos) refuse(user string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.refused[user], c.fates[user] = true, quarantined
}

func (c *chaos) fated(user string, given fate) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.fates[user] = given
}

func (c *chaos) missing() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.undelivered(len(c.produced))
}

func (c *chaos) undelivered(upto int) []string {
	var missing []string
	for _, user := range c.produced[:upto] {
		if c.fates[user] == delivered && len(c.named[user]) == 0 {
			missing = append(missing, user)
		}
	}
	return missing
}

func (c *chaos) caughtUp(t *testing.T, after string, within time.Duration) {
	t.Helper()
	c.mu.Lock()
	upto := len(c.produced)
	c.mu.Unlock()
	deadline := time.Now().Add(within)
	for {
		c.mu.Lock()
		missing := c.undelivered(upto)
		c.mu.Unlock()
		if len(missing) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("after %s the platform does not hold within %s %d events sshd decided before it ended, %q first", after, within, len(missing), missing[:min(len(missing), 5)])
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// Settled once the platform holds every event the agent was to deliver: each
// outcome sshd decided is one event, which every copy carries byte for byte,
// and the platform holds nothing the gate did not have sshd decide nor any
// event the agent was to count apart.
func (c *chaos) settled(t *testing.T, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for missing := c.missing(); len(missing) > 0; missing = c.missing() {
		if time.Now().After(deadline) {
			t.Fatalf("after %s the platform does not hold %d events the agent was to deliver, %q first:\n%s", within, len(missing), missing[:min(len(missing), 5)],
				answer("journalctl", "--no-pager", "--output", "cat", "--lines", "60", "_SYSTEMD_INVOCATION_ID="+c.invocation))
		}
		time.Sleep(250 * time.Millisecond)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	produced := map[string]bool{}
	for _, user := range c.produced {
		produced[user] = true
	}
	repeated := 0
	for _, user := range slices.Sorted(maps.Keys(c.named)) {
		ids := c.named[user]
		switch {
		case !produced[user]:
			t.Errorf("the platform holds an event of %s, an outcome sshd never decided", user)
		case c.fates[user] != delivered:
			t.Errorf("the platform holds an event of %s, which the agent was to count as %s", user, c.fates[user])
		case len(ids) != 1:
			t.Errorf("the platform holds %d events for the one outcome of %s: %v", len(ids), user, slices.Sorted(maps.Keys(ids)))
		}
		for id := range ids {
			copies := c.copies[id]
			if len(copies) > 1 {
				repeated++
			}
			for _, copied := range copies[1:] {
				if !bytes.Equal(copied, copies[0]) {
					t.Errorf("the event %s of %s was delivered again as other bytes", id, user)
				}
			}
		}
	}
	t.Logf("sshd decided %d outcomes; the platform holds %d events, %d of them delivered more than once and every copy the same bytes", len(c.produced), len(c.named), repeated)
}

func (c *chaos) gap(t *testing.T) {
	run(t, "systemctl", "stop", unit)
	c.write(t, "gap", 5, 10*time.Millisecond).wait(t)
	for number := 1; number <= 5; number++ {
		c.fated(fmt.Sprintf("gap-%06d", number), dropped)
	}
	run(t, "journalctl", "--rotate")
	time.Sleep(2 * time.Second)
	run(t, "journalctl", "--vacuum-time=1s")
	run(t, "systemctl", "start", unit)
	c.invocation = started(t, c.invocation)
	if gap := await(t, c.invocation, "collection_gap", 30*time.Second); gap["level"] != "WARN" || gap["recovery"] == nil {
		t.Errorf("the agent reported what the journal dropped as %v", gap)
	}
	c.write(t, "after", 20, 20*time.Millisecond).wait(t)
	c.settled(t, time.Minute)
}

func (c *chaos) counted(t *testing.T) {
	run(t, "systemctl", "restart", unit)
	c.invocation = started(t, c.invocation)
	opened := await(t, c.invocation, "spool_opened", 10*time.Second)
	events, _ := opened["events"].(map[string]any)
	c.mu.Lock()
	counts := map[fate]int{}
	for _, user := range c.produced {
		counts[c.fates[user]]++
	}
	c.mu.Unlock()
	if events["outstanding"] != float64(0) || events["expired"] != float64(0) || events["lost"] != float64(counts[lost]) ||
		events["quarantined"] != float64(counts[quarantined]) || events["delivered"].(float64) < float64(counts[delivered]) {
		t.Errorf("the agent opened its spool as %v, and the gate has sshd decide outcomes it meant to be %v", events, counts)
	}
	said := c.reported(t, true)
	for _, line := range []string{"events: nothing waiting", fmt.Sprintf("0 expired, %d lost, %d quarantined", counts[lost], counts[quarantined])} {
		if !strings.Contains(said, line) {
			t.Errorf("the status does not say %q:\n%s", line, said)
		}
	}
	run(t, "systemctl", "stop", unit)
	run(t, "umount", state)
}

func (c *chaos) found(t *testing.T, since time.Time, within time.Duration, said string, match func(entry map[string]any) bool) map[string]any {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		for _, entry := range journal(t, c.invocation) {
			at, _ := time.Parse(time.RFC3339Nano, fmt.Sprint(entry["time"]))
			if !at.Before(since) && match(entry) {
				return entry
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("the agent logged no %s within %s:\n%s", said, within,
				answer("journalctl", "--no-pager", "--output", "cat", "--lines", "60", "_SYSTEMD_INVOCATION_ID="+c.invocation))
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func (c *chaos) logged(t *testing.T, message string, since time.Time, within time.Duration) map[string]any {
	t.Helper()
	return c.found(t, since, within, message, func(entry map[string]any) bool { return entry["msg"] == message })
}

func (c *chaos) says(t *testing.T, text string, within time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		said, _ := as(t, "-config", configuration, "status")
		if strings.Contains(said, text) {
			return said
		}
		if time.Now().After(deadline) {
			t.Fatalf("the status did not say %q within %s:\n%s", text, within, said)
		}
		time.Sleep(time.Second)
	}
}

func (c *chaos) unstarted(t *testing.T, since time.Time, within time.Duration) map[string]any {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		said := answer("journalctl", "--no-pager", "--output", "cat", "--unit", unit, "--since", "@"+strconv.FormatInt(since.Unix(), 10))
		for line := range strings.Lines(said) {
			entry := map[string]any{}
			if json.Unmarshal([]byte(line), &entry) == nil && entry["msg"] == "agent_not_started" {
				return entry
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("the service started no agent that refused to start within %s:\n%s", within, said)
		}
		time.Sleep(time.Second)
	}
}
