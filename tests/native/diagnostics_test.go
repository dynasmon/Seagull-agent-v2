//go:build linux

package native_test

import (
	"bufio"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/diagnostics"
	"github.com/dynasmon/Seagull-agent-v2/internal/identity"
)

const written = "/var/tmp/seagull-native-diagnostics.json"

// What the commands run as the account wrote to the system journal of what
// they did, with what journald wrote down beside it of who sent each note.
func audited(t *testing.T, uid int) []map[string]string {
	t.Helper()
	var notes []map[string]string
	lines := bufio.NewScanner(strings.NewReader(run(t, "journalctl", "--no-pager", "--output=json", "SYSLOG_IDENTIFIER=seagull-agent", "_TRANSPORT=journal", "_UID="+strconv.Itoa(uid))))
	lines.Buffer(nil, 1<<20)
	for lines.Scan() {
		var note map[string]any
		if err := json.Unmarshal(lines.Bytes(), &note); err != nil {
			continue
		}
		held := map[string]string{}
		for name, value := range note {
			if text, ok := value.(string); ok {
				held[name] = text
			}
		}
		notes = append(notes, held)
	}
	return notes
}

func (g *gate) recorded(t *testing.T, events ...string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		held := map[string]int{}
		for _, note := range audited(t, g.uid) {
			if note["_COMM"] == "seagull-agent" && note["PRIORITY"] != "" && strings.Contains(note["MESSAGE"], `"msg":"`+note["SEAGULL_EVENT"]+`"`) {
				held[note["SEAGULL_EVENT"]]++
			}
		}
		if !slices.ContainsFunc(events, func(event string) bool { return held[event] == 0 }) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the journal records %v of what the service account did, and %q are wanted", held, events)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// The service account writes a bundle beside the running agent, and the gate
// reads it as root: what it says of the agent, its installation and its log,
// and that it holds no key, no record the spool keeps and nothing sshd wrote.
func (g *gate) diagnose(t *testing.T) {
	os.Remove(written)
	t.Cleanup(func() { os.Remove(written) })
	invocation, settings := g.invocation, read(t, configuration)
	for destination, refused := range map[string]string{
		filepath.Join(state, "bundle.json"): "write the bundle outside the directories the agent keeps as its own",
		configuration:                       "name a file that is not there yet",
	} {
		if said, err := as(t, "-config", configuration, "diagnostics", destination); err == nil || !strings.Contains(said, refused) {
			t.Errorf("a bundle written to %s was answered with %v:\n%s", destination, err, said)
		}
	}
	if _, err := os.Lstat(filepath.Join(state, "bundle.json")); err == nil {
		t.Error("a refused bundle was written into the installation")
	}
	if held := read(t, configuration); held != settings {
		t.Errorf("a refused bundle changed the settings into %q", held)
	}
	g.recorded(t, "diagnostics_not_written")

	said, err := as(t, "-config", configuration, "diagnostics", written)
	if err != nil || !strings.HasPrefix(said, fmt.Sprintf("the bundle is written to %q: ", written)) {
		t.Fatalf("the service account wrote a bundle as %v:\n%s", err, said)
	}
	owns(t, written, g.uid, g.gid, 0o600)
	content, err := os.ReadFile(written)
	if err != nil {
		t.Fatal(err)
	}
	var bundle diagnostics.Bundle
	if err := json.Unmarshal(content, &bundle); err != nil {
		t.Fatalf("the bundle reads as %v", err)
	}
	g.inspect(t, bundle, content)
	if property(t, "InvocationID") != invocation {
		t.Error("writing a bundle beside the agent started another")
	}
	g.reported(t, true)
	g.recorded(t, "diagnostics_written")
}

func (g *gate) inspect(t *testing.T, bundle diagnostics.Bundle, content []byte) {
	t.Helper()
	reader, err := user.LookupGroup("systemd-journal")
	if err != nil {
		t.Fatal(err)
	}
	journalGroup, _ := strconv.Atoi(reader.Gid)
	identified, _, _ := strings.Cut(run(t, agentPath, "-version"), "\n")
	if bundle.Writer.User != g.uid || !slices.Contains(bundle.Writer.Groups, journalGroup) || string(bundle.Build.Identity) != identified || len(bundle.Unread()) != 0 {
		t.Errorf("the bundle was written by %+v as %s, and could not read %q", bundle.Writer, bundle.Build.Identity, bundle.Unread())
	}
	var last struct {
		State string `json:"state"`
		Agent struct {
			Process int `json:"process"`
		} `json:"agent"`
	}
	if err := json.Unmarshal(bundle.Status.Held, &last); err != nil || last.State != "running" || strconv.Itoa(last.Agent.Process) != property(t, "MainPID") {
		t.Errorf("the bundle holds the status %s: %v", bundle.Status.Held, err)
	}
	var installation identity.Record
	if err := json.Unmarshal(bundle.Installation.Held, &installation); err != nil || installation.InstallationID != g.installation || installation.Enrollment == nil {
		t.Fatalf("the bundle holds the installation %s: %v", bundle.Installation.Held, err)
	}
	active := installation.Enrollment
	if chain := bundle.Credential.Chain; len(chain) == 0 || string(chain[0].Fingerprint) != active.Certificate.FingerprintSHA256 || string(chain[0].KeyID) != active.KeyID ||
		!strings.Contains(string(bundle.Credential.Verification), "the chain authenticates the agent, as a client") {
		t.Errorf("the bundle describes the credential of generation %d as %+v", active.Generation, bundle.Credential)
	}
	listed := map[string]diagnostics.File{}
	for _, file := range bundle.Files.Entries {
		listed[string(file.Path)] = file
	}
	for _, kept := range []string{"installation.json", "keys/" + active.KeyID + ".pem", "collection/authentication.json", "spool/events/ledger", "status/status.json"} {
		if file, found := listed[kept]; !found || file.Mode != "-rw-------" || file.Owner == nil || *file.Owner != g.uid {
			t.Errorf("the bundle lists %s as %+v", kept, file)
		}
	}
	saw := map[string]bool{}
	for _, entry := range bundle.Logs.Entries {
		switch {
		case entry.User != nil && *entry.User == g.uid && strings.Contains(entry.Message, `"msg":"agent_starting"`):
			saw["the agent starting"] = true
		case entry.Process == 1 && strings.Contains(entry.Message, unit):
			saw["the service manager"] = true
		case entry.User != nil && *entry.User == g.uid && strings.Contains(entry.Message, `"msg":"diagnostics_not_written"`):
			saw["a bundle refused"] = true
		}
	}
	if len(saw) != 3 {
		t.Errorf("the bundle holds the log of %v, from %q", saw, bundle.Logs.Sources)
	}
	for _, withheld := range append(keyLines(t), "PRIVATE KEY", "BEGIN CERTIFICATE", "Failed password for invalid user", "Accepted password for") {
		if strings.Contains(string(content), withheld) {
			t.Errorf("the bundle holds %q", withheld)
		}
	}
}

func keyLines(t *testing.T) []string {
	t.Helper()
	held, err := filepath.Glob(filepath.Join(state, "keys", "*.pem"))
	if err != nil || len(held) == 0 {
		t.Fatalf("the installation holds the keys %q: %v", held, err)
	}
	var lines []string
	for _, path := range held {
		block, _ := pem.Decode([]byte(read(t, path)))
		if block == nil {
			t.Fatalf("%s holds no key", path)
		}
		for _, line := range strings.Split(string(pem.EncodeToMemory(&pem.Block{Bytes: block.Bytes})), "\n") {
			if len(line) > 16 && !strings.HasPrefix(line, "-----") {
				lines = append(lines, line)
			}
		}
	}
	return lines
}

func read(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}
