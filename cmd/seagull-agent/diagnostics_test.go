package main

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dynasmon/Seagull-agent-v2/internal/diagnostics"
	"github.com/dynasmon/Seagull-agent-v2/internal/identity"
	"github.com/dynasmon/Seagull-agent-v2/internal/platform/journal"
	"github.com/dynasmon/Seagull-agent-v2/internal/spool"
)

type stand struct {
	asked   []journal.Query
	entries map[string][]journal.Entry
	failure error
}

// A journal that answers what a bundle asks of it with the entries the test
// hands it, keyed by the unit or by the first field a query matches on.
func journalStandIn(t *testing.T, entries map[string][]journal.Entry, failure error) *stand {
	t.Helper()
	held := &stand{entries: entries, failure: failure}
	before := journaled
	journaled = func(_ context.Context, query journal.Query, most int) ([]journal.Entry, error) {
		held.asked = append(held.asked, query)
		key := query.Unit
		if key == "" && len(query.Matches) > 0 {
			key = query.Matches[0].Field
		}
		return held.entries[key], held.failure
	}
	t.Cleanup(func() { journaled = before })
	return held
}

// A directory the account writes in and others may enter, as /var/tmp is: one
// only the account may enter is a directory the agent keeps as its own.
func shared(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	return directory
}

func logEntry(cursor string, at time.Time, fields map[string]string) journal.Entry {
	return journal.Entry{Cursor: cursor, Realtime: at, Fields: fields}
}

func bundled(t *testing.T, path, destination string) (diagnostics.Bundle, []byte, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-config", path, "diagnostics", destination}, &stdout, &stderr); code != 0 {
		t.Fatalf("write a bundle: exit code %d:\n%s%s", code, stdout.String(), stderr.String())
	}
	content, err := os.ReadFile(destination)
	if err != nil {
		t.Fatalf("read the bundle: %v", err)
	}
	var bundle diagnostics.Bundle
	if err := json.Unmarshal(content, &bundle); err != nil {
		t.Fatalf("decode the bundle: %v", err)
	}
	return bundle, content, stdout.String()
}

func TestABundleSaysWhatTheAgentIsAndLastSaidAndNothingThatAuthenticatesIt(t *testing.T) {
	state := stateDirectory(t)
	path := configured(t, state, nil)
	held := enroll(t, path)
	serveStopped(t, path)
	began := time.Now().UTC().Add(-time.Hour)
	journal := journalStandIn(t, map[string][]journal.Entry{
		packagedService: {
			logEntry("unit-2", began.Add(2*time.Second), map[string]string{"MESSAGE": `{"level":"INFO","msg":"agent_stopped"}`, "PRIORITY": "6", "_PID": "41", "_UID": strconv.Itoa(os.Geteuid()), "_COMM": "seagull-agent"}),
			logEntry("unit-1", began, map[string]string{"MESSAGE": "Started seagull-agent.service - Seagull endpoint agent.", "PRIORITY": "6", "_PID": "1", "_UID": "0", "_COMM": "systemd"}),
		},
		"SYSLOG_IDENTIFIER": {
			logEntry("audit-1", began.Add(time.Second), map[string]string{"MESSAGE": `{"level":"INFO","msg":"credential_imported"}`, "PRIORITY": "6", "_UID": strconv.Itoa(os.Geteuid()), "_AUDIT_LOGINUID": "1000", "_COMM": "seagull-agent"}),
		},
	}, nil)
	recorded := notes(t, nil)
	destination := filepath.Join(shared(t), "bundle.json")
	bundle, content, said := bundled(t, path, destination)

	if !strings.HasPrefix(said, fmt.Sprintf("the bundle is written to %q: %d bytes", destination, len(content))) {
		t.Errorf("the command said %q", said)
	}
	if bundle.Format != diagnostics.Format || bundle.Build.Identity != diagnostics.Text(buildIdentity()) || bundle.Build.Versions["protocol_version"] != 1 ||
		bundle.Writer.User != os.Geteuid() || bundle.Configuration.From != diagnostics.Text(path) {
		t.Errorf("the bundle says it is %+v, written by %+v from %s", bundle.Build, bundle.Writer, bundle.Configuration.From)
	}
	var settings struct {
		Identity struct {
			StateDirectory string `json:"state_directory"`
		} `json:"identity"`
		Spool struct {
			MaxBytes string `json:"max_bytes"`
		} `json:"spool"`
	}
	if err := json.Unmarshal(bundle.Configuration.Held, &settings); err != nil || settings.Identity.StateDirectory != state || settings.Spool.MaxBytes != "512MiB" {
		t.Errorf("the bundle holds the settings %s: %v", bundle.Configuration.Held, err)
	}
	var last struct {
		State string `json:"state"`
	}
	if err := json.Unmarshal(bundle.Status.Held, &last); err != nil || last.State != "stopped" {
		t.Errorf("the bundle holds the status %s: %v", bundle.Status.Held, err)
	}
	var installation identity.Record
	if err := json.Unmarshal(bundle.Installation.Held, &installation); err != nil || installation.Enrollment == nil || installation.Enrollment.AgentID != "web-01" {
		t.Fatalf("the bundle holds the installation %s: %v", bundle.Installation.Held, err)
	}
	if chain := bundle.Credential.Chain; len(chain) != 2 || chain[0].KeyID != diagnostics.Text(installation.Enrollment.KeyID) ||
		chain[0].Fingerprint != diagnostics.Text(installation.Enrollment.Certificate.FingerprintSHA256) || chain[0].Subject != "CN=web-01" || !chain[1].Authority ||
		!strings.Contains(string(bundle.Credential.Verification), "the chain authenticates the agent, as a client") {
		t.Errorf("the bundle describes the credential as %+v", bundle.Credential)
	}
	if bundle.Authorities.Trusted != "server.trust_bundle" || len(bundle.Authorities.Configured.Authorities) != 1 || bundle.Authorities.Adopted != nil {
		t.Errorf("the bundle describes the authorities as %+v", bundle.Authorities)
	}
	key := "keys/" + installation.Enrollment.KeyID + ".pem"
	var listed bool
	for _, file := range bundle.Files.Entries {
		if string(file.Path) == key {
			listed = file.Mode == "-rw-------" && file.Owner != nil && *file.Owner == os.Geteuid() && file.Size > 0
		}
	}
	if !listed || !bundle.Files.Complete {
		t.Errorf("the bundle lists the installation as %+v", bundle.Files.Entries)
	}
	var messages []string
	for _, entry := range bundle.Logs.Entries {
		messages = append(messages, entry.Message)
	}
	if !slices.Equal(messages, []string{"Started seagull-agent.service - Seagull endpoint agent.", `{"level":"INFO","msg":"credential_imported"}`, `{"level":"INFO","msg":"agent_stopped"}`}) ||
		bundle.Logs.Entries[1].Login == nil || *bundle.Logs.Entries[1].Login != 1000 || !bundle.Logs.Complete {
		t.Errorf("the bundle holds the logs %+v", bundle.Logs)
	}
	asked := fmt.Sprint(journal.asked)
	if len(journal.asked) != 2 || journal.asked[0].Unit != packagedService || !strings.Contains(asked, "{_UID "+strconv.Itoa(os.Geteuid())+"}") || !strings.Contains(asked, "{_TRANSPORT journal}") {
		t.Errorf("the bundle asked the journal for %s", asked)
	}

	described, err := os.Lstat(destination)
	if err != nil || described.Mode() != 0o600 {
		t.Errorf("the bundle was written as %v: %v", described, err)
	}
	certificate, err := os.ReadFile(held.certificate)
	if err != nil {
		t.Fatal(err)
	}
	if exposesKeys(t, string(content), state) || strings.Contains(string(content), "PRIVATE KEY") || strings.Contains(string(content), "BEGIN CERTIFICATE") {
		t.Fatal("the bundle holds key or certificate material")
	}
	for line := range strings.Lines(string(certificate)) {
		if line = strings.TrimSpace(line); len(line) > 16 && !strings.HasPrefix(line, "-----") && strings.Contains(string(content), line) {
			t.Fatal("the bundle holds the certificate the agent presents")
		}
	}

	if len(*recorded) != 1 || (*recorded)[0].Fields["SEAGULL_EVENT"] != "diagnostics_written" || (*recorded)[0].Priority != 6 || (*recorded)[0].Identifier != "seagull-agent" {
		t.Fatalf("the command recorded %+v", *recorded)
	}
	var note map[string]any
	if err := json.Unmarshal([]byte((*recorded)[0].Message), &note); err != nil || note["msg"] != "diagnostics_written" || note["bundle"] != destination ||
		note["bytes"] != float64(len(content)) || note["config"] != path {
		t.Errorf("the command recorded %v: %v", note, err)
	}
}

func TestABundleIsWrittenBesideARunningAgentWithoutHoldingItBack(t *testing.T) {
	state := stateDirectory(t)
	path := configured(t, state, nil)
	journalStandIn(t, nil, nil)
	entries, stop := running(t, path)
	await(t, buffered(entries), "agent_starting")
	written(t, state)
	before := names(t, state)

	bundle, _, _ := bundled(t, path, filepath.Join(shared(t), "bundle.json"))
	var last struct {
		State string `json:"state"`
		Agent struct {
			Process int `json:"process"`
		} `json:"agent"`
	}
	if err := json.Unmarshal(bundle.Status.Held, &last); err != nil || last.State != "degraded" || last.Agent.Process != os.Getpid() {
		t.Errorf("a bundle of the running agent holds the status %s: %v", bundle.Status.Held, err)
	}
	if bundle.Installation.Unread != "" || bundle.Files.Unread != "" {
		t.Errorf("a bundle of the running agent could not read %q", bundle.Unread())
	}
	if after := names(t, state); !slices.Equal(before, after) {
		t.Errorf("the installation held %q and holds %q once the bundle was written", before, after)
	}
	if code, _ := stop(); code != 0 {
		t.Fatalf("the agent exited with %d once a bundle was written beside it", code)
	}
}

func TestABundleNeverLandsWhereItWouldReplaceOrJoinWhatTheAgentKeeps(t *testing.T) {
	state := stateDirectory(t)
	path := configured(t, state, nil)
	held := enroll(t, path)
	journalStandIn(t, nil, nil)
	recorded := notes(t, nil)
	directory, private := shared(t), t.TempDir()
	if err := os.Chmod(private, 0o700); err != nil {
		t.Fatal(err)
	}
	existing, linked := filepath.Join(directory, "notes.txt"), filepath.Join(directory, "linked.json")
	if err := os.WriteFile(existing, []byte("an operator's notes"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(held.key, linked); err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(held.key)
	if err != nil {
		t.Fatal(err)
	}
	before := names(t, state)
	for destination, said := range map[string]string{
		existing:                            "name a file that is not there yet",
		linked:                              "name a file that is not there yet",
		held.key:                            "write the bundle outside the directories the agent keeps as its own",
		filepath.Join(state, "bundle.json"): "write the bundle outside the directories the agent keeps as its own",
		filepath.Join(state, keysDirectory, "bundle.json"): "write the bundle outside the directories the agent keeps as its own",
		filepath.Join(directory, "absent", "bundle.json"):  "such as /var/tmp",
		directory + "/":                       "such as /var/tmp",
		filepath.Join(private, "bundle.json"): "write the bundle outside the directories the agent keeps as its own",
	} {
		var stdout, stderr bytes.Buffer
		if code := run([]string{"-config", path, "diagnostics", destination}, &stdout, &stderr); code != 1 || stdout.Len() != 0 || !strings.Contains(stderr.String(), said) {
			t.Errorf("a bundle written to %s exited %d:\n%s%s", destination, code, stdout.String(), stderr.String())
		}
	}
	if after := names(t, state); !slices.Equal(before, after) {
		t.Errorf("the installation held %q and holds %q", before, after)
	}
	if content, err := os.ReadFile(held.key); err != nil || !bytes.Equal(content, key) {
		t.Errorf("the key changed: %v", err)
	}
	if content, err := os.ReadFile(existing); err != nil || string(content) != "an operator's notes" {
		t.Errorf("the file the bundle was refused over reads %q: %v", content, err)
	}
	if held := names(t, directory); !slices.Equal(held, []string{"linked.json", "notes.txt"}) {
		t.Errorf("refused bundles left %q", held)
	}
	for _, note := range *recorded {
		if note.Fields["SEAGULL_EVENT"] != "diagnostics_not_written" || note.Priority != 4 {
			t.Errorf("a refused bundle was recorded as %+v", note)
		}
	}
	if len(*recorded) != 8 {
		t.Errorf("8 refused bundles were recorded %d times", len(*recorded))
	}
	if held := names(t, private); len(held) != 0 {
		t.Errorf("a refused bundle left %q", held)
	}

	rewrite(t, path, state, map[string]string{"server": servers("https://gateway.example:8443", "https://control.example:8446", filepath.Join(directory, "absent-ca.pem"))})
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-config", path, "diagnostics", filepath.Join(state, "bundle.json")}, &stdout, &stderr); code != 1 ||
		!strings.Contains(stderr.String(), "write the bundle outside the directories the agent keeps as its own") {
		t.Errorf("a bundle of a configuration the agent refuses, written into its installation, exited %d:\n%s%s", code, stdout.String(), stderr.String())
	}
	if after := names(t, state); !slices.Equal(before, after) {
		t.Errorf("with its configuration refused, the installation held %q and holds %q", before, after)
	}
}

func TestABundleOfAnAgentThatCannotRunSaysWhyAndNoMore(t *testing.T) {
	const password = "p4ssw0rd-token"
	marker := strings.Repeat("written", 36) + "-marker-tail"
	journalStandIn(t, nil, nil)
	for name, prepare := range map[string]func(t *testing.T, state string) string{
		"a listener that carries a credential": func(t *testing.T, state string) string {
			path := configured(t, state, nil)
			rewrite(t, path, state, map[string]string{"server": fmt.Sprintf(
				`{"ingest_url": "https://agent:%s@gateway.example:8443", "renewal_url": "https://control.example:8446", "trust_bundle": %q}`, password, trustBundle(path))})
			return path
		},
		"an installation state that is damaged": func(t *testing.T, state string) string {
			path := configured(t, state, nil)
			if err := os.Mkdir(state, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(state, "installation.json"), []byte(fmt.Sprintf(`{"format": 1, "installation_id": %q}`, marker)), 0o600); err != nil {
				t.Fatal(err)
			}
			return path
		},
		"a key that is not one": func(t *testing.T, state string) string {
			path := configured(t, state, nil)
			if err := os.WriteFile(enroll(t, path).key, pem.EncodeToMemory(&pem.Block{Type: marker, Bytes: []byte(password)}), 0o600); err != nil {
				t.Fatal(err)
			}
			return path
		},
		"a spool that holds secrets": func(t *testing.T, state string) string {
			path := configured(t, state, nil)
			kept, release := spoolIn(t, state)
			if _, err := kept.Admit(spool.Events, spool.Record{ID: "session-1-marker-tail", Payload: []byte(strings.Repeat(password+" "+marker, 4))}); err != nil {
				t.Fatal(err)
			}
			release()
			return path
		},
	} {
		t.Run(name, func(t *testing.T) {
			state := stateDirectory(t)
			path := prepare(t, state)
			bundle, content, said := bundled(t, path, filepath.Join(shared(t), "bundle.json"))
			if strings.Contains(string(content)+said, password) || strings.Contains(string(content)+said, "-marker-tail") {
				t.Errorf("the bundle holds what the agent read:\n%s", content)
			}
			if exposesKeys(t, string(content), state) || strings.Contains(string(content), "PRIVATE KEY") {
				t.Error("the bundle holds a key")
			}
			for line := range strings.Lines(string(content)) {
				if len(line) > 6<<10 {
					t.Errorf("the bundle holds a line of %d bytes", len(line))
				}
			}
			if bundle.Logs.Entries == nil || bundle.Build.Identity == "" {
				t.Errorf("a bundle of an agent that cannot run holds %+v", bundle)
			}
		})
	}
}

func TestABundleCostsNoMoreThanItsBoundsWhateverTheInstallationAndTheJournalHold(t *testing.T) {
	state := stateDirectory(t)
	path := configured(t, state, nil)
	serveStopped(t, path)
	for n := range 3000 {
		if err := os.WriteFile(filepath.Join(state, collectionDirectory, fmt.Sprintf("stray-%04d", n)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var flood []journal.Entry
	long := strings.Repeat("x", journal.MaxLine)
	for n := range 3 * diagnostics.MaxEntries {
		flood = append(flood, logEntry(fmt.Sprint(n), time.Unix(int64(n), 0), map[string]string{"MESSAGE": long}))
	}
	journalStandIn(t, map[string][]journal.Entry{packagedService: flood, "SYSLOG_IDENTIFIER": flood}, nil)
	bundle, content, _ := bundled(t, path, filepath.Join(shared(t), "bundle.json"))
	if len(content) >= diagnostics.MaxBytes || len(bundle.Files.Entries) != diagnostics.MaxFiles || bundle.Files.Complete ||
		len(bundle.Logs.Entries) > diagnostics.MaxEntries || bundle.Logs.Complete {
		t.Errorf("a bundle of %d bytes lists %d files and holds %d entries", len(content), len(bundle.Files.Entries), len(bundle.Logs.Entries))
	}

	before := journaled
	journaled = func(ctx context.Context, _ journal.Query, _ int) ([]journal.Entry, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	t.Cleanup(func() { journaled = before })
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	destination := filepath.Join(shared(t), "bundle.json")
	began := time.Now()
	var stdout, stderr bytes.Buffer
	if code := diagnose(ctx, path, destination, &stdout, &stderr); code != 0 || time.Since(began) > 10*time.Second || !strings.Contains(stdout.String(), "context deadline exceeded") {
		t.Errorf("a journal that never answers kept the bundle %s, exit code %d:\n%s%s", time.Since(began), code, stdout.String(), stderr.String())
	}
}

func names(t *testing.T, directory string) []string {
	t.Helper()
	var held []string
	err := filepath.WalkDir(directory, func(path string, _ fs.DirEntry, err error) error {
		if err == nil && path != directory {
			held = append(held, strings.TrimPrefix(path, directory+string(filepath.Separator)))
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return held
}
